// ANet library adapter. See NOTICE and LICENSE.upstream for upstream attribution.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	tls "github.com/refraction-networking/utls"
)

// Adapted from dpi-ch/inetutil/tls.go. These describe the diagnostic probe,
// not the fingerprint of ANet's rustls transports.
var fingerprints = map[string]tls.ClientHelloID{
	"chrome":  tls.HelloChrome_133,
	"firefox": tls.HelloFirefox_120,
	"safari":  tls.HelloSafari_16_0,
	"ios":     tls.HelloIOS_14,
	"android": tls.HelloAndroid_11_OkHttp,
	"edge":    tls.HelloEdge_85,
	"360":     tls.Hello360_7_5,
	"qq":      tls.HelloQQ_11_1,
}

type request struct {
	Fingerprint  string `json:"fingerprint"`
	SNI          string `json:"sni"`
	TimeoutMs    int    `json:"timeout_ms"`
	TransferPath string `json:"transfer_path,omitempty"`
	PayloadBytes int    `json:"payload_bytes,omitempty"`
}
type result struct {
	Status                string `json:"status"`
	Code                  string `json:"code"`
	Fingerprint           string `json:"fingerprint"`
	ElapsedMs             int64  `json:"elapsed_ms"`
	ALPN                  string `json:"alpn,omitempty"`
	TLSVersion            uint16 `json:"tls_version,omitempty"`
	TxBytes               int    `json:"tx_bytes,omitempty"`
	RxBytes               int    `json:"rx_bytes,omitempty"`
	CertificateValidation string `json:"certificate_validation"`
}

var active sync.Map

func probe(ctx context.Context, conn net.Conn, r request) (out result) {
	start := time.Now()
	out = result{Status: "failed", Code: "invalid_options", Fingerprint: r.Fingerprint, CertificateValidation: "not_checked"}
	defer func() { out.ElapsedMs = time.Since(start).Milliseconds() }()
	defer conn.Close()
	if r.TimeoutMs < 1 || r.TimeoutMs > 15000 || len(r.SNI) > 253 || strings.ContainsAny(r.SNI, "\r\n") {
		return
	}
	fp, ok := fingerprints[r.Fingerprint]
	if !ok {
		return
	}
	deadline := time.Now().Add(time.Duration(r.TimeoutMs) * time.Millisecond)
	_ = conn.SetDeadline(deadline)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer close(done)
	t := tls.UClient(conn, &tls.Config{ServerName: r.SNI, InsecureSkipVerify: true}, fp)
	if err := t.HandshakeContext(ctx); err != nil {
		out.Code = classify(err, ctx)
		return
	}
	state := t.ConnectionState()
	out.ALPN = state.NegotiatedProtocol
	out.TLSVersion = state.Version
	out.Status = "passed"
	out.Code = "tls_handshake_completed"
	if r.TransferPath == "" {
		return
	}
	if !strings.HasPrefix(r.TransferPath, "/") || strings.ContainsAny(r.TransferPath, "\r\n") || r.PayloadBytes < 32768 || r.PayloadBytes > 131072 {
		out.Status = "failed"
		out.Code = "invalid_transfer_options"
		return
	}
	if out.ALPN != "" && out.ALPN != "http/1.1" {
		out.Status = "skipped"
		out.Code = "transfer_requires_http1"
		return
	}
	payload := make([]byte, r.PayloadBytes)
	if _, err := rand.Read(payload); err != nil {
		out.Status = "failed"
		out.Code = "random_failed"
		return
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+r.SNI+r.TransferPath, bytes.NewReader(payload))
	if err != nil {
		out.Status = "failed"
		out.Code = "invalid_transfer_options"
		return
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Connection", "close")
	if err = req.Write(t); err != nil {
		out.Status = "failed"
		out.Code = classify(err, ctx)
		return
	}
	out.TxBytes = len(payload)
	resp, err := http.ReadResponse(bufio.NewReader(t), req)
	if err != nil {
		out.Status = "failed"
		out.Code = classify(err, ctx)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(len(payload)+1)))
	out.RxBytes = len(body)
	if err != nil {
		out.Status = "failed"
		out.Code = classify(err, ctx)
		return
	}
	if resp.StatusCode != 200 || !bytes.Equal(body, payload) {
		out.Status = "inconclusive"
		out.Code = "echo_endpoint_not_confirmed"
		return
	}
	out.Code = "echo_roundtrip_completed"
	return
}

func classify(err error, ctx context.Context) string {
	if ctx.Err() != nil {
		return "cancelled"
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		return "timeout"
	}
	if strings.Contains(strings.ToLower(err.Error()), "certificate") {
		return "tls_certificate_error"
	}
	return "tls_or_io_error"
}

//export anet_dpi_probe
func anet_dpi_probe(id C.ulonglong, fd C.int, raw *C.char) (ret *C.char) {
	defer func() {
		if recover() != nil {
			ret = C.CString(`{"status":"failed","code":"adapter_panic","certificate_validation":"not_checked"}`)
		}
	}()
	var r request
	if raw == nil || json.Unmarshal([]byte(C.GoString(raw)), &r) != nil {
		return C.CString(`{"status":"failed","code":"invalid_json","certificate_validation":"not_checked"}`)
	}
	ctx, cancel := context.WithCancel(context.Background())
	active.Store(uint64(id), cancel)
	defer func() { active.Delete(uint64(id)); cancel() }()
	// Dup before net.FileConn: never close the descriptor borrowed from Rust.
	dup, err := syscall.Dup(int(fd))
	if err != nil {
		return C.CString(`{"status":"failed","code":"duplicate_socket_failed","certificate_validation":"not_checked"}`)
	}
	file := os.NewFile(uintptr(dup), "anet-diagnostic-socket")
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		return C.CString(`{"status":"failed","code":"socket_conversion_failed","certificate_validation":"not_checked"}`)
	}
	data, err := json.Marshal(probe(ctx, conn, r))
	if err != nil {
		return C.CString(`{"status":"failed","code":"json_failed","certificate_validation":"not_checked"}`)
	}
	return C.CString(string(data))
}

//export anet_dpi_cancel
func anet_dpi_cancel(id C.ulonglong) {
	if c, ok := active.Load(uint64(id)); ok {
		c.(context.CancelFunc)()
	}
}

//export anet_dpi_free
func anet_dpi_free(ptr *C.char) { C.free(unsafe.Pointer(ptr)) }

func main() { fmt.Println("ANet DPI helper is a socket-only shared library") }
