package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func endpoint(t *testing.T, handler http.HandlerFunc) (net.Conn, func()) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return conn, server.Close
}
func TestEchoRequiresCompleteRoundtrip(t *testing.T) {
	conn, closeServer := endpoint(t, func(w http.ResponseWriter, r *http.Request) { io.Copy(w, r.Body) })
	defer closeServer()
	result := probe(context.Background(), conn, request{Fingerprint: "android", SNI: "localhost", TimeoutMs: 2000, TransferPath: "/echo", PayloadBytes: 65536})
	if result.Code != "echo_roundtrip_completed" || result.TxBytes != 65536 || result.RxBytes != 65536 {
		t.Fatalf("%+v", result)
	}
}
func TestOrdinaryHTTPResponseDoesNotProveTransfer(t *testing.T) {
	conn, closeServer := endpoint(t, func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body); w.Write([]byte("OK")) })
	defer closeServer()
	result := probe(context.Background(), conn, request{Fingerprint: "android", SNI: "localhost", TimeoutMs: 2000, TransferPath: "/echo", PayloadBytes: 65536})
	if result.Status != "inconclusive" || result.Code != "echo_endpoint_not_confirmed" {
		t.Fatalf("%+v", result)
	}
}
func TestCancellationInterruptsHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(30*time.Millisecond, cancel)
	started := time.Now()
	r := probe(ctx, conn, request{Fingerprint: "android", SNI: "localhost", TimeoutMs: 15000})
	if r.Code != "cancelled" || time.Since(started) > time.Second {
		t.Fatalf("%+v", r)
	}
}
func TestDeadlineStopsSilentPeer(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	started := time.Now()
	r := probe(context.Background(), a, request{Fingerprint: "chrome", SNI: "localhost", TimeoutMs: 30})
	if r.Code != "timeout" || time.Since(started) > time.Second {
		t.Fatalf("%+v", r)
	}
}
