# ANet DPI socket adapter

Library ABI: `anet_dpi_probe(uint64_t id, int borrowed_fd, const char *request_json)` returns an allocated JSON string; release it with `anet_dpi_free`. `anet_dpi_cancel(id)` cancels an active call. IDs must be unique among simultaneous calls. Retry cancel until the call returns if cancellation races call startup.

The library duplicates an already connected TCP socket. It does not create outbound connections or resolve DNS. The caller retains its socket and connection-budget permit until the function returns. Request timeout is 1–15000 ms. Keep this Go library loaded for the process lifetime: unloading a running Go runtime is unsafe.

Request: `fingerprint`, `sni`, `timeout_ms`; optional `transfer_path` and `payload_bytes` (32768–131072). Transfer uses HTTP/1.1 over TLS and requires an HTTPS endpoint that returns HTTP 200 with the exact request bytes. No redirects. A TLS success checks neither certificate trust nor ANet authentication. Browser profiles describe the probe, not ANet's production ClientHello.

Build prerequisites: Go >=1.24, C compiler, Android NDK 25.2.9519653 for Android. Sources and dependency versions are pinned in go.mod/go.sum. Go 1.27 and the upstream TUI are not required.

```sh
go build -buildmode=c-shared -o dist/libanet_dpi.so .
go test -race ./...
python3 tests/ffi_smoke.py
```

Android examples are in `build-android.sh`. Bundle NOTICE, LICENSE.upstream and THIRD_PARTY_LICENSES with binaries. Android app embeds them in assets/dpi-helper.
