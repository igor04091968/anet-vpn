"""Local-only C ABI checks: borrowed FD ownership and cross-thread cancellation."""
import ctypes, json, socket, ssl, threading, time
from pathlib import Path
root=Path(__file__).resolve().parents[3]
lib=ctypes.CDLL(str(root/'tools/dpi-helper/dist/libanet_dpi.so'))
lib.anet_dpi_probe.argtypes=[ctypes.c_ulonglong,ctypes.c_int,ctypes.c_char_p]
lib.anet_dpi_probe.restype=ctypes.c_void_p
lib.anet_dpi_free.argtypes=[ctypes.c_void_p]
lib.anet_dpi_cancel.argtypes=[ctypes.c_ulonglong]

def call(probe_id,sock):
 raw=json.dumps(dict(fingerprint='android',sni='localhost',timeout_ms=15000)).encode()
 ptr=lib.anet_dpi_probe(probe_id,sock.fileno(),raw)
 try:return json.loads(ctypes.string_at(ptr))
 finally:lib.anet_dpi_free(ptr)

listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(root/'anet-client-core/tests/fixtures/connection-limit-test-cert.pem.fixture',root/'anet-client-core/tests/fixtures/connection-limit-test-key.pem.fixture')
def server():
 conn,_=listener.accept()
 with context.wrap_socket(conn,server_side=True) as tls: tls.recv(1)
thread=threading.Thread(target=server,daemon=True);thread.start()
with socket.create_connection(listener.getsockname()) as sock:
 result=call(101,sock)
 assert result['status']=='passed',result
 # fstat works only while the Rust/caller-owned descriptor remains valid.
 import os
 os.fstat(sock.fileno())
thread.join(2)

with socket.create_connection(listener.getsockname()) as sock:
 peer,_=listener.accept()
 results=[]
 thread=threading.Thread(target=lambda:results.append(call(102,sock)))
 started=time.monotonic();thread.start()
 while thread.is_alive() and time.monotonic()-started<2:
  lib.anet_dpi_cancel(102);thread.join(0.02)
 assert not thread.is_alive(),'C ABI cancellation did not stop within 2 seconds'
 assert results[0]['code']=='cancelled',results
 os.fstat(sock.fileno());peer.close()
listener.close()
print('C ABI: TLS, borrowed FD preservation, cancellation passed')
