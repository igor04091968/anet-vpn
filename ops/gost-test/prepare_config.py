#!/usr/bin/env python3
"""Create a separate test config on gw; never print or copy its server keys off-host."""
import argparse
import json
import os
from pathlib import Path
import tomllib

parser = argparse.ArgumentParser()
parser.add_argument("--source", default="/opt/anet/server22.toml")
parser.add_argument("--output", default="/opt/anet/gost-test/server.toml")
parser.add_argument("--fingerprints", required=True)
parser.add_argument("--algorithm", choices=["kuznyechik-mgm", "chacha20-poly1305"], default="kuznyechik-mgm")
args = parser.parse_args()
source = tomllib.loads(Path(args.source).read_text())
allowed = Path(args.fingerprints).read_text().splitlines()
if not allowed or any(not value.strip() for value in allowed):
    raise SystemExit("Expected a non-empty list of authorized fingerprints")
config = {
    "network": dict(net="10.23.0.0", mask="255.255.255.0", gateway="10.23.0.1",
                    self_ip="10.23.0.1", if_name="anet-gost-test", mtu=1300),
    "server": dict(quic_bind_to="0.0.0.0:2445", ssh_bind_to="", vnc_bind_to="",
                   websocket_bind_to="", ahttp_bind_to=""),
    "authentication": dict(allowed_clients=allowed, auth_servers=[], auth_server_token=""),
    "crypto": {key: source["crypto"][key] for key in ("quic_cert", "quic_key", "server_signing_key")},
    "stealth": dict(padding_step=64, min_jitter_ns=100000, max_jitter_ns=500000),
    "quic_transport": dict(algorithm="bbr", expected_rtt_ms=100, bandwidth_down_mbps=30,
                           bandwidth_up_mbps=30, max_mtu=1300, enable_gso=False,
                           idle_timeout_seconds=90, keep_alive_interval_seconds=7),
    "shaper": dict(enabled=False),
}
config["crypto"]["algorithm"] = args.algorithm
# JSON scalar/list syntax is valid for these TOML values (including PEM newlines).
text = "\n".join(f"[{section}]\n" + "\n".join(
    f"{key} = {json.dumps(value)}" for key, value in values.items()) + "\n"
    for section, values in config.items())
tomllib.loads(text)
output = Path(args.output)
output.parent.mkdir(parents=True, exist_ok=True)
temporary = output.with_suffix(f".tmp.{os.getpid()}")
fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as stream:
    stream.write(text)
    stream.flush()
    os.fsync(stream.fileno())
os.replace(temporary, output)
directory_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
print(f"Prepared {args.algorithm} test config on UDP 2445; authorized clients: {len(allowed)}")
