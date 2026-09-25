#!/usr/bin/env python3
"""Stage a reversible GOST outer-envelope cutover for gw UDP 993.

Run as root on gw. This command does not change the running service.
"""

import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import tomllib
from datetime import datetime, timezone


CURRENT_BINARY = Path("/opt/anet/anet-server")
CURRENT_CONFIG = Path("/opt/anet/server22.toml")
TEST_BINARY = Path("/opt/anet/gost-test/anet-server")
TEST_CONFIG = Path("/opt/anet/gost-test/server.toml")
EXPECTED_TEST_BINARY = "f9bfeedfa928cdbb3977fb8297af71501de60a0f0c8ed097e179634fba659180"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def set_value(text, section, key, value):
    pattern = re.compile(rf"(?ms)^(\[{re.escape(section)}\][ \t]*\n)(.*?)(?=^\[|\Z)")
    match = pattern.search(text)
    if not match:
        raise ValueError(f"Missing [{section}] section")
    body = match.group(2)
    key_pattern = re.compile(rf"(?m)^[ \t]*{re.escape(key)}[ \t]*=.*$")
    replacement = f"{key} = {value}"
    if key_pattern.search(body):
        body = key_pattern.sub(replacement, body, count=1)
    else:
        body = replacement + "\n" + body
    return text[: match.start(2)] + body + text[match.end(2) :]


def sync_copy(source, destination, mode):
    with source.open("rb") as inp, destination.open("xb") as out:
        shutil.copyfileobj(inp, out)
        out.flush()
        os.fsync(out.fileno())
    destination.chmod(mode)


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run as root on gw")
    current_bytes = CURRENT_CONFIG.read_bytes()
    test_bytes = TEST_CONFIG.read_bytes()
    current = tomllib.loads(current_bytes.decode())
    test = tomllib.loads(test_bytes.decode())
    if current["server"]["quic_bind_to"] != "0.0.0.0:993":
        raise SystemExit("Unexpected production UDP bind")
    if test["server"]["quic_bind_to"] != "0.0.0.0:2445":
        raise SystemExit("Unexpected test UDP bind")
    if current["crypto"].get("algorithm", "chacha20-poly1305") != "chacha20-poly1305":
        raise SystemExit("Production cipher is no longer the expected ChaCha mode")
    if test["crypto"].get("algorithm") != "kuznyechik-mgm":
        raise SystemExit("Test server is not in GOST mode")
    for key in ("quic_cert", "quic_key", "server_signing_key"):
        if current["crypto"][key] != test["crypto"][key]:
            raise SystemExit(f"Production and test server {key} differ")
    if digest(TEST_BINARY.read_bytes()) != EXPECTED_TEST_BINARY:
        raise SystemExit("Unexpected test server binary checksum")

    text = current_bytes.decode()
    for section, key, value in (
        ("crypto", "algorithm", '"kuznyechik-mgm"'),
        ("network", "mtu", "1300"),
        ("quic_transport", "max_mtu", "1300"),
        ("quic_transport", "enable_gso", "false"),
        ("quic_transport", "idle_timeout_seconds", "90"),
        ("quic_transport", "keep_alive_interval_seconds", "7"),
    ):
        text = set_value(text, section, key, value)
    staged = tomllib.loads(text)
    expected = dict(current)
    expected["crypto"] = dict(current["crypto"], algorithm="kuznyechik-mgm")
    expected["network"] = dict(current["network"], mtu=1300)
    expected["quic_transport"] = dict(
        current["quic_transport"], max_mtu=1300, enable_gso=False,
        idle_timeout_seconds=90, keep_alive_interval_seconds=7,
    )
    if staged != expected:
        raise SystemExit("Staged config changed unexpected fields")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = Path(f"/opt/anet/backups/gost-cutover-{stamp}")
    backup.mkdir(mode=0o700, parents=True, exist_ok=False)
    sync_copy(CURRENT_BINARY, backup / "anet-server.before", 0o700)
    sync_copy(CURRENT_CONFIG, backup / "server22.toml.before", 0o600)
    sync_copy(TEST_BINARY, backup / "anet-server.new", 0o700)
    new_config = backup / "server22.toml.new"
    with new_config.open("x") as out:
        out.write(text)
        out.flush()
        os.fsync(out.fileno())
    new_config.chmod(0o600)
    rollback = backup / "rollback.sh"
    q = shlex.quote(str(backup))
    rollback.write_text(
        "#!/bin/sh\nset -eu\n"
        f"if [ \"${{1:-}}\" != --force ]; then test ! -e {q}/verified || exit 0; fi\n"
        f"install -m 755 {q}/anet-server.before /opt/anet/anet-server.rollback.tmp\n"
        f"install -m 600 {q}/server22.toml.before /opt/anet/server22.toml.rollback.tmp\n"
        "mv -f /opt/anet/anet-server.rollback.tmp /opt/anet/anet-server\n"
        "mv -f /opt/anet/server22.toml.rollback.tmp /opt/anet/server22.toml\n"
        "systemctl restart anet-server2\n"
    )
    rollback.chmod(0o700)
    directory_fd = os.open(backup, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    print(f"STAGED={backup}")
    print(f"old_binary_sha256={digest(CURRENT_BINARY.read_bytes())}")
    print(f"old_config_sha256={digest(current_bytes)}")
    print(f"new_config_sha256={digest(text.encode())}")
    print(f"test_config_sha256={digest(test_bytes)}")


if __name__ == "__main__":
    main()
