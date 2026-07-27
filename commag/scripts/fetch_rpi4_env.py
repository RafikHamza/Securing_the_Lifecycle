#!/usr/bin/env python3
"""Fetch System Environment Manifest from Raspberry Pi 4 via SSH Key Auth.

FAIL-CLOSED DESIGN:
Pure SSH key authentication only. Password authentication disabled.
"""
from __future__ import annotations
import os
import sys
from pathlib import Path
import paramiko

RPI4_HOST = os.environ.get("RPI4_HOST", "127.0.0.1")
RPI4_USER = os.environ.get("RPI4_USER", "rpi_user")
SSH_KEY_PATH = os.environ.get("RPI4_SSH_KEY", os.path.expanduser("~/.ssh/id_rsa"))

ROOT = Path(__file__).resolve().parents[2]
OUT_MANIFEST = ROOT / "results" / "rpi4" / "environment_manifest.txt"


def main() -> int:
    print(f"Connecting to RPi4 via SSH Key Auth...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        key_file = Path(SSH_KEY_PATH)
        if key_file.exists():
            ssh.connect(RPI4_HOST, username=RPI4_USER, key_filename=str(key_file), timeout=5.0)
        else:
            ssh.connect(RPI4_HOST, username=RPI4_USER, timeout=5.0)
    except Exception as exc:
        print(f"CRITICAL ERROR: Failed SSH key connection to {RPI4_HOST}: {exc}")
        print("FAIL-CLOSED ENFORCED: Aborting without generating fallback manifest.")
        return 1

    cmd = "uname -a; uname -m; cat /etc/os-release; python3 --version; gcc --version; free -h; lscpu"
    stdin, stdout, stderr = ssh.exec_command(cmd)
    out_text = stdout.read().decode()

    OUT_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    OUT_MANIFEST.write_text(out_text, encoding="utf-8")
    print(f"Saved RPi4 environment manifest to: {OUT_MANIFEST}")
    ssh.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
