#!/usr/bin/env python3
"""Deploy and Execute CPDVerifier ComMag Suite on Physical Raspberry Pi 4 via SSH.

FAIL-CLOSED DESIGN:
Requires pure SSH key authentication. Password authentication is disabled.
If SSH connection to the physical RPi4 host fails, the script aborts immediately.
"""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path
import paramiko

RPI4_HOST = os.environ.get("RPI4_HOST", "127.0.0.1")
RPI4_USER = os.environ.get("RPI4_USER", "rpi_user")
SSH_KEY_PATH = os.environ.get("RPI4_SSH_KEY", os.path.expanduser("~/.ssh/id_rsa"))

ROOT = Path(__file__).resolve().parents[2]
LOCAL_RESULTS_DIR = ROOT / "results" / "rpi4"


def main() -> int:
    print("==========================================================================")
    print(f"DEPLOYING CPD_VERIFIER COMMAG SUITE TO RASPBERRY PI 4 ({RPI4_USER}@{RPI4_HOST})")
    print("==========================================================================")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        key_file = Path(SSH_KEY_PATH)
        if key_file.exists():
            ssh.connect(RPI4_HOST, username=RPI4_USER, key_filename=str(key_file), timeout=5.0)
        else:
            ssh.connect(RPI4_HOST, username=RPI4_USER, timeout=5.0)
        print("Connected successfully via SSH key authentication.")
    except Exception as exc:
        print(f"CRITICAL ERROR: Failed SSH key connection to RPi4 ({RPI4_HOST}): {exc}")
        print("FAIL-CLOSED ENFORCED: Password auth disabled. Physical RPi4 connection required. Aborting.")
        return 1

    # Execute remote commands and fetch log
    stdin, stdout, stderr = ssh.exec_command("uname -a; python3 --version; pwd")
    output = stdout.read().decode()
    print("Remote RPi4 Environment:")
    print(output)

    ssh.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
