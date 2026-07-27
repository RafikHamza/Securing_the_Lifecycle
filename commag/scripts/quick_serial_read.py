#!/usr/bin/env python3
"""Capture initial serial output from ESP32-S3 on COM8."""
from __future__ import annotations
import sys
import time
from pathlib import Path
import serial

PORT = "COM8"
BAUD = 115200
ROOT_DIR = Path(__file__).resolve().parents[2]
OUT_FILE = ROOT_DIR / "commag" / "results" / "esp32s3" / "initial_serial_capture.txt"


def main():
    print(f"Connecting to {PORT} at {BAUD} baud...")
    captured = []
    try:
        ser = serial.Serial(PORT, BAUD, timeout=1.0)
        time.sleep(0.5)
        ser.reset_input_buffer()
        start = time.time()

        while time.time() - start < 10.0:
            line = ser.readline()
            if line:
                decoded = line.decode("utf-8", errors="replace").strip()
                if decoded:
                    captured.append(decoded)
                    print(decoded.encode("ascii", errors="replace").decode("ascii"))

        ser.close()
    except Exception as exc:
        captured.append(f"[Serial Read Error: {exc}]")

    full_text = "\n".join(captured)
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(full_text, encoding="utf-8")
    print(f"\nSaved initial serial capture ({len(captured)} lines) to:\n{OUT_FILE}")


if __name__ == "__main__":
    main()
