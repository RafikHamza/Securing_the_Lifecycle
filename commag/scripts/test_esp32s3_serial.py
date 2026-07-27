#!/usr/bin/env python3
"""Inspect COM8 Serial Output at Multiple Baud Rates for ESP32-S3."""
from __future__ import annotations
import sys
import time
import serial

PORT = "COM8"
BAUD_RATES = [115200, 9600, 57600, 230400, 460800, 921600]

def test_baud(baud: int, duration: float = 3.0) -> tuple[str, bool]:
    try:
        ser = serial.Serial(PORT, baud, timeout=1.0)
        time.sleep(0.5)
        ser.reset_input_buffer()
        start = time.time()
        captured = []
        is_readable = False

        while time.time() - start < duration:
            line = ser.readline()
            if line:
                try:
                    decoded = line.decode("utf-8", errors="replace").strip()
                    captured.append(decoded)
                    # Check if printable ASCII without high density of replacement chars
                    if len(decoded) > 3 and not decoded.startswith(""):
                        is_readable = True
                except Exception:
                    pass

        ser.close()
        text = "\n".join(captured)
        return text, is_readable
    except Exception as exc:
        return f"Error opening port at {baud}: {exc}", False

def main():
    print(f"Testing serial port {PORT} across baud rates...")
    results = {}
    for b in BAUD_RATES:
        print(f"\n--- Testing Baud {b} ---")
        text, readable = test_baud(b, duration=3.0)
        results[b] = (text, readable)
        print(f"Readable: {readable}")
        print("Captured sample:")
        print(text[:500] if text else "<No data received>")

    # Select best baud rate
    best_baud = None
    for b in BAUD_RATES:
        if results[b][1]:
            best_baud = b
            break

    if best_baud is None:
        best_baud = 115200

    print(f"\n=========================================")
    print(f"Selected Best Baud Rate: {best_baud}")
    print(f"=========================================")
    return best_baud

if __name__ == "__main__":
    main()
