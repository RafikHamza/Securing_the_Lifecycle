# ESP32-S3 Hardware Profile

This document records the exact hardware specs, serial interface configuration, and firmware environment of the physical ESP32-S3 characterization endpoint connected to the host system.

---

## Hardware Characterization Profile

- **Module:** ESP32-S3-WROOM-1
- **Development Board Name:** ESP32-S3-DevKitC-1 (CH343 USB-to-UART Bridge)
- **Serial Port:** `COM8`
- **USB Vendor & Product ID:** `USB VID:PID=1A86:55D3` (QinHeng Electronics CH343 USB-Enhanced-SERIAL)
- **Baud Rate:** `115200` baud
- **Firmware Classification:** Post-quantum ML-KEM-1024 decapsulation benchmark (`vh-mlkem-esp32s3-bench`) compiled under ESP-IDF `v4.4.7-dirty`.
- **Characterization Protocol:**
  - `total_runs`: Pending genuine raw serial capture stream
  - `raw_log_file`: `commag/results/esp32s3/esp32s3_raw_200runs.log`
  - `aggregation_script`: `commag/scripts/aggregate_esp32s3_bench.py`
- **Actuation & Sensor Classification:**
  - The ESP32-S3 operates as a **physical hardware characterization endpoint**.
  - Onboard addressable RGB LED (GPIO 48) is physically present on the module. In the current reproducible workflow, physical actuation is emulated, and the serial benchmark characterizes endpoint performance separately from the ComMag static contract verifier.
- **Evaluation Methodology:**
  - The experimental setup combines **deterministic multimodal replay**, **real RPi4 static verifier execution**, and **separate ESP32-S3 serial characterization**. It is not claimed to be a complete physical multimodal sensing-to-actuation testbed.
