# ESP32-S3 Firmware Flashing Instructions

This document outlines how to build and flash the ESP32-S3 firmware using the ESP-IDF framework.

## Prerequisites
- ESP-IDF v4.4.7 or later installed on host machine.
- USB-to-UART drivers (CH343 / CH340 driver for COM8).

## Build and Flash Steps

```bash
# 1. Set ESP-IDF environment variables
export IDF_PATH=/path/to/esp-idf
source $IDF_PATH/export.sh

# 2. Navigate to firmware directory
cd commag/hardware/esp32s3/firmware/

# 3. Set target to ESP32-S3
idf.py set-target esp32s3

# 4. Build, flash to COM8, and start monitor
idf.py -p COM8 -b 115200 build flash monitor
```

## Serial Monitoring
To monitor the serial stream without re-flashing:

```bash
python -m serial.tools.miniterm COM8 115200
```
