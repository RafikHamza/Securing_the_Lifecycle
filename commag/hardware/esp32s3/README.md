# ESP32-S3 Physical Endpoint Integration

This directory contains the firmware documentation, host serial bridge adapter, message schemas, and flashing instructions for the ESP32-S3 sensing endpoint.

## Directory Structure

```text
commag/hardware/esp32s3/
├── README.md
├── ESP32S3_HARDWARE_PROFILE.md
├── firmware/
│   └── README.md
├── host_adapter/
│   └── serial_bridge.py
├── message_schema.json
├── flash_instructions.md
└── expected_output/
    └── sample_serial_output.json
```

## Host Adapter Execution

To run the host bridge adapter connecting the ESP32-S3 over USB serial:

```bash
python commag/hardware/esp32s3/host_adapter/serial_bridge.py --port COM8 --baud 115200
```
