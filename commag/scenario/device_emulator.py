"""ESP32-S3 Telemetry & Camera/Audio Sensor Device Emulator.

Simulates raw sensor acquisition: camera video frames, audio spectral samples,
and 3-axis vibration/environmental telemetry from ESP32-S3 microcontroller endpoint.
"""
from __future__ import annotations
import math
import time

class SensorDeviceEmulator:
    def __init__(self, device_id: str = "esp32s3_sensor_node_01"):
        self.device_id = device_id

    def capture_raw_video(self, frame_index: int) -> dict:
        """Capture raw video frame matrix (raw_video domain)."""
        return {
            "device_id": self.device_id,
            "frame_id": frame_index,
            "raw_pixels": [128 + int(50 * math.sin(frame_index + i)) for i in range(16)],
            "timestamp": time.time(),
        }

    def capture_raw_audio(self, sample_index: int) -> dict:
        """Capture raw audio waveform (raw_audio domain)."""
        return {
            "device_id": self.device_id,
            "sample_id": sample_index,
            "pcm_samples": [int(1000 * math.sin(0.1 * sample_index + j)) for j in range(16)],
            "timestamp": time.time(),
        }

    def capture_raw_telemetry(self, tick_index: int) -> dict:
        """Capture 3-axis vibration/accel telemetry (raw_telemetry domain)."""
        return {
            "device_id": self.device_id,
            "tick_id": tick_index,
            "accel_xyz": [
                0.05 * math.sin(tick_index),
                0.02 * math.cos(tick_index),
                9.81 + 0.1 * math.sin(tick_index * 2),
            ],
            "timestamp": time.time(),
        }
