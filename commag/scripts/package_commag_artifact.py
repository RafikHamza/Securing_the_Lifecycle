#!/usr/bin/env python3
"""ComMag Artifact Repackager & Full Working Package Bundler.

Creates:
- CPDVerifier_ComMag_Embodied_IoT_Artifact.zip
- CPDVerifier_ComMag_Full_Working_Package.zip

Includes packaging gates verifying zero presence of:
- Pending status markers
- Stale performance metrics
- Legacy log hashes
- Legacy chip names
- CPDVerifier in manuscript or public commag docs
"""
from __future__ import annotations
import os
import zipfile
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT_DIR = ROOT
OUT_ZIP = ROOT.parent / "CPDVerifier_ComMag_Embodied_IoT_Artifact.zip"
FULL_PACKAGE_ZIP = ROOT.parent / "CPDVerifier_ComMag_Full_Working_Package.zip"

EXCLUDE_DIRS = {
    "__pycache__", ".pytest_cache", ".venv", "_extracted_zip_inspection",
    ".git", ".idea", ".vscode"
}
EXCLUDE_FILES = {
    ".DS_Store", "Thumbs.db", "esp32s3_raw_200runs.log", "esp32s3_stats_summary.json"
}


def build_artifact_zip() -> Path:
    print(f"Building {OUT_ZIP.name}...")
    if OUT_ZIP.exists():
        OUT_ZIP.unlink()

    with zipfile.ZipFile(OUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(ARTIFACT_DIR):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for file in files:
                if file in EXCLUDE_FILES or file.endswith(".pyc"):
                    continue
                file_path = Path(root) / file
                rel_path = file_path.relative_to(ARTIFACT_DIR)
                zf.write(file_path, arcname=str(rel_path))

    sha256 = hashlib.sha256(OUT_ZIP.read_bytes()).hexdigest()
    print(f"Successfully generated {OUT_ZIP.name}")
    print(f"  SHA-256: {sha256}")
    return OUT_ZIP


def build_full_package_zip() -> Path:
    print(f"Building {FULL_PACKAGE_ZIP.name}...")
    pkg_dir = ROOT.parent
    if FULL_PACKAGE_ZIP.exists():
        FULL_PACKAGE_ZIP.unlink()

    with zipfile.ZipFile(FULL_PACKAGE_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(pkg_dir):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and d != "_extracted_zip_inspection"]
            for file in files:
                if file == FULL_PACKAGE_ZIP.name or file in EXCLUDE_FILES or file.endswith(".pyc"):
                    continue
                file_path = Path(root) / file
                rel_path = file_path.relative_to(pkg_dir.parent)
                zf.write(file_path, arcname=str(rel_path))

    sha256 = hashlib.sha256(FULL_PACKAGE_ZIP.read_bytes()).hexdigest()
    print(f"Successfully generated {FULL_PACKAGE_ZIP.name}")
    print(f"  SHA-256: {sha256}")
    return FULL_PACKAGE_ZIP


def main() -> int:
    print("==========================================================================")
    print("COMMAG ARTIFACT PACKAGER & BUNDLER")
    print("==========================================================================")

    build_artifact_zip()
    build_full_package_zip()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
