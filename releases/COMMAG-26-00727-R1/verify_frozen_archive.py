#!/usr/bin/env python3
"""Validate the *unchanged* COMMAG R1 ZIP before any extraction or reproduction."""
from __future__ import annotations
import hashlib
import io
import sys
import zipfile
from pathlib import Path

EXPECTED_ZIP_SHA256 = "17acb55c68536a279505b6fd0a19c1622c565ac2b302a6a3dbe8c4946e8c70b6"
EXPECTED_SIZE = 401887
EXPECTED_ENTRIES = 33
EXPECTED_MANIFEST_ENTRIES = 32

def main(path: Path) -> int:
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != EXPECTED_SIZE or digest != EXPECTED_ZIP_SHA256:
        print("FAIL: frozen ZIP bytes do not match release reference")
        print("observed length:", len(data), "SHA-256:", digest)
        return 2
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        assert len(z.infolist()) == EXPECTED_ENTRIES, "unexpected ZIP entry count"
        assert z.testzip() is None, "ZIP CRC failure"
        names = z.namelist()
        roots = {n.split("/")[0] for n in names}
        assert len(roots) == 1, "expected one top-level directory"
        root = roots.pop()
        manifest = z.read(root + "/SHA256SUMS.txt").decode("ascii").splitlines()
        checked = 0
        for line in manifest:
            if not line.strip():
                continue
            expected, relpath = line.split("  ", 1)
            observed = hashlib.sha256(z.read(root + "/" + relpath)).hexdigest()
            assert observed == expected, "manifest mismatch: " + relpath
            checked += 1
        assert checked == EXPECTED_MANIFEST_ENTRIES, "unexpected number of files"
    print("PASS: frozen ZIP SHA-256, size, CRC, and 32/32 manifest entries")
    return 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python verify_frozen_archive.py path/to/FINAL.zip")
    raise SystemExit(main(Path(sys.argv[1])))
