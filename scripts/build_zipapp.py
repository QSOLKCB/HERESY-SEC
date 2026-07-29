#!/usr/bin/env python3
"""Build a deterministic ZIP_STORED HERESY-SEC Python zipapp."""

from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "heresy_sec"
OUTPUT = ROOT / "dist" / "heresy_sec.pyz"
SHEBANG = b"#!/usr/bin/env python3\n"
ENTRYPOINT = b"from heresy_sec.cli import main\nraise SystemExit(main())\n"
FIXED_TIME = (1980, 1, 1, 0, 0, 0)
FIXED_MODE = 0o100644 << 16


def zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=FIXED_TIME)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = FIXED_MODE
    info.extra = b""
    info.comment = b""
    info.flag_bits = 0x800
    return info


def build() -> bytes:
    entries = {"__main__.py": ENTRYPOINT}
    for path in sorted(PACKAGE.glob("*.py")):
        entries[f"heresy_sec/{path.name}"] = (
            path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.comment = b""
        for name, body in sorted(entries.items()):
            archive.writestr(zip_info(name), body)
    return SHEBANG + buffer.getvalue()


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    temporary = OUTPUT.with_suffix(".pyz.tmp")
    if temporary.exists():
        raise SystemExit("BUILD_TEMP_EXISTS")
    body = build()
    with temporary.open("xb") as handle:
        handle.write(body)
    os.chmod(temporary, 0o755)
    os.replace(temporary, OUTPUT)
    print(f"PASS {OUTPUT} {len(body)} bytes")


if __name__ == "__main__":
    main()

