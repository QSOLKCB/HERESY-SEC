#!/usr/bin/env python3
"""Verify and optionally assemble the inert YAML doctoral-qualifier corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "manifest.json"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def assemble() -> tuple[bytes, dict[str, object]]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    chunks: list[bytes] = []

    for entry in manifest["parts"]:
        path = ROOT / entry["path"]
        data = path.read_bytes()
        if len(data) != entry["bytes"]:
            raise SystemExit(f"size mismatch: {entry['path']}")
        if _sha256(data) != entry["sha256"]:
            raise SystemExit(f"sha256 mismatch: {entry['path']}")
        chunks.append(data)

    payload = b"".join(chunks)
    expected = manifest["assembled"]
    line_count = payload.count(b"\n") + (0 if payload.endswith(b"\n") else 1)

    if len(payload) != expected["bytes"]:
        raise SystemExit("assembled size mismatch")
    if line_count != expected["lines"]:
        raise SystemExit("assembled line-count mismatch")
    if _sha256(payload) != expected["sha256"]:
        raise SystemExit("assembled sha256 mismatch")

    return payload, manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the inert corpus shards; optionally materialize EXAM.yaml."
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write the verified assembled bytes to this path; no YAML is parsed",
    )
    args = parser.parse_args()

    payload, manifest = assemble()
    if args.output is not None:
        args.output.write_bytes(payload)

    result = {
        "bytes": len(payload),
        "lines": manifest["assembled"]["lines"],
        "sha256": _sha256(payload),
        "status": "verified",
        "yaml_parsed": False,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
