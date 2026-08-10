#!/usr/bin/env python3
"""Verify and optionally assemble the inert YAML doctoral-qualifier corpus."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "source"
MANIFEST = ROOT / "manifest.json"
REPO_ROOT = ROOT.parents[1]

# Direct execution places this script's directory, rather than the repository root,
# at sys.path[0]. Add the trusted checkout root so we can reuse HERESY-SEC's strict
# JSON parser without duplicating its security rules in this defensive corpus tool.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from heresy_sec.canonical import parse_json_bytes  # noqa: E402
from heresy_sec.errors import HeresySecError  # noqa: E402


SCHEMA = "heresy-sec.defensive-corpus/v1"
_TOP_LEVEL_KEYS = {"schema", "name", "description", "assembled", "parts"}
_ASSEMBLED_KEYS = {"filename", "sha256", "bytes", "lines"}
_PART_KEYS = {"path", "sha256", "bytes"}
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def line_count(payload: bytes) -> int:
    """Count physical lines; an unterminated final segment counts as one line."""

    if not payload:
        return 0
    return payload.count(b"\n") + (0 if payload.endswith(b"\n") else 1)


def _fail(message: str) -> None:
    raise SystemExit(message)


def _require_exact_keys(value: object, expected: set[str], context: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(f"manifest {context} must be an object")
    mapping = value
    actual = set(mapping)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        _fail(
            f"manifest {context} fields mismatch: missing={missing}, unexpected={unexpected}"
        )
    return mapping


def _require_string(value: object, context: str, *, exact: str | None = None) -> str:
    if type(value) is not str or not value:
        _fail(f"manifest {context} must be a non-empty string")
    if exact is not None and value != exact:
        _fail(f"manifest {context} must equal {exact!r}")
    return value


def _require_positive_int(value: object, context: str, *, allow_zero: bool = False) -> int:
    if type(value) is not int:
        _fail(f"manifest {context} must be an integer")
    minimum = 0 if allow_zero else 1
    if value < minimum:
        _fail(f"manifest {context} must be >= {minimum}")
    return value


def _require_sha256(value: object, context: str) -> str:
    digest = _require_string(value, context)
    if _SHA256_RE.fullmatch(digest) is None:
        _fail(f"manifest {context} must be a lowercase SHA-256 hex digest")
    return digest


def parse_manifest(raw: bytes) -> dict[str, Any]:
    """Strictly parse and validate the exact defensive-corpus manifest schema."""

    try:
        parsed = parse_json_bytes(raw)
    except HeresySecError as exc:
        _fail(f"manifest JSON invalid: {exc.code}: {exc.message}")

    manifest = _require_exact_keys(parsed, _TOP_LEVEL_KEYS, "root")
    _require_string(manifest["schema"], "schema", exact=SCHEMA)
    _require_string(manifest["name"], "name")
    _require_string(manifest["description"], "description")

    assembled = _require_exact_keys(manifest["assembled"], _ASSEMBLED_KEYS, "assembled")
    _require_string(assembled["filename"], "assembled.filename", exact="EXAM.yaml")
    _require_sha256(assembled["sha256"], "assembled.sha256")
    _require_positive_int(assembled["bytes"], "assembled.bytes")
    _require_positive_int(assembled["lines"], "assembled.lines")

    parts = manifest["parts"]
    if type(parts) is not list or not parts:
        _fail("manifest parts must be a non-empty array")

    seen_paths: set[str] = set()
    for index, entry_value in enumerate(parts):
        entry = _require_exact_keys(entry_value, _PART_KEYS, f"parts[{index}]")
        path_text = _require_string(entry["path"], f"parts[{index}].path")
        if path_text in seen_paths:
            _fail(f"manifest duplicate part path: {path_text}")
        seen_paths.add(path_text)
        _require_sha256(entry["sha256"], f"parts[{index}].sha256")
        _require_positive_int(entry["bytes"], f"parts[{index}].bytes")

    return manifest


def _validated_part_path(root: Path, source: Path, path_text: str) -> Path:
    """Return a regular non-symlinked direct child of source or fail closed."""

    relative = PurePosixPath(path_text)
    canonical = f"source/{relative.name}"
    if (
        relative.is_absolute()
        or len(relative.parts) != 2
        or relative.parts[0] != "source"
        or path_text != canonical
        or not relative.name.endswith(".yaml.part")
    ):
        _fail(f"manifest part path is outside canonical source layout: {path_text}")

    if source.is_symlink() or not source.is_dir():
        _fail("corpus source directory must be a real directory, not a symlink")

    candidate = root / Path(*relative.parts)
    if candidate.is_symlink():
        _fail(f"manifest part must not be a symlink: {path_text}")
    if not candidate.is_file():
        _fail(f"manifest part is not a regular file: {path_text}")

    try:
        source_resolved = source.resolve(strict=True)
        candidate_resolved = candidate.resolve(strict=True)
    except OSError as exc:
        _fail(f"cannot resolve manifest part {path_text}: {exc}")

    if candidate_resolved.parent != source_resolved:
        _fail(f"manifest part escapes source directory: {path_text}")
    return candidate


def assemble() -> tuple[bytes, dict[str, Any]]:
    manifest = parse_manifest(MANIFEST.read_bytes())
    chunks: list[bytes] = []

    for entry in manifest["parts"]:
        path = _validated_part_path(ROOT, SOURCE, entry["path"])
        data = path.read_bytes()
        if len(data) != entry["bytes"]:
            _fail(f"size mismatch: {entry['path']}")
        if _sha256(data) != entry["sha256"]:
            _fail(f"sha256 mismatch: {entry['path']}")
        chunks.append(data)

    payload = b"".join(chunks)
    expected = manifest["assembled"]

    if len(payload) != expected["bytes"]:
        _fail("assembled size mismatch")
    if line_count(payload) != expected["lines"]:
        _fail("assembled line-count mismatch")
    if _sha256(payload) != expected["sha256"]:
        _fail("assembled sha256 mismatch")

    return payload, manifest


def write_new_output(path: Path, payload: bytes) -> None:
    """Write a new output atomically with respect to creation; never overwrite."""

    # The explicit pre-check gives a clear error (including broken symlinks), while
    # exclusive creation below closes the time-of-check/time-of-use race.
    if path.exists() or path.is_symlink():
        _fail(f"refusing to overwrite existing output: {path}")
    try:
        with path.open("xb") as handle:
            handle.write(payload)
    except FileExistsError:
        _fail(f"refusing to overwrite existing output: {path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the inert corpus shards; optionally materialize EXAM.yaml."
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write verified bytes to a new path; existing paths are never overwritten",
    )
    args = parser.parse_args()

    payload, manifest = assemble()
    if args.output is not None:
        write_new_output(args.output, payload)

    result = {
        "bytes": len(payload),
        "lines": manifest["assembled"]["lines"],
        "sha256": _sha256(payload),
        "status": "verified",
        "yaml_parsed": False,
    }
    from heresy_sec.canonical import canonical_json

    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
