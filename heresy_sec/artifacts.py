"""Fail-closed artifact writing and manifest verification."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Mapping

from .canonical import DOMAINS, canonical_bytes, domain_hash, parse_json_bytes, sha256_bytes, without_self_hash
from .errors import HeresySecError


RUN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
README_ORIGIN = (
    "HERESY-SEC v0.1.0 deterministic security evidence run\n"
    "\n"
    "Inputs describe proposed or observed actions. HERESY-SEC executes none of them.\n"
    "SHA-256 receipts prove integrity and lineage, not signer authenticity.\n"
    "No wall-clock value or host path is generated into canonical identity.\n"
).encode("utf-8")


def safe_run_directory(runs_root: Path, run_name: str) -> Path:
    if not RUN_NAME_RE.fullmatch(run_name) or run_name in {".", ".."}:
        raise HeresySecError("OUTPUT_PATH_UNSAFE", "run name is unsafe")
    try:
        if runs_root.is_symlink():
            raise HeresySecError("OUTPUT_PATH_UNSAFE", "runs root cannot be a symbolic link")
        root = runs_root.resolve()
        if root.exists() and not root.is_dir():
            raise HeresySecError("OUTPUT_PATH_UNSAFE", "runs root must be a directory")
        root.mkdir(parents=True, exist_ok=True)
        target = (root / run_name).resolve()
        if target.parent != root:
            raise HeresySecError(
                "OUTPUT_PATH_UNSAFE",
                "run directory must be a direct child of runs root",
            )
        if target.exists():
            if target.is_symlink() or not target.is_dir():
                raise HeresySecError("OUTPUT_PATH_UNSAFE", "run target is not a safe directory")
            if any(target.iterdir()):
                raise HeresySecError("OUTPUT_DIRECTORY_NOT_EMPTY", "run output directory is not empty")
        else:
            target.mkdir(mode=0o755)
        return target
    except OSError as exc:
        raise HeresySecError(
            "OUTPUT_IO_ERROR",
            "run output directory could not be prepared",
        ) from exc


def build_manifest(files: Mapping[str, bytes], run_id: str) -> bytes:
    rows = [
        {"path": path, "byte_length": len(body), "sha256": sha256_bytes(body)}
        for path, body in sorted(files.items())
    ]
    core = {
        "schema": "heresy-sec.manifest/v1",
        "run_id": run_id,
        "files": rows,
        "manifest_sha256": "",
    }
    core["manifest_sha256"] = domain_hash(
        DOMAINS["manifest"],
        without_self_hash(core, "manifest_sha256"),
    )
    return canonical_bytes(core)


def write_artifacts(run_dir: Path, files: Mapping[str, bytes]) -> None:
    try:
        if run_dir.is_symlink():
            raise HeresySecError("OUTPUT_PATH_UNSAFE", "run directory cannot be a symbolic link")
        root = run_dir.resolve()
        if not root.is_dir():
            raise HeresySecError("OUTPUT_PATH_UNSAFE", "run directory is not safe")
    except OSError as exc:
        raise HeresySecError("ARTIFACT_WRITE_FAILED", "artifact root could not be inspected") from exc

    for relative, body in sorted(files.items()):
        if (
            type(relative) is not str
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or type(body) is not bytes
        ):
            raise HeresySecError("ARTIFACT_PATH_UNSAFE", "artifact path or body is unsafe")
        unresolved = root / relative
        try:
            if unresolved.is_symlink() or any(
                parent.is_symlink()
                for parent in unresolved.parents
                if parent != root and root in parent.parents
            ):
                raise HeresySecError(
                    "ARTIFACT_PATH_UNSAFE",
                    "artifact path uses a symbolic link",
                )
            target = unresolved.resolve()
            if root not in target.parents:
                raise HeresySecError("ARTIFACT_PATH_UNSAFE", "artifact escapes run directory")
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.parent.is_symlink() or target.is_symlink():
                raise HeresySecError(
                    "ARTIFACT_PATH_UNSAFE",
                    "artifact path uses a symbolic link",
                )
            with target.open("xb") as handle:
                handle.write(body)
        except FileExistsError as exc:
            raise HeresySecError(
                "ARTIFACT_OUTPUT_EXISTS",
                f"artifact output already exists: {relative}",
            ) from exc
        except OSError as exc:
            raise HeresySecError(
                "ARTIFACT_WRITE_FAILED",
                f"artifact could not be written: {relative}",
            ) from exc


def verify_manifest(run_dir: Path) -> dict[str, object]:
    if run_dir.is_symlink():
        raise HeresySecError("RUN_DIRECTORY_INVALID", "run directory cannot be a symbolic link")
    root = run_dir.resolve()
    if not root.is_dir():
        raise HeresySecError("RUN_DIRECTORY_INVALID", "run directory is invalid")
    manifest_path = root / "manifest.json"
    try:
        manifest = parse_json_bytes(manifest_path.read_bytes())
    except OSError as exc:
        raise HeresySecError("MANIFEST_MISSING", "manifest.json is missing") from exc
    if type(manifest) is not dict or set(manifest) != {
        "schema",
        "run_id",
        "files",
        "manifest_sha256",
    }:
        raise HeresySecError("MANIFEST_INVALID", "manifest fields are invalid")
    if (
        manifest["schema"] != "heresy-sec.manifest/v1"
        or type(manifest["run_id"]) is not str
        or type(manifest["files"]) is not list
        or type(manifest["manifest_sha256"]) is not str
    ):
        raise HeresySecError("MANIFEST_INVALID", "manifest contract is invalid")
    expected_manifest_hash = domain_hash(
        DOMAINS["manifest"],
        without_self_hash(manifest, "manifest_sha256"),
    )
    if manifest["manifest_sha256"] != expected_manifest_hash:
        raise HeresySecError("MANIFEST_HASH_MISMATCH", "manifest self-hash is invalid")

    declared: set[str] = set()
    for row in manifest["files"]:
        if type(row) is not dict or set(row) != {"path", "byte_length", "sha256"}:
            raise HeresySecError("MANIFEST_INVALID", "manifest file row is invalid")
        relative = row["path"]
        if (
            type(relative) is not str
            or relative in declared
            or relative == "manifest.json"
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or type(row["byte_length"]) is not int
            or type(row["sha256"]) is not str
        ):
            raise HeresySecError("MANIFEST_INVALID", "manifest file identity is invalid")
        declared.add(relative)
        unresolved = root / relative
        target = unresolved.resolve()
        if (
            root not in target.parents
            or not target.is_file()
            or unresolved.is_symlink()
            or any(parent.is_symlink() for parent in unresolved.parents if parent != root)
        ):
            raise HeresySecError("MANIFEST_ARTIFACT_MISSING", f"artifact is missing or unsafe: {relative}")
        body = target.read_bytes()
        if len(body) != row["byte_length"] or sha256_bytes(body) != row["sha256"]:
            raise HeresySecError("MANIFEST_ARTIFACT_TAMPERED", f"artifact hash mismatch: {relative}")
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    }
    if actual != declared | {"manifest.json"}:
        raise HeresySecError("MANIFEST_FILE_SET_MISMATCH", "run has missing or undeclared files")
    return {
        "status": "PASS",
        "run_id": manifest["run_id"],
        "manifest_sha256": manifest["manifest_sha256"],
        "artifact_count": len(declared),
    }
