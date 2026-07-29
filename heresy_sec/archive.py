"""Deterministic ZIP_STORED run archives."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from .canonical import sha256_bytes
from .errors import HeresySecError


FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
FIXED_FILE_MODE = 0o100644 << 16


def _regular_archive_files(root: Path) -> list[Path]:
    directories = [root]
    files: list[Path] = []
    while directories:
        directory = directories.pop()
        try:
            entries = sorted(directory.iterdir(), key=lambda path: path.name)
        except OSError as exc:
            raise HeresySecError(
                "ARCHIVE_READ_FAILED",
                "archive source could not be enumerated",
            ) from exc
        children: list[Path] = []
        for path in entries:
            if path.is_symlink():
                raise HeresySecError(
                    "ARCHIVE_SYMLINK_FORBIDDEN",
                    "archive cannot contain symbolic links",
                )
            if path.is_dir():
                children.append(path)
            elif path.is_file():
                files.append(path)
            else:
                raise HeresySecError(
                    "ARCHIVE_ENTRY_INVALID",
                    "archive can contain only regular files and directories",
                )
        directories.extend(reversed(children))
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def deterministic_zip_bytes(run_dir: Path) -> bytes:
    if run_dir.is_symlink():
        raise HeresySecError("ARCHIVE_RUN_INVALID", "archive source cannot be a symbolic link")
    root = run_dir.resolve()
    if not root.is_dir():
        raise HeresySecError("ARCHIVE_RUN_INVALID", "archive source must be a safe run directory")
    paths = _regular_archive_files(root)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        archive.comment = b""
        for path in paths:
            if path.is_symlink():
                raise HeresySecError("ARCHIVE_SYMLINK_FORBIDDEN", "archive cannot contain symbolic links")
            relative = path.relative_to(root).as_posix()
            info = zipfile.ZipInfo(relative, date_time=FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = FIXED_FILE_MODE
            info.extra = b""
            info.comment = b""
            info.flag_bits = 0x800
            try:
                body = path.read_bytes()
            except OSError as exc:
                raise HeresySecError(
                    "ARCHIVE_READ_FAILED",
                    f"archive file could not be read: {relative}",
                ) from exc
            archive.writestr(info, body)
    return buffer.getvalue()


def pack_run(run_dir: Path, output: Path | None = None) -> dict[str, object]:
    body = deterministic_zip_bytes(run_dir)
    target = output or run_dir.with_name(run_dir.name + ".heresy-sec.zip")
    source_root = run_dir.resolve()
    resolved_target = target.resolve()
    if resolved_target == source_root or source_root in resolved_target.parents:
        raise HeresySecError("ARCHIVE_OUTPUT_UNSAFE", "archive output must be outside the run directory")
    if target.is_symlink() or target.exists():
        raise HeresySecError("ARCHIVE_OUTPUT_EXISTS", "archive output already exists")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as handle:
            handle.write(body)
    except FileExistsError as exc:
        raise HeresySecError("ARCHIVE_OUTPUT_EXISTS", "archive output already exists") from exc
    except OSError as exc:
        raise HeresySecError("ARCHIVE_WRITE_FAILED", "archive output could not be written") from exc
    return {
        "status": "PASS",
        "path": str(target),
        "byte_length": len(body),
        "sha256": sha256_bytes(body),
    }
