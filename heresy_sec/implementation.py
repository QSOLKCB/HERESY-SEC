"""Identity of the exact HERESY-SEC source bundle used for a run."""

from __future__ import annotations

from importlib import resources
from typing import Any

from . import __version__
from .canonical import DOMAINS, domain_hash, sha256_bytes
from .errors import HeresySecError


IMPLEMENTATION_MODULES = (
    "__init__.py",
    "__main__.py",
    "archive.py",
    "artifacts.py",
    "canonical.py",
    "cli.py",
    "contracts.py",
    "engine.py",
    "errors.py",
    "geometry.py",
    "geometry_math.py",
    "geometry_profile_v2.py",
    "geometry_profile_v2_evidence.py",
    "geometry_profile_v2_policy.py",
    "geometry_profile_v2_runtime.py",
    "geometry_profile_v2_sensors.py",
    "implementation.py",
    "policy.py",
    "selftest.py",
)


def _normalized_source(name: str) -> bytes:
    body = resources.files("heresy_sec").joinpath(name).read_bytes()
    return body.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def build_implementation_identity() -> dict[str, Any]:
    rows = []
    for name in IMPLEMENTATION_MODULES:
        body = _normalized_source(name)
        rows.append(
            {
                "path": f"heresy_sec/{name}",
                "byte_length": len(body),
                "sha256": sha256_bytes(body),
            }
        )
    core = {
        "schema": "heresy-sec.implementation/v1",
        "version": __version__,
        "runtime": "python-standard-library",
        "source_files": rows,
    }
    return {
        **core,
        "source_bundle_sha256": domain_hash(DOMAINS["implementation"], core),
    }


def normalize_implementation(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {
        "schema",
        "version",
        "runtime",
        "source_files",
        "source_bundle_sha256",
    }:
        raise HeresySecError("IMPLEMENTATION_INVALID", "implementation record has invalid fields")
    if (
        value["schema"] != "heresy-sec.implementation/v1"
        or type(value["version"]) is not str
        or value["runtime"] != "python-standard-library"
        or type(value["source_files"]) is not list
    ):
        raise HeresySecError("IMPLEMENTATION_INVALID", "implementation record is invalid")
    rows = []
    seen = set()
    for row in value["source_files"]:
        if type(row) is not dict or set(row) != {"path", "byte_length", "sha256"}:
            raise HeresySecError("IMPLEMENTATION_INVALID", "source-file record is invalid")
        if (
            type(row["path"]) is not str
            or type(row["byte_length"]) is not int
            or type(row["sha256"]) is not str
            or len(row["sha256"]) != 64
            or row["path"] in seen
        ):
            raise HeresySecError("IMPLEMENTATION_INVALID", "source-file identity is invalid")
        seen.add(row["path"])
        rows.append(dict(row))
    core = {
        "schema": value["schema"],
        "version": value["version"],
        "runtime": value["runtime"],
        "source_files": rows,
    }
    expected = domain_hash(DOMAINS["implementation"], core)
    if value["source_bundle_sha256"] != expected:
        raise HeresySecError("IMPLEMENTATION_HASH_MISMATCH", "implementation self-hash is invalid")
    return {**core, "source_bundle_sha256": expected}
