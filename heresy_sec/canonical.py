"""Strict canonical JSON and domain-separated SHA-256 identities."""

from __future__ import annotations

import hashlib
import json
from types import MappingProxyType
from typing import Any, Mapping

from .errors import HeresySecError


DOMAINS = MappingProxyType(
    {
        "action": "HERESY-SEC/ACTION/v1",
        "policy": "HERESY-SEC/POLICY/v1",
        "decision": "HERESY-SEC/DECISION/v1",
        "receipt": "HERESY-SEC/RECEIPT/v1",
        "run": "HERESY-SEC/RUN/v1",
        "manifest": "HERESY-SEC/MANIFEST/v1",
        "implementation": "HERESY-SEC/IMPLEMENTATION/v1",
    }
)

MAX_SAFE_INTEGER = 2**53 - 1


def _invalid(message: str) -> HeresySecError:
    return HeresySecError("CANONICAL_INVALID", message)


def _validate(value: Any, active: set[int]) -> None:
    if value is None or type(value) in (str, bool):
        if type(value) is str:
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise _invalid("canonical strings must be valid UTF-8") from exc
        return
    if type(value) is int:
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise _invalid("canonical integers must remain inside the exact safe-integer range")
        return
    if type(value) is float:
        raise _invalid("floating-point values are forbidden in canonical identity")
    if type(value) is list:
        marker = id(value)
        if marker in active:
            raise _invalid("canonical JSON cannot encode cycles")
        active.add(marker)
        for item in value:
            _validate(item, active)
        active.remove(marker)
        return
    if type(value) is dict:
        marker = id(value)
        if marker in active:
            raise _invalid("canonical JSON cannot encode cycles")
        active.add(marker)
        for key, item in value.items():
            if type(key) is not str:
                raise _invalid("canonical mapping keys must be strings")
            _validate(item, active)
        active.remove(marker)
        return
    raise _invalid(f"unsupported canonical type: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Return compact UTF-8 JSON with recursively sorted object keys."""

    _validate(value, set())
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise _invalid("value cannot be serialized canonically") from exc


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def canonical_clone(value: Any) -> Any:
    return parse_json_bytes(canonical_bytes(value))


def sha256_bytes(value: bytes) -> str:
    if type(value) is not bytes:
        raise _invalid("SHA-256 input must have exact bytes type")
    return hashlib.sha256(value).hexdigest()


def domain_hash(domain: str, value: Any) -> str:
    if type(domain) is not str or not domain or "\x00" in domain:
        raise _invalid("hash domain must be a non-empty NUL-free string")
    return hashlib.sha256(domain.encode("utf-8") + b"\x00" + canonical_bytes(value)).hexdigest()


def without_self_hash(value: Mapping[str, Any], hash_key: str) -> dict[str, Any]:
    if type(hash_key) is not str or not hash_key:
        raise _invalid("self-hash key must be a non-empty string")
    output = dict(value)
    output.pop(hash_key, None)
    return output


def parse_json_bytes(raw: bytes) -> Any:
    """Parse one JSON value while rejecting floats, constants and duplicate keys."""

    if type(raw) is not bytes:
        raise HeresySecError("JSON_INVALID", "JSON input must be exact bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HeresySecError("JSON_INVALID_UTF8", "JSON input is not valid UTF-8") from exc

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in items:
            if type(key) is not str or key in output:
                raise HeresySecError("JSON_DUPLICATE_KEY", "JSON object has a duplicate key")
            output[key] = value
        return output

    def reject_float(_: str) -> Any:
        raise HeresySecError("JSON_FLOAT_FORBIDDEN", "JSON floating-point values are forbidden")

    def reject_constant(_: str) -> Any:
        raise HeresySecError("JSON_CONSTANT_FORBIDDEN", "non-finite JSON constants are forbidden")

    decoder = json.JSONDecoder(
        object_pairs_hook=pairs,
        parse_float=reject_float,
        parse_constant=reject_constant,
    )
    try:
        value, end = decoder.raw_decode(text)
    except HeresySecError:
        raise
    except (ValueError, TypeError) as exc:
        raise HeresySecError("JSON_INVALID", "input is not one valid JSON value") from exc
    if text[end:].strip():
        raise HeresySecError("JSON_TRAILING_DATA", "JSON input has trailing data")
    canonical_bytes(value)
    return value

