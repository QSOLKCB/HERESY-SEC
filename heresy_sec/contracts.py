"""Validated identity-bearing contracts for actions, policies and receipts."""

from __future__ import annotations

import re
from typing import Any, Iterable

from .canonical import DOMAINS, canonical_clone, domain_hash, without_self_hash
from .errors import HeresySecError


IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$")
HEX_RE = re.compile(r"^[0-9a-f]{64}$")
OPERATION_RE = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")

SERVICES = frozenset({"file", "network", "process", "ipc", "model", "tool", "system"})
AUTHORITIES = frozenset(
    {"SIM_ONLY", "READ_ONLY_EXTERNAL", "WORKSPACE_WRITE", "NETWORK", "CONTROLLED_EXECUTION"}
)
EFFECTS = frozenset({"ALLOW", "DENY", "REVIEW"})
MODEL_KINDS = frozenset({"OPEN_WEIGHT", "CLOSED", "NO_MODEL", "UNKNOWN"})


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise HeresySecError("CONTRACT_INVALID", f"{label} must be an object")
    return value


def _keys(
    value: dict[str, Any],
    *,
    required: Iterable[str],
    optional: Iterable[str] = (),
    label: str,
) -> None:
    required_set = set(required)
    allowed = required_set | set(optional)
    missing = sorted(required_set - set(value))
    unexpected = sorted(set(value) - allowed)
    if missing:
        raise HeresySecError("CONTRACT_FIELD_MISSING", f"{label} is missing fields: {', '.join(missing)}")
    if unexpected:
        raise HeresySecError(
            "CONTRACT_FIELD_UNEXPECTED",
            f"{label} has unexpected fields: {', '.join(unexpected)}",
        )


def _string(value: Any, label: str, *, minimum: int = 1, maximum: int = 2048) -> str:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        raise HeresySecError("CONTRACT_INVALID", f"{label} must be a string of length {minimum}..{maximum}")
    return value


def _nullable_string(value: Any, label: str, *, maximum: int = 2048) -> str | None:
    if value is None:
        return None
    return _string(value, label, maximum=maximum)


def _identifier(value: Any, label: str) -> str:
    text = _string(value, label, maximum=256)
    if not IDENTIFIER_RE.fullmatch(text):
        raise HeresySecError("CONTRACT_INVALID", f"{label} is not a stable identifier")
    return text


def _integer(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise HeresySecError("CONTRACT_INVALID", f"{label} must be an exact integer in {minimum}..{maximum}")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise HeresySecError("CONTRACT_INVALID", f"{label} must be an exact boolean")
    return value


def _choice(value: Any, label: str, choices: frozenset[str]) -> str:
    text = _string(value, label, maximum=64)
    if text not in choices:
        raise HeresySecError("CONTRACT_INVALID", f"{label} has unsupported value: {text}")
    return text


def _digest(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not HEX_RE.fullmatch(value):
        raise HeresySecError("CONTRACT_INVALID", f"{label} must be null or a lowercase SHA-256 digest")
    return value


def _required_digest(value: Any, label: str) -> str:
    digest = _digest(value, label)
    if digest is None:
        raise HeresySecError("CONTRACT_INVALID", f"{label} cannot be null")
    return digest


def _string_set(
    value: Any,
    label: str,
    *,
    choices: frozenset[str] | None = None,
    allow_wildcard: bool = False,
    maximum_items: int = 256,
) -> list[str]:
    if type(value) is not list or not 1 <= len(value) <= maximum_items:
        raise HeresySecError("CONTRACT_INVALID", f"{label} must be a non-empty list")
    output: list[str] = []
    for index, item in enumerate(value):
        text = _string(item, f"{label}[{index}]", maximum=2048)
        if choices is not None and text not in choices and not (allow_wildcard and text == "*"):
            raise HeresySecError("CONTRACT_INVALID", f"{label}[{index}] has unsupported value: {text}")
        output.append(text)
    if len(set(output)) != len(output):
        raise HeresySecError("CONTRACT_INVALID", f"{label} cannot contain duplicates")
    return sorted(output)


def normalize_producer(value: Any) -> dict[str, Any]:
    source = _mapping(value, "producer")
    _keys(
        source,
        required=("schema", "agent_id", "model_kind"),
        optional=(
            "workload_id",
            "model_id",
            "model_digest",
            "harness_id",
            "harness_digest",
        ),
        label="producer",
    )
    if source["schema"] != "heresy-sec.producer/v1":
        raise HeresySecError("SCHEMA_UNSUPPORTED", "producer schema must be heresy-sec.producer/v1")
    model_kind = _choice(source["model_kind"], "producer.model_kind", MODEL_KINDS)
    model_id = _nullable_string(source.get("model_id"), "producer.model_id", maximum=256)
    model_digest = _digest(source.get("model_digest"), "producer.model_digest")
    if model_kind == "NO_MODEL" and (model_id is not None or model_digest is not None):
        raise HeresySecError(
            "CONTRACT_INVALID",
            "NO_MODEL producers cannot declare model identity",
        )
    return {
        "schema": "heresy-sec.producer/v1",
        "agent_id": _identifier(source["agent_id"], "producer.agent_id"),
        "workload_id": _nullable_string(source.get("workload_id"), "producer.workload_id", maximum=512),
        "model_id": model_id,
        "model_kind": model_kind,
        "model_digest": model_digest,
        "harness_id": _nullable_string(source.get("harness_id"), "producer.harness_id", maximum=256),
        "harness_digest": _digest(source.get("harness_digest"), "producer.harness_digest"),
    }


def normalize_action(value: Any) -> dict[str, Any]:
    action = _mapping(value, "action")
    _keys(
        action,
        required=("schema", "action_id", "sequence", "producer", "service", "operation", "target"),
        optional=("observed_at", "parameters", "requested_authority", "slot", "context"),
        label="action",
    )
    if action["schema"] != "heresy-sec.action/v1":
        raise HeresySecError("SCHEMA_UNSUPPORTED", "action schema must be heresy-sec.action/v1")
    operation = _string(action["operation"], "action.operation", maximum=64)
    if not OPERATION_RE.fullmatch(operation):
        raise HeresySecError("CONTRACT_INVALID", "action.operation has invalid syntax")
    slot = action.get("slot")
    if slot is not None:
        slot = _integer(slot, "action.slot", minimum=0, maximum=2**31 - 1)
    parameters = action.get("parameters", {})
    context = action.get("context", {})
    _mapping(parameters, "action.parameters")
    _mapping(context, "action.context")
    return {
        "schema": "heresy-sec.action/v1",
        "action_id": _identifier(action["action_id"], "action.action_id"),
        "sequence": _integer(action["sequence"], "action.sequence", minimum=0, maximum=2**53 - 1),
        "producer": normalize_producer(action["producer"]),
        "observed_at": _nullable_string(action.get("observed_at"), "action.observed_at", maximum=64),
        "service": _choice(action["service"], "action.service", SERVICES),
        "operation": operation,
        "target": _string(action["target"], "action.target", maximum=2048),
        "parameters": canonical_clone(parameters),
        "requested_authority": _choice(
            action.get("requested_authority", "SIM_ONLY"),
            "action.requested_authority",
            AUTHORITIES,
        ),
        "slot": slot,
        "context": canonical_clone(context),
    }


def action_identity(action: dict[str, Any]) -> str:
    return domain_hash(DOMAINS["action"], normalize_action(action))


DEFAULT_BOUNDARIES: dict[str, Any] = {
    "allowed_authorities": ["SIM_ONLY"],
    "max_parameter_bytes": 16384,
    "max_ipc_slots": 32,
    "network_enabled": False,
    "allowed_network_schemes": ["https"],
    "allowed_network_hosts": [],
    "process_enabled": False,
    "allowed_processes": [],
    "file_target_prefixes": ["workspace/"],
}


def _relative_prefix(value: str, label: str) -> str:
    if value == "*":
        return value
    if "\\" in value or "\x00" in value or value.startswith("/"):
        raise HeresySecError("CONTRACT_INVALID", f"{label} must be a safe relative POSIX prefix")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts if part != parts[-1]):
        raise HeresySecError("CONTRACT_INVALID", f"{label} must be a safe relative POSIX prefix")
    cleaned = value.rstrip("/")
    if not cleaned or any(part in {"", ".", ".."} for part in cleaned.split("/")):
        raise HeresySecError("CONTRACT_INVALID", f"{label} must be a safe relative POSIX prefix")
    return cleaned + "/"


def normalize_boundaries(value: Any) -> dict[str, Any]:
    source = _mapping(value, "policy.boundaries")
    _keys(
        source,
        required=(),
        optional=tuple(DEFAULT_BOUNDARIES),
        label="policy.boundaries",
    )
    merged = {**DEFAULT_BOUNDARIES, **source}
    prefixes = _string_set(merged["file_target_prefixes"], "boundaries.file_target_prefixes")
    schemes = _string_set(
        merged["allowed_network_schemes"],
        "boundaries.allowed_network_schemes",
    )
    hosts = (
        _string_set(
            merged["allowed_network_hosts"],
            "boundaries.allowed_network_hosts",
        )
        if merged["allowed_network_hosts"]
        else []
    )
    if any(item != item.lower() or not OPERATION_RE.fullmatch(item) for item in schemes):
        raise HeresySecError(
            "CONTRACT_INVALID",
            "allowed network schemes must be lower-case scheme names",
        )
    if any(
        item != item.lower()
        or "/" in item
        or "@" in item
        or "\x00" in item
        or item.startswith(".")
        or item.endswith(".")
        for item in hosts
    ):
        raise HeresySecError(
            "CONTRACT_INVALID",
            "allowed network hosts must be lower-case exact host names",
        )
    return {
        "allowed_authorities": _string_set(
            merged["allowed_authorities"],
            "boundaries.allowed_authorities",
            choices=AUTHORITIES,
        ),
        "max_parameter_bytes": _integer(
            merged["max_parameter_bytes"],
            "boundaries.max_parameter_bytes",
            minimum=0,
            maximum=16_777_216,
        ),
        "max_ipc_slots": _integer(
            merged["max_ipc_slots"],
            "boundaries.max_ipc_slots",
            minimum=1,
            maximum=65_536,
        ),
        "network_enabled": _boolean(merged["network_enabled"], "boundaries.network_enabled"),
        "allowed_network_schemes": schemes,
        "allowed_network_hosts": hosts,
        "process_enabled": _boolean(merged["process_enabled"], "boundaries.process_enabled"),
        "allowed_processes": _string_set(
            merged["allowed_processes"] or ["__NONE__"],
            "boundaries.allowed_processes",
        )
        if merged["allowed_processes"]
        else [],
        "file_target_prefixes": sorted(
            _relative_prefix(item, f"boundaries.file_target_prefixes[{index}]")
            for index, item in enumerate(prefixes)
        ),
    }


def normalize_rule(value: Any) -> dict[str, Any]:
    rule = _mapping(value, "rule")
    _keys(
        rule,
        required=("schema", "rule_id", "priority", "effect"),
        optional=("services", "operations", "target_prefixes", "agent_ids", "authorities"),
        label="rule",
    )
    if rule["schema"] != "heresy-sec.rule/v1":
        raise HeresySecError("SCHEMA_UNSUPPORTED", "rule schema must be heresy-sec.rule/v1")
    return {
        "schema": "heresy-sec.rule/v1",
        "rule_id": _identifier(rule["rule_id"], "rule.rule_id"),
        "priority": _integer(rule["priority"], "rule.priority", minimum=-1_000_000, maximum=1_000_000),
        "effect": _choice(rule["effect"], "rule.effect", EFFECTS),
        "services": _string_set(
            rule.get("services", ["*"]),
            "rule.services",
            choices=SERVICES,
            allow_wildcard=True,
        ),
        "operations": _string_set(rule.get("operations", ["*"]), "rule.operations"),
        "target_prefixes": _string_set(rule.get("target_prefixes", ["*"]), "rule.target_prefixes"),
        "agent_ids": _string_set(rule.get("agent_ids", ["*"]), "rule.agent_ids"),
        "authorities": _string_set(
            rule.get("authorities", ["*"]),
            "rule.authorities",
            choices=AUTHORITIES,
            allow_wildcard=True,
        ),
    }


def normalize_policy(value: Any) -> dict[str, Any]:
    policy = _mapping(value, "policy")
    _keys(
        policy,
        required=("schema", "policy_id", "default_effect", "rules"),
        optional=("boundaries",),
        label="policy",
    )
    if policy["schema"] != "heresy-sec.policy/v1":
        raise HeresySecError("SCHEMA_UNSUPPORTED", "policy schema must be heresy-sec.policy/v1")
    if type(policy["rules"]) is not list or len(policy["rules"]) > 4096:
        raise HeresySecError("CONTRACT_INVALID", "policy.rules must be a list with at most 4096 items")
    rules = [normalize_rule(item) for item in policy["rules"]]
    rule_ids = [item["rule_id"] for item in rules]
    if len(set(rule_ids)) != len(rule_ids):
        raise HeresySecError("CONTRACT_INVALID", "policy rule_id values must be unique")
    return {
        "schema": "heresy-sec.policy/v1",
        "policy_id": _identifier(policy["policy_id"], "policy.policy_id"),
        "default_effect": _choice(policy["default_effect"], "policy.default_effect", EFFECTS),
        "boundaries": normalize_boundaries(policy.get("boundaries", {})),
        "rules": sorted(rules, key=lambda item: item["rule_id"]),
    }


def policy_identity(policy: dict[str, Any]) -> str:
    return domain_hash(DOMAINS["policy"], normalize_policy(policy))


def build_decision(
    *,
    action_sha256: str,
    policy_sha256: str,
    effect: str,
    reason_codes: list[str],
    matched_rule_ids: list[str],
    selected_rule_id: str | None,
) -> dict[str, Any]:
    core = {
        "schema": "heresy-sec.decision/v1",
        "action_sha256": _required_digest(action_sha256, "decision.action_sha256"),
        "policy_sha256": _required_digest(policy_sha256, "decision.policy_sha256"),
        "effect": _choice(effect, "decision.effect", EFFECTS),
        "reason_codes": sorted(set(reason_codes)),
        "matched_rule_ids": sorted(set(matched_rule_ids)),
        "selected_rule_id": selected_rule_id,
        "decision_sha256": "",
    }
    if selected_rule_id is not None:
        _identifier(selected_rule_id, "decision.selected_rule_id")
        if selected_rule_id not in core["matched_rule_ids"]:
            raise HeresySecError("DECISION_INVALID", "selected rule is not in the matched rule set")
    for index, code in enumerate(core["reason_codes"]):
        _identifier(code, f"decision.reason_codes[{index}]")
    if not core["reason_codes"]:
        raise HeresySecError("DECISION_INVALID", "decision must contain at least one reason code")
    for index, rule_id in enumerate(core["matched_rule_ids"]):
        _identifier(rule_id, f"decision.matched_rule_ids[{index}]")
    core["decision_sha256"] = domain_hash(
        DOMAINS["decision"],
        without_self_hash(core, "decision_sha256"),
    )
    return core


def normalize_decision(value: Any) -> dict[str, Any]:
    decision = _mapping(value, "decision")
    _keys(
        decision,
        required=(
            "schema",
            "action_sha256",
            "policy_sha256",
            "effect",
            "reason_codes",
            "matched_rule_ids",
            "selected_rule_id",
            "decision_sha256",
        ),
        label="decision",
    )
    if decision["schema"] != "heresy-sec.decision/v1":
        raise HeresySecError("SCHEMA_UNSUPPORTED", "decision schema must be heresy-sec.decision/v1")
    rebuilt = build_decision(
        action_sha256=decision["action_sha256"],
        policy_sha256=decision["policy_sha256"],
        effect=decision["effect"],
        reason_codes=_string_set(decision["reason_codes"], "decision.reason_codes"),
        matched_rule_ids=_string_set(
            decision["matched_rule_ids"] or ["__NONE__"],
            "decision.matched_rule_ids",
        )
        if decision["matched_rule_ids"]
        else [],
        selected_rule_id=decision["selected_rule_id"],
    )
    if decision["decision_sha256"] != rebuilt["decision_sha256"]:
        raise HeresySecError("DECISION_HASH_MISMATCH", "decision self-hash is invalid")
    return rebuilt


def build_receipt(
    *,
    index: int,
    capture_sha256: str,
    action_sha256: str,
    policy_sha256: str,
    decision_sha256: str,
    previous_receipt_sha256: str,
) -> dict[str, Any]:
    core = {
        "schema": "heresy-sec.receipt/v1",
        "index": _integer(index, "receipt.index", minimum=0, maximum=2**53 - 1),
        "capture_sha256": _required_digest(capture_sha256, "receipt.capture_sha256"),
        "action_sha256": _required_digest(action_sha256, "receipt.action_sha256"),
        "policy_sha256": _required_digest(policy_sha256, "receipt.policy_sha256"),
        "decision_sha256": _required_digest(decision_sha256, "receipt.decision_sha256"),
        "previous_receipt_sha256": _required_digest(
            previous_receipt_sha256,
            "receipt.previous_receipt_sha256",
        ),
        "receipt_sha256": "",
    }
    core["receipt_sha256"] = domain_hash(
        DOMAINS["receipt"],
        without_self_hash(core, "receipt_sha256"),
    )
    return core


def normalize_receipt(value: Any) -> dict[str, Any]:
    receipt = _mapping(value, "receipt")
    _keys(
        receipt,
        required=(
            "schema",
            "index",
            "capture_sha256",
            "action_sha256",
            "policy_sha256",
            "decision_sha256",
            "previous_receipt_sha256",
            "receipt_sha256",
        ),
        label="receipt",
    )
    if receipt["schema"] != "heresy-sec.receipt/v1":
        raise HeresySecError("SCHEMA_UNSUPPORTED", "receipt schema must be heresy-sec.receipt/v1")
    rebuilt = build_receipt(
        index=receipt["index"],
        capture_sha256=receipt["capture_sha256"],
        action_sha256=receipt["action_sha256"],
        policy_sha256=receipt["policy_sha256"],
        decision_sha256=receipt["decision_sha256"],
        previous_receipt_sha256=receipt["previous_receipt_sha256"],
    )
    if receipt["receipt_sha256"] != rebuilt["receipt_sha256"]:
        raise HeresySecError("RECEIPT_HASH_MISMATCH", "receipt self-hash is invalid")
    return rebuilt
