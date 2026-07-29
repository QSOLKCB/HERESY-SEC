"""Deterministic, side-effect-free policy evaluation."""

from __future__ import annotations

import re
from typing import Any

from .canonical import canonical_bytes
from .contracts import (
    action_identity,
    build_decision,
    normalize_action,
    normalize_policy,
    policy_identity,
)


URL_RE = re.compile(
    r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<authority>[^/?#]+)(?:[/?#].*)?$"
)
EFFECT_ORDER = {"DENY": 0, "REVIEW": 1, "ALLOW": 2}


def _network_endpoint(target: str) -> tuple[str | None, str | None]:
    match = URL_RE.fullmatch(target)
    if match is None:
        return None, None
    scheme = match.group("scheme").lower()
    authority = match.group("authority")
    if "@" in authority:
        return None, None
    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0:
            return None, None
        host = authority[1:closing].lower()
        suffix = authority[closing + 1 :]
        if suffix and (not suffix.startswith(":") or not suffix[1:].isdigit()):
            return None, None
    else:
        if authority.count(":") > 1:
            return None, None
        host, separator, port = authority.partition(":")
        if separator and (not port.isdigit() or not 1 <= int(port) <= 65535):
            return None, None
        host = host.lower()
    if not host or "\x00" in host:
        return None, None
    return scheme, host


def _safe_file_target(target: str) -> bool:
    if not target or target.startswith("/") or "\\" in target or "\x00" in target:
        return False
    parts = target.split("/")
    return all(part not in {"", ".", ".."} for part in parts)


def _prefix_match(target: str, prefix: str) -> bool:
    if prefix == "*":
        return True
    if prefix.endswith("/"):
        return target.startswith(prefix)
    clean = prefix.rstrip("/")
    return target == clean or target.startswith(clean + "/")


def _rule_matches(rule: dict[str, Any], action: dict[str, Any]) -> bool:
    producer = action["producer"]
    return (
        ("*" in rule["services"] or action["service"] in rule["services"])
        and ("*" in rule["operations"] or action["operation"] in rule["operations"])
        and any(_prefix_match(action["target"], prefix) for prefix in rule["target_prefixes"])
        and ("*" in rule["agent_ids"] or producer["agent_id"] in rule["agent_ids"])
        and (
            "*" in rule["authorities"]
            or action["requested_authority"] in rule["authorities"]
        )
    )


def _boundary_reasons(action: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    boundaries = policy["boundaries"]
    reasons: list[str] = []

    if action["requested_authority"] not in boundaries["allowed_authorities"]:
        reasons.append("AUTHORITY_NOT_GRANTED")
    if len(canonical_bytes(action["parameters"])) > boundaries["max_parameter_bytes"]:
        reasons.append("PARAMETERS_TOO_LARGE")

    service = action["service"]
    target = action["target"]
    if service == "network":
        if not boundaries["network_enabled"]:
            reasons.append("NETWORK_DISABLED")
        scheme, host = _network_endpoint(target)
        if scheme is None or host is None:
            reasons.append("NETWORK_TARGET_INVALID")
        else:
            if scheme not in boundaries["allowed_network_schemes"]:
                reasons.append("NETWORK_SCHEME_NOT_ALLOWED")
            if host not in boundaries["allowed_network_hosts"]:
                reasons.append("NETWORK_HOST_NOT_ALLOWED")
    elif service == "process":
        if not boundaries["process_enabled"]:
            reasons.append("PROCESS_DISABLED")
        if target not in boundaries["allowed_processes"]:
            reasons.append("PROCESS_NOT_ALLOWED")
    elif service == "file":
        if not _safe_file_target(target):
            reasons.append("FILE_TARGET_INVALID")
        elif not any(
            _prefix_match(target, prefix)
            for prefix in boundaries["file_target_prefixes"]
        ):
            reasons.append("FILE_TARGET_OUTSIDE_PREFIX")
    elif service == "ipc":
        slot = action["slot"]
        if slot is None or not 0 <= slot < boundaries["max_ipc_slots"]:
            reasons.append("IPC_SLOT_INVALID")

    return sorted(set(reasons))


def evaluate_action(action_value: Any, policy_value: Any) -> dict[str, Any]:
    """Return a deterministic decision without executing the proposed action."""

    action = normalize_action(action_value)
    policy = normalize_policy(policy_value)
    action_sha256 = action_identity(action)
    policy_sha256 = policy_identity(policy)

    matching = [rule for rule in policy["rules"] if _rule_matches(rule, action)]
    matching.sort(
        key=lambda rule: (
            -rule["priority"],
            EFFECT_ORDER[rule["effect"]],
            rule["rule_id"],
        )
    )
    matched_ids = [rule["rule_id"] for rule in matching]
    boundary_reasons = _boundary_reasons(action, policy)

    if boundary_reasons:
        effect = "DENY"
        selected = None
        reasons = boundary_reasons
    elif matching:
        selected_rule = matching[0]
        selected = selected_rule["rule_id"]
        effect = selected_rule["effect"]
        reasons = [f"RULE_{effect}"]
    else:
        selected = None
        effect = policy["default_effect"]
        reasons = [f"DEFAULT_{effect}"]

    return build_decision(
        action_sha256=action_sha256,
        policy_sha256=policy_sha256,
        effect=effect,
        reason_codes=reasons,
        matched_rule_ids=matched_ids,
        selected_rule_id=selected,
    )
