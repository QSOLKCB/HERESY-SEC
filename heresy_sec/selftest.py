"""Small installed-artifact self-test independent of the repository test suite."""

from __future__ import annotations

import copy
import tempfile
from pathlib import Path

from .canonical import canonical_bytes, parse_json_bytes
from .engine import demo_documents, replay_run, run_actions, verify_run_directory
from .errors import HeresySecError
from .geometry import default_geometry_policy
from .policy import evaluate_action


def run_selftest() -> dict[str, object]:
    checks: list[str] = []

    try:
        parse_json_bytes(b'{"x":1.5}')
    except HeresySecError as exc:
        if exc.code != "JSON_FLOAT_FORBIDDEN":
            raise
        checks.append("float-rejection")
    else:
        raise HeresySecError("SELFTEST_FAILED", "canonical parser accepted a float")

    action, policy = demo_documents()
    first = evaluate_action(action, policy)
    second = evaluate_action(action, policy)
    if canonical_bytes(first) != canonical_bytes(second) or first["effect"] != "ALLOW":
        raise HeresySecError("SELFTEST_FAILED", "deterministic allow decision failed")
    checks.append("deterministic-decision")

    denied = dict(action)
    denied["action_id"] = "demo-network-denial"
    denied["service"] = "network"
    denied["operation"] = "connect"
    denied["target"] = "https://forbidden.example/upload"
    denied["requested_authority"] = "NETWORK"
    decision = evaluate_action(denied, policy)
    if decision["effect"] != "DENY" or "NETWORK_DISABLED" not in decision["reason_codes"]:
        raise HeresySecError("SELFTEST_FAILED", "network boundary did not fail closed")
    checks.append("network-denial")

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        run_dir, _ = run_actions(
            [canonical_bytes(action) + b"\n"],
            canonical_bytes(policy) + b"\n",
            root,
            run_name="selftest",
        )
        verify_run_directory(run_dir)
        replay_run(run_dir)
        checks.extend(("manifest-verification", "exact-replay"))

        geometry_policy = copy.deepcopy(policy)
        geometry_policy["schema"] = "heresy-sec.policy/v2"
        geometry_policy["geometry"] = default_geometry_policy()
        geometry_policy["boundaries"]["allowed_authorities"] = [
            "READ_ONLY_EXTERNAL",
            "WORKSPACE_WRITE",
        ]
        geometry_policy["rules"] = [
            {
                "schema": "heresy-sec.rule/v1",
                "rule_id": "allow-geometry-file-actions",
                "priority": 100,
                "effect": "ALLOW",
                "services": ["file"],
                "operations": ["read", "write"],
                "target_prefixes": ["workspace/"],
                "agent_ids": ["demo-agent"],
                "authorities": ["*"],
            }
        ]
        external_read = copy.deepcopy(action)
        external_read.update(
            {
                "action_id": "geometry-external-read",
                "requested_authority": "READ_ONLY_EXTERNAL",
            }
        )
        workspace_write = copy.deepcopy(action)
        workspace_write.update(
            {
                "action_id": "geometry-workspace-write",
                "sequence": 1,
                "operation": "write",
                "requested_authority": "WORKSPACE_WRITE",
            }
        )
        geometry_run, geometry_report = run_actions(
            [
                canonical_bytes(external_read) + b"\n",
                canonical_bytes(workspace_write) + b"\n",
            ],
            canonical_bytes(geometry_policy) + b"\n",
            root,
            run_name="selftest-geometry",
        )
        if (
            geometry_report["final_state"] != "DENIED"
            or geometry_report["geometry_window_count"] != 1
        ):
            raise HeresySecError(
                "SELFTEST_FAILED",
                "geometry holonomy did not fail closed",
            )
        verify_run_directory(geometry_run)
        replay_run(geometry_run)
        checks.extend(("geometry-holonomy-denial", "geometry-exact-replay"))

    return {"status": "PASS", "checks": checks, "check_count": len(checks)}
