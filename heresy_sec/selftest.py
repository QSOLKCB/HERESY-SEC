"""Small installed-artifact self-test independent of the repository test suite."""

from __future__ import annotations

import tempfile
from pathlib import Path

from .canonical import canonical_bytes, parse_json_bytes
from .engine import demo_documents, replay_run, run_actions, verify_run_directory
from .errors import HeresySecError
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

    return {"status": "PASS", "checks": checks, "check_count": len(checks)}

