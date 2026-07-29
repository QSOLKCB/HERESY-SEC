"""Deterministic run construction, verification and exact replay."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .artifacts import README_ORIGIN, build_manifest, safe_run_directory, verify_manifest, write_artifacts
from .canonical import DOMAINS, canonical_bytes, domain_hash, parse_json_bytes, sha256_bytes
from .contracts import (
    action_identity,
    build_receipt,
    normalize_action,
    normalize_decision,
    normalize_policy,
    normalize_receipt,
    policy_identity,
)
from .errors import HeresySecError
from .implementation import build_implementation_identity, normalize_implementation
from .policy import evaluate_action


ZERO_HASH = "0" * 64


def _read_bytes(path: Path, label: str) -> bytes:
    try:
        if not path.is_file() or path.is_symlink():
            raise OSError
        return path.read_bytes()
    except OSError as exc:
        raise HeresySecError("INPUT_READ_FAILED", f"cannot read {label}: {path}") from exc


def load_action(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = _read_bytes(path, "action")
    return raw, normalize_action(parse_json_bytes(raw))


def load_policy(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = _read_bytes(path, "policy")
    return raw, normalize_policy(parse_json_bytes(raw))


def load_jsonl_actions(path: Path) -> list[bytes]:
    body = _read_bytes(path, "JSONL action stream")
    lines = body.splitlines(keepends=True)
    if not lines:
        raise HeresySecError("ACTION_STREAM_EMPTY", "JSONL action stream is empty")
    output: list[bytes] = []
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            raise HeresySecError(
                "ACTION_STREAM_BLANK_LINE",
                f"JSONL action stream has a blank line at {index}",
            )
        normalize_action(parse_json_bytes(line))
        output.append(line)
    return output


def _normalize_actions(raw_actions: list[bytes]) -> list[dict[str, Any]]:
    if not raw_actions:
        raise HeresySecError("ACTION_STREAM_EMPTY", "at least one action is required")
    actions = [normalize_action(parse_json_bytes(raw)) for raw in raw_actions]
    action_ids = [action["action_id"] for action in actions]
    sequences = [action["sequence"] for action in actions]
    if len(set(action_ids)) != len(action_ids):
        raise HeresySecError("ACTION_ID_DUPLICATE", "action_id values must be unique within one run")
    if len(set(sequences)) != len(sequences):
        raise HeresySecError("ACTION_SEQUENCE_DUPLICATE", "action sequence values must be unique")
    if sequences != sorted(sequences):
        raise HeresySecError("ACTION_SEQUENCE_ORDER", "actions must be supplied in ascending sequence order")
    return actions


def _run_id(
    *,
    raw_policy: bytes,
    policy: dict[str, Any],
    raw_actions: list[bytes],
    actions: list[dict[str, Any]],
    implementation: dict[str, Any],
) -> str:
    return domain_hash(
        DOMAINS["run"],
        {
            "schema": "heresy-sec.run/v1",
            "policy_sha256": policy_identity(policy),
            "policy_capture_sha256": sha256_bytes(raw_policy),
            "action_sha256s": [action_identity(action) for action in actions],
            "capture_sha256s": [sha256_bytes(raw) for raw in raw_actions],
            "implementation_sha256": implementation["source_bundle_sha256"],
        },
    )


def _build_records(
    raw_actions: list[bytes],
    actions: list[dict[str, Any]],
    policy: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    policy_sha256 = policy_identity(policy)
    decisions: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    previous = ZERO_HASH
    for index, (raw, action) in enumerate(zip(raw_actions, actions)):
        decision = evaluate_action(action, policy)
        receipt = build_receipt(
            index=index,
            capture_sha256=sha256_bytes(raw),
            action_sha256=action_identity(action),
            policy_sha256=policy_sha256,
            decision_sha256=decision["decision_sha256"],
            previous_receipt_sha256=previous,
        )
        decisions.append(decision)
        receipts.append(receipt)
        previous = receipt["receipt_sha256"]
    return decisions, receipts


def _summary(
    *,
    run_id: str,
    raw_policy: bytes,
    policy: dict[str, Any],
    decisions: list[dict[str, Any]],
    receipts: list[dict[str, Any]],
    implementation: dict[str, Any],
) -> dict[str, Any]:
    counts = {
        effect: sum(1 for decision in decisions if decision["effect"] == effect)
        for effect in ("ALLOW", "DENY", "REVIEW")
    }
    if counts["DENY"]:
        final_state = "DENIED"
    elif counts["REVIEW"]:
        final_state = "REVIEW_REQUIRED"
    else:
        final_state = "ALLOWED"
    return {
        "schema": "heresy-sec.summary/v1",
        "run_id": run_id,
        "final_state": final_state,
        "action_count": len(decisions),
        "effect_counts": counts,
        "policy_sha256": policy_identity(policy),
        "policy_capture_sha256": sha256_bytes(raw_policy),
        "implementation_sha256": implementation["source_bundle_sha256"],
        "head_receipt_sha256": receipts[-1]["receipt_sha256"],
        "actions_executed": False,
    }


def _artifact_map(
    *,
    raw_policy: bytes,
    policy: dict[str, Any],
    raw_actions: list[bytes],
    actions: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    receipts: list[dict[str, Any]],
    implementation: dict[str, Any],
    summary: dict[str, Any],
) -> dict[str, bytes]:
    files: dict[str, bytes] = {
        "README_ORIGIN.txt": README_ORIGIN,
        "policy.raw": raw_policy,
        "policy.json": canonical_bytes(policy),
        "implementation.json": canonical_bytes(implementation),
        "summary.json": canonical_bytes(summary),
        "event-log.jsonl": b"".join(canonical_bytes(item) + b"\n" for item in receipts),
    }
    for index, (raw, action, decision, receipt) in enumerate(
        zip(raw_actions, actions, decisions, receipts)
    ):
        stem = f"{index:06d}"
        files[f"captures/{stem}.raw"] = raw
        files[f"actions/{stem}.json"] = canonical_bytes(action)
        files[f"decisions/{stem}.json"] = canonical_bytes(decision)
        files[f"receipts/{stem}.json"] = canonical_bytes(receipt)
    return dict(sorted(files.items()))


def run_actions(
    raw_actions: list[bytes],
    raw_policy: bytes,
    runs_dir: Path,
    *,
    run_name: str | None = None,
) -> tuple[Path, dict[str, Any]]:
    policy = normalize_policy(parse_json_bytes(raw_policy))
    actions = _normalize_actions(raw_actions)
    implementation = build_implementation_identity()
    run_id = _run_id(
        raw_policy=raw_policy,
        policy=policy,
        raw_actions=raw_actions,
        actions=actions,
        implementation=implementation,
    )
    decisions, receipts = _build_records(raw_actions, actions, policy)
    summary = _summary(
        run_id=run_id,
        raw_policy=raw_policy,
        policy=policy,
        decisions=decisions,
        receipts=receipts,
        implementation=implementation,
    )
    files = _artifact_map(
        raw_policy=raw_policy,
        policy=policy,
        raw_actions=raw_actions,
        actions=actions,
        decisions=decisions,
        receipts=receipts,
        implementation=implementation,
        summary=summary,
    )
    files["manifest.json"] = build_manifest(files, run_id)
    target = safe_run_directory(runs_dir, run_name or f"run-{run_id[:16]}")
    write_artifacts(target, files)
    manifest = parse_json_bytes(files["manifest.json"])
    return target, {
        **summary,
        "run_directory": str(target),
        "manifest_sha256": manifest["manifest_sha256"],
    }


def run_action_file(
    action_path: Path,
    policy_path: Path,
    runs_dir: Path,
    *,
    run_name: str | None = None,
) -> tuple[Path, dict[str, Any]]:
    raw_action, _ = load_action(action_path)
    raw_policy, _ = load_policy(policy_path)
    return run_actions([raw_action], raw_policy, runs_dir, run_name=run_name)


def run_jsonl_file(
    jsonl_path: Path,
    policy_path: Path,
    runs_dir: Path,
    *,
    run_name: str | None = None,
) -> tuple[Path, dict[str, Any]]:
    raw_actions = load_jsonl_actions(jsonl_path)
    raw_policy, _ = load_policy(policy_path)
    return run_actions(raw_actions, raw_policy, runs_dir, run_name=run_name)


def _read_run_json(root: Path, relative: str) -> Any:
    try:
        target = (root / relative).resolve()
        if root not in target.parents or not target.is_file() or target.is_symlink():
            raise OSError
        return parse_json_bytes(target.read_bytes())
    except OSError as exc:
        raise HeresySecError("RUN_ARTIFACT_MISSING", f"run artifact is missing: {relative}") from exc


def _semantic_records(
    root: Path,
) -> tuple[
    bytes,
    dict[str, Any],
    list[bytes],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any],
    dict[str, Any],
]:
    summary = _read_run_json(root, "summary.json")
    if type(summary) is not dict or type(summary.get("action_count")) is not int:
        raise HeresySecError("SUMMARY_INVALID", "summary contract is invalid")
    count = summary["action_count"]
    if count < 1:
        raise HeresySecError("SUMMARY_INVALID", "summary action_count must be positive")

    raw_policy = _read_bytes(root / "policy.raw", "captured policy")
    policy = normalize_policy(_read_run_json(root, "policy.json"))
    if normalize_policy(parse_json_bytes(raw_policy)) != policy:
        raise HeresySecError("POLICY_CAPTURE_MISMATCH", "captured and normalized policy differ")
    if (root / "policy.json").read_bytes() != canonical_bytes(policy):
        raise HeresySecError("POLICY_CANONICAL_MISMATCH", "stored policy is not canonical")

    implementation = normalize_implementation(_read_run_json(root, "implementation.json"))
    if _read_bytes(root / "implementation.json", "implementation") != canonical_bytes(
        implementation
    ):
        raise HeresySecError(
            "IMPLEMENTATION_CANONICAL_MISMATCH",
            "implementation record is not canonical",
        )
    if _read_bytes(root / "README_ORIGIN.txt", "run origin") != README_ORIGIN:
        raise HeresySecError(
            "RUN_ORIGIN_MISMATCH",
            "run origin notice differs from the implementation",
        )
    raw_actions: list[bytes] = []
    actions: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    previous = ZERO_HASH
    for index in range(count):
        stem = f"{index:06d}"
        raw = _read_bytes(root / "captures" / f"{stem}.raw", f"capture {stem}")
        action = normalize_action(_read_run_json(root, f"actions/{stem}.json"))
        if normalize_action(parse_json_bytes(raw)) != action:
            raise HeresySecError("ACTION_CAPTURE_MISMATCH", f"capture differs from action {stem}")
        if (root / "actions" / f"{stem}.json").read_bytes() != canonical_bytes(action):
            raise HeresySecError("ACTION_CANONICAL_MISMATCH", f"action is not canonical: {stem}")
        decision_relative = f"decisions/{stem}.json"
        receipt_relative = f"receipts/{stem}.json"
        decision = normalize_decision(_read_run_json(root, decision_relative))
        receipt = normalize_receipt(_read_run_json(root, receipt_relative))
        if _read_bytes(root / decision_relative, f"decision {stem}") != canonical_bytes(decision):
            raise HeresySecError(
                "DECISION_CANONICAL_MISMATCH",
                f"decision is not canonical: {stem}",
            )
        if _read_bytes(root / receipt_relative, f"receipt {stem}") != canonical_bytes(receipt):
            raise HeresySecError(
                "RECEIPT_CANONICAL_MISMATCH",
                f"receipt is not canonical: {stem}",
            )
        if decision["action_sha256"] != action_identity(action):
            raise HeresySecError("DECISION_LINEAGE_MISMATCH", f"decision does not bind action {stem}")
        if decision["policy_sha256"] != policy_identity(policy):
            raise HeresySecError("DECISION_LINEAGE_MISMATCH", f"decision does not bind policy {stem}")
        if (
            receipt["index"] != index
            or receipt["capture_sha256"] != sha256_bytes(raw)
            or receipt["action_sha256"] != action_identity(action)
            or receipt["policy_sha256"] != policy_identity(policy)
            or receipt["decision_sha256"] != decision["decision_sha256"]
            or receipt["previous_receipt_sha256"] != previous
        ):
            raise HeresySecError("RECEIPT_LINEAGE_MISMATCH", f"receipt lineage is invalid: {stem}")
        previous = receipt["receipt_sha256"]
        raw_actions.append(raw)
        actions.append(action)
        decisions.append(decision)
        receipts.append(receipt)

    _normalize_actions(raw_actions)
    expected_log = b"".join(canonical_bytes(item) + b"\n" for item in receipts)
    if _read_bytes(root / "event-log.jsonl", "event log") != expected_log:
        raise HeresySecError("EVENT_LOG_MISMATCH", "event log differs from receipt chain")
    return (
        raw_policy,
        policy,
        raw_actions,
        actions,
        decisions,
        receipts,
        implementation,
        summary,
    )


def verify_run_directory(run_dir: Path) -> dict[str, Any]:
    root = run_dir.resolve()
    manifest_report = verify_manifest(root)
    (
        raw_policy,
        policy,
        raw_actions,
        actions,
        decisions,
        receipts,
        implementation,
        summary,
    ) = _semantic_records(root)
    run_id = _run_id(
        raw_policy=raw_policy,
        policy=policy,
        raw_actions=raw_actions,
        actions=actions,
        implementation=implementation,
    )
    expected_summary = _summary(
        run_id=run_id,
        raw_policy=raw_policy,
        policy=policy,
        decisions=decisions,
        receipts=receipts,
        implementation=implementation,
    )
    if summary != expected_summary or (root / "summary.json").read_bytes() != canonical_bytes(expected_summary):
        raise HeresySecError("SUMMARY_MISMATCH", "summary does not match run artifacts")
    if manifest_report["run_id"] != run_id:
        raise HeresySecError("MANIFEST_RUN_MISMATCH", "manifest does not bind the computed run")
    return {
        **manifest_report,
        "final_state": summary["final_state"],
        "action_count": summary["action_count"],
        "head_receipt_sha256": summary["head_receipt_sha256"],
    }


def replay_run(run_dir: Path) -> dict[str, Any]:
    root = run_dir.resolve()
    verify_run_directory(root)
    (
        raw_policy,
        policy,
        raw_actions,
        actions,
        stored_decisions,
        stored_receipts,
        stored_implementation,
        stored_summary,
    ) = _semantic_records(root)
    current_implementation = build_implementation_identity()
    if (
        current_implementation["source_bundle_sha256"]
        != stored_implementation["source_bundle_sha256"]
    ):
        raise HeresySecError(
            "REPLAY_IMPLEMENTATION_MISMATCH",
            "exact replay requires the source bundle that created the run",
        )
    replayed_decisions, replayed_receipts = _build_records(raw_actions, actions, policy)
    run_id = _run_id(
        raw_policy=raw_policy,
        policy=policy,
        raw_actions=raw_actions,
        actions=actions,
        implementation=current_implementation,
    )
    replayed_summary = _summary(
        run_id=run_id,
        raw_policy=raw_policy,
        policy=policy,
        decisions=replayed_decisions,
        receipts=replayed_receipts,
        implementation=current_implementation,
    )
    if (
        [canonical_bytes(item) for item in replayed_decisions]
        != [canonical_bytes(item) for item in stored_decisions]
        or [canonical_bytes(item) for item in replayed_receipts]
        != [canonical_bytes(item) for item in stored_receipts]
        or canonical_bytes(replayed_summary) != canonical_bytes(stored_summary)
    ):
        raise HeresySecError("REPLAY_DIVERGENCE", "deterministic replay diverged from stored artifacts")
    return {
        "status": "PASS",
        "run_id": run_id,
        "action_count": len(actions),
        "final_state": stored_summary["final_state"],
        "implementation_sha256": current_implementation["source_bundle_sha256"],
    }


def inspect_run(run_dir: Path) -> dict[str, Any]:
    root = run_dir.resolve()
    verify_run_directory(root)
    summary = _read_run_json(root, "summary.json")
    decisions = []
    for index in range(summary["action_count"]):
        stem = f"{index:06d}"
        action = _read_run_json(root, f"actions/{stem}.json")
        decision = _read_run_json(root, f"decisions/{stem}.json")
        decisions.append(
            {
                "index": index,
                "action_id": action["action_id"],
                "service": action["service"],
                "operation": action["operation"],
                "target": action["target"],
                "effect": decision["effect"],
                "reason_codes": decision["reason_codes"],
                "decision_sha256": decision["decision_sha256"],
            }
        )
    return {"summary": summary, "decisions": decisions}


def validate_files(action_path: Path, policy_path: Path) -> dict[str, Any]:
    raw_action, action = load_action(action_path)
    raw_policy, policy = load_policy(policy_path)
    decision = evaluate_action(action, policy)
    return {
        "status": "PASS",
        "action_sha256": action_identity(action),
        "capture_sha256": sha256_bytes(raw_action),
        "policy_sha256": policy_identity(policy),
        "policy_capture_sha256": sha256_bytes(raw_policy),
        "prospective_effect": decision["effect"],
        "reason_codes": decision["reason_codes"],
    }


def demo_documents() -> tuple[dict[str, Any], dict[str, Any]]:
    action = {
        "schema": "heresy-sec.action/v1",
        "action_id": "demo-safe-read",
        "sequence": 0,
        "producer": {
            "schema": "heresy-sec.producer/v1",
            "agent_id": "demo-agent",
            "workload_id": None,
            "model_id": "mock/security-proposer",
            "model_kind": "OPEN_WEIGHT",
            "model_digest": None,
            "harness_id": "heresy-sec-demo/v1",
            "harness_digest": None,
        },
        "observed_at": None,
        "service": "file",
        "operation": "read",
        "target": "workspace/evidence.txt",
        "parameters": {},
        "requested_authority": "SIM_ONLY",
        "slot": None,
        "context": {"purpose": "deterministic policy demonstration"},
    }
    policy = {
        "schema": "heresy-sec.policy/v1",
        "policy_id": "demo-policy",
        "default_effect": "DENY",
        "boundaries": {
            "allowed_authorities": ["SIM_ONLY"],
            "max_parameter_bytes": 16384,
            "max_ipc_slots": 32,
            "network_enabled": False,
            "allowed_network_schemes": ["https"],
            "allowed_network_hosts": [],
            "process_enabled": False,
            "allowed_processes": [],
            "file_target_prefixes": ["workspace/"],
        },
        "rules": [
            {
                "schema": "heresy-sec.rule/v1",
                "rule_id": "allow-demo-read",
                "priority": 100,
                "effect": "ALLOW",
                "services": ["file"],
                "operations": ["read"],
                "target_prefixes": ["workspace/"],
                "agent_ids": ["demo-agent"],
                "authorities": ["SIM_ONLY"],
            }
        ],
    }
    return normalize_action(action), normalize_policy(policy)


def init_demo(directory: Path) -> dict[str, Any]:
    if directory.is_symlink():
        raise HeresySecError("INIT_DIRECTORY_NOT_EMPTY", "demo directory cannot be a symbolic link")
    target = directory.resolve()
    if target.exists():
        if target.is_symlink() or not target.is_dir() or any(target.iterdir()):
            raise HeresySecError("INIT_DIRECTORY_NOT_EMPTY", "demo directory must not exist or must be empty")
    else:
        target.mkdir(parents=True)
    action, policy = demo_documents()
    files = {
        "action.json": canonical_bytes(action) + b"\n",
        "events.jsonl": canonical_bytes(action) + b"\n",
        "policy.json": canonical_bytes(policy) + b"\n",
        "README.txt": (
            b"Run: python -m heresy_sec run action.json --policy policy.json --runs-dir runs\n"
            b"Batch: python -m heresy_sec monitor events.jsonl --policy policy.json --runs-dir runs\n"
        ),
    }
    for name, body in files.items():
        with (target / name).open("xb") as handle:
            handle.write(body)
    return {"status": "PASS", "directory": str(target), "files": sorted(files)}
