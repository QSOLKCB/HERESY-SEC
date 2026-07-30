"""Dual-window scheduling, decisions, artifacts and engine dispatch for profile v2."""

from __future__ import annotations

from typing import Any

from . import geometry as _geometry
from .canonical import DOMAINS, canonical_bytes, domain_hash
from .geometry_profile_v2_evidence import (
    _evidence_manifest,
    _manifest_geometry,
    _window_bundle,
)
from .geometry_profile_v2_policy import (
    MODULE_VERSION_V2,
    PROFILE_V1,
    PROFILE_V2,
    _V2_DOMAINS,
    _profile,
    _self_hashed,
)
from .geometry_profile_v2_sensors import _aggregate_registry, _sensor_window


_ORIGINAL_BUILD_GEOMETRY_WINDOWS = _geometry.build_geometry_windows
_ORIGINAL_GEOMETRY_ARTIFACT_MAP = _geometry.geometry_artifact_map


def _classical_effect(decisions: list[dict[str, Any]]) -> str:
    return min(
        (decision["effect"] for decision in decisions),
        key=lambda effect: _geometry.EFFECT_ORDER[effect],
    )


def _build_v2_window(
    *,
    window_index: int,
    endpoint: int,
    step_start: int,
    raw_actions: list[bytes],
    actions: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    receipts: list[dict[str, Any]],
    policy: dict[str, Any],
    previous_short_spectrum: list[int],
    previous_long_spectrum: list[int],
    previous_geometry_receipt_sha256: str,
    previously_armed: bool,
) -> dict[str, Any]:
    schedule = policy["geometry"]["window"]
    short_start = max(0, endpoint - schedule["short"])
    long_start = max(0, endpoint - schedule["long"])

    short = _sensor_window(
        role="short",
        window_index=window_index,
        raw_actions=raw_actions[short_start:endpoint],
        actions=actions[short_start:endpoint],
        decisions=decisions[short_start:endpoint],
        policy=policy,
        previous_spectrum=previous_short_spectrum,
    )
    long = _sensor_window(
        role="long",
        window_index=window_index,
        raw_actions=raw_actions[long_start:endpoint],
        actions=actions[long_start:endpoint],
        decisions=decisions[long_start:endpoint],
        policy=policy,
        previous_spectrum=previous_long_spectrum,
    )
    registry = _aggregate_registry(
        window_index=window_index,
        short=short,
        long=long,
    )
    policy_sha256 = domain_hash(DOMAINS["policy_v2"], policy)
    evidence = _evidence_manifest(
        window_index=window_index,
        raw_actions=raw_actions[long_start:endpoint],
        actions=actions[long_start:endpoint],
        decisions=decisions[long_start:endpoint],
        policy_sha256=policy_sha256,
        short=short,
        long=long,
        registry=registry,
    )
    manifest_geometry = _manifest_geometry(
        policy=policy,
        window_index=window_index,
        endpoint=endpoint,
        short=short,
        long=long,
    )
    bundle = _window_bundle(
        window_index=window_index,
        endpoint=endpoint,
        short=short,
        long=long,
        manifest_geometry=manifest_geometry,
    )

    forman_ok = short["curvature"]["ok"] and long["curvature"]["ok"]
    spectral_ok = short["spectral"]["ok"] and long["spectral"]["ok"]
    holonomy_ok = (
        short["holonomy"]["delta_P"] == 0
        and long["holonomy"]["delta_P"] == 0
    )
    companion_ok = evidence["N_missing"] == 0
    geom_ok = (
        forman_ok
        and spectral_ok
        and holonomy_ok
        and companion_ok
        and registry["effect"] == "ALLOW"
    )
    commitment_core = {
        "schema": "heresy-geom.commitment/v2",
        "profile": PROFILE_V2,
        "window_index": window_index,
        "short_event_range": short["graph"]["event_range"],
        "long_event_range": long["graph"]["event_range"],
        "bundle_sha256": bundle["bundle_sha256"],
        "registry_sha256": registry["registry_sha256"],
        "evidence_manifest_sha256": evidence["evidence_manifest_sha256"],
        "delta_P": bundle["delta_P"],
        "forman_ok": forman_ok,
        "spectral_ok": spectral_ok,
        "holonomy_ok": holonomy_ok,
        "companion_ok": companion_ok,
        "geom_ok": geom_ok,
        "geometry_effect": registry["effect"],
    }
    commitment = _self_hashed(
        _V2_DOMAINS["commitment"],
        commitment_core,
        "geometry_sha256",
    )

    long_decisions = decisions[long_start:endpoint]
    classical_effect = _classical_effect(long_decisions)
    geometry_effect = registry["effect"]
    preliminary_effect = min(
        (classical_effect, geometry_effect),
        key=lambda effect: _geometry.EFFECT_ORDER[effect],
    )
    trip = preliminary_effect == "DENY" or geometry_effect == "REVIEW" or not geom_ok
    rearm_present = (
        step_start < endpoint
        and _geometry._is_rearm_action(actions[step_start], decisions[step_start])
    )
    armed = _geometry.shadow_guard_transition(
        armed=previously_armed,
        trip=trip,
        rearm_receipt_present=rearm_present,
        revalidation_ok=classical_effect == "ALLOW" and geom_ok,
    )
    final_effect = preliminary_effect
    if not armed and final_effect == "ALLOW":
        final_effect = "DENY"

    reason_codes = []
    if classical_effect != "ALLOW":
        reason_codes.append(f"CLASSICAL_{classical_effect}")
    reason_codes.extend(item["obstruction_type"] for item in registry["obstructions"])
    if not companion_ok:
        reason_codes.append("GEOMETRY_COMPANION_MISSING")
    if not armed:
        reason_codes.append("SHADOW_GUARD_DISARMED")
    if not reason_codes:
        reason_codes.append("GEOMETRY_ALLOW")

    load_bearing_allow = (
        classical_effect == "ALLOW"
        and geom_ok
        and bundle["delta_P"] == 0
        and armed
        and evidence["N_missing"] == 0
        and final_effect == "ALLOW"
    )
    decision_core = {
        "schema": "heresy-geom.decision/v2",
        "profile": PROFILE_V2,
        "window_index": window_index,
        "policy_sha256": policy_sha256,
        "geometry_sha256": commitment["geometry_sha256"],
        "bundle_sha256": bundle["bundle_sha256"],
        "evidence_manifest_sha256": evidence["evidence_manifest_sha256"],
        "classical_effect": classical_effect,
        "geometry_effect": geometry_effect,
        "geom_ok": geom_ok,
        "forman_ok": forman_ok,
        "spectral_ok": spectral_ok,
        "holonomy_ok": holonomy_ok,
        "effect": final_effect,
        "reason_codes": sorted(set(reason_codes)),
        "shadow_guard_armed": armed,
        "load_bearing_allow": load_bearing_allow,
        "N_missing": evidence["N_missing"],
    }
    geometry_decision = _self_hashed(
        _V2_DOMAINS["decision"],
        decision_core,
        "geometry_decision_sha256",
    )
    receipt_core = {
        "schema": "heresy-geom.receipt/v2",
        "profile": PROFILE_V2,
        "window_index": window_index,
        "short_event_range": short["graph"]["event_range"],
        "long_event_range": long["graph"]["event_range"],
        "bundle_sha256": bundle["bundle_sha256"],
        "geometry_sha256": commitment["geometry_sha256"],
        "geometry_decision_sha256": geometry_decision["geometry_decision_sha256"],
        "evidence_manifest_sha256": evidence["evidence_manifest_sha256"],
        "head_classical_receipt_sha256": receipts[endpoint - 1]["receipt_sha256"],
        "previous_geometry_receipt_sha256": previous_geometry_receipt_sha256,
    }
    geometry_receipt = _self_hashed(
        _V2_DOMAINS["receipt"],
        receipt_core,
        "geometry_receipt_sha256",
    )
    return {
        "profile_version": 2,
        "short": short,
        "long": long,
        "manifest_geometry": manifest_geometry,
        "bundle": bundle,
        "registry": registry,
        "evidence": evidence,
        "commitment": commitment,
        "decision": geometry_decision,
        "receipt": geometry_receipt,
    }


def build_geometry_windows(
    *,
    raw_actions: list[bytes],
    actions: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    receipts: list[dict[str, Any]],
    policy: dict[str, Any],
    zero_hash: str,
) -> list[dict[str, Any]]:
    if policy["schema"] != "heresy-sec.policy/v2":
        return []
    if policy["geometry"]["version"] != MODULE_VERSION_V2:
        with _profile(PROFILE_V1):
            return _ORIGINAL_BUILD_GEOMETRY_WINDOWS(
                raw_actions=raw_actions,
                actions=actions,
                decisions=decisions,
                receipts=receipts,
                policy=policy,
                zero_hash=zero_hash,
            )

    stride = policy["geometry"]["window"]["stride"]
    endpoints = list(range(stride, len(actions) + 1, stride))
    if not endpoints or endpoints[-1] != len(actions):
        endpoints.append(len(actions))

    windows = []
    previous_short_spectrum: list[int] = []
    previous_long_spectrum: list[int] = []
    previous_receipt = zero_hash
    armed = True
    step_start = 0
    with _profile(PROFILE_V2):
        for window_index, endpoint in enumerate(endpoints):
            window = _build_v2_window(
                window_index=window_index,
                endpoint=endpoint,
                step_start=step_start,
                raw_actions=raw_actions,
                actions=actions,
                decisions=decisions,
                receipts=receipts,
                policy=policy,
                previous_short_spectrum=previous_short_spectrum,
                previous_long_spectrum=previous_long_spectrum,
                previous_geometry_receipt_sha256=previous_receipt,
                previously_armed=armed,
            )
            windows.append(window)
            previous_short_spectrum = window["short"]["spectral"]["quantized_eigenvalues"]
            previous_long_spectrum = window["long"]["spectral"]["quantized_eigenvalues"]
            previous_receipt = window["receipt"]["geometry_receipt_sha256"]
            armed = window["decision"]["shadow_guard_armed"]
            step_start = endpoint
    return windows


def geometry_artifact_map(windows: list[dict[str, Any]]) -> dict[str, bytes]:
    if not windows or windows[0].get("profile_version") != 2:
        return _ORIGINAL_GEOMETRY_ARTIFACT_MAP(windows)

    files: dict[str, bytes] = {}
    log = []
    top_names = (
        ("manifest-geometry.json", "manifest_geometry"),
        ("bundle.json", "bundle"),
        ("impossible-configurations.json", "registry"),
        ("evidence-manifest.json", "evidence"),
        ("commitment.json", "commitment"),
        ("decision.json", "decision"),
        ("receipt.json", "receipt"),
    )
    role_names = (
        ("action-graph.json", "graph"),
        ("curvature.json", "curvature"),
        ("spectral.json", "spectral"),
        ("holonomy.json", "holonomy"),
        ("impossible-configurations.json", "registry"),
    )
    for index, window in enumerate(windows):
        prefix = f"geometry/{index:06d}"
        for filename, key in top_names:
            files[f"{prefix}/{filename}"] = canonical_bytes(window[key])
        for role in ("short", "long"):
            for filename, key in role_names:
                files[f"{prefix}/{role}/{filename}"] = canonical_bytes(window[role][key])
        log.append(canonical_bytes(window["receipt"]) + b"\n")
    files["geometry-event-log.jsonl"] = b"".join(log)
    return dict(sorted(files.items()))


def _install_engine_dispatch(engine: Any) -> None:
    if not getattr(engine._summary, "_heresy_geom_v2_dispatch", False):
        original_summary = engine._summary

        def summary_dispatch(**kwargs: Any) -> dict[str, Any]:
            output = original_summary(**kwargs)
            policy = kwargs["policy"]
            if (
                policy["schema"] == "heresy-sec.policy/v2"
                and policy["geometry"]["version"] == MODULE_VERSION_V2
            ):
                output["geometry_profile"] = PROFILE_V2
            return output

        summary_dispatch._heresy_geom_v2_dispatch = True
        engine._summary = summary_dispatch

    if not getattr(engine.validate_files, "_heresy_geom_v2_dispatch", False):
        original_validate = engine.validate_files

        def validate_dispatch(action_path: Any, policy_path: Any) -> dict[str, Any]:
            output = original_validate(action_path, policy_path)
            _, policy = engine.load_policy(policy_path)
            if (
                policy["schema"] == "heresy-sec.policy/v2"
                and policy["geometry"]["version"] == MODULE_VERSION_V2
            ):
                output["geometry_profile"] = PROFILE_V2
            return output

        validate_dispatch._heresy_geom_v2_dispatch = True
        engine.validate_files = validate_dispatch


def install_engine_dispatch(engine: Any) -> None:
    _install_engine_dispatch(engine)
