"""Companion atoms, geometry manifest and bundle hashing for profile v2."""

from __future__ import annotations

from typing import Any

from .canonical import DOMAINS, domain_hash, sha256_bytes
from .geometry_profile_v2_policy import (
    FIXTURE_SET_V2,
    PROFILE_V2,
    _V2_DOMAINS,
    _self_hashed,
)


def _evidence_atom(
    *,
    cell: str,
    kind: str,
    ordinal: int,
    reference_sha256: str,
) -> dict[str, Any]:
    core = {
        "cell": cell,
        "kind": kind,
        "ordinal": ordinal,
        "reference_sha256": reference_sha256,
    }
    return {
        **core,
        "atom_id": domain_hash(_V2_DOMAINS["evidence_atom"], core),
    }


def _evidence_manifest(
    *,
    window_index: int,
    raw_actions: list[bytes],
    actions: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    policy_sha256: str,
    short: dict[str, Any],
    long: dict[str, Any],
    registry: dict[str, Any],
) -> dict[str, Any]:
    atoms = [
        _evidence_atom(
            cell="policy",
            kind="POLICY",
            ordinal=0,
            reference_sha256=policy_sha256,
        ),
        _evidence_atom(
            cell="short",
            kind="SHORT_ACTION_GRAPH",
            ordinal=0,
            reference_sha256=short["graph"]["graph_sha256"],
        ),
        _evidence_atom(
            cell="short",
            kind="SHORT_FORMAN",
            ordinal=1,
            reference_sha256=short["curvature"]["curvature_sha256"],
        ),
        _evidence_atom(
            cell="short",
            kind="SHORT_SPECTRAL",
            ordinal=2,
            reference_sha256=short["spectral"]["spectral_sha256"],
        ),
        _evidence_atom(
            cell="short",
            kind="SHORT_HOLONOMY",
            ordinal=3,
            reference_sha256=short["holonomy"]["holonomy_sha256"],
        ),
        _evidence_atom(
            cell="short",
            kind="SHORT_REGISTRY",
            ordinal=4,
            reference_sha256=short["registry"]["registry_sha256"],
        ),
        _evidence_atom(
            cell="long",
            kind="LONG_ACTION_GRAPH",
            ordinal=0,
            reference_sha256=long["graph"]["graph_sha256"],
        ),
        _evidence_atom(
            cell="long",
            kind="LONG_FORMAN",
            ordinal=1,
            reference_sha256=long["curvature"]["curvature_sha256"],
        ),
        _evidence_atom(
            cell="long",
            kind="LONG_SPECTRAL",
            ordinal=2,
            reference_sha256=long["spectral"]["spectral_sha256"],
        ),
        _evidence_atom(
            cell="long",
            kind="LONG_HOLONOMY",
            ordinal=3,
            reference_sha256=long["holonomy"]["holonomy_sha256"],
        ),
        _evidence_atom(
            cell="long",
            kind="LONG_REGISTRY",
            ordinal=4,
            reference_sha256=long["registry"]["registry_sha256"],
        ),
        _evidence_atom(
            cell="bundle",
            kind="IMPOSSIBLE_CONFIGURATIONS",
            ordinal=0,
            reference_sha256=registry["registry_sha256"],
        ),
    ]
    for role, sensor in (("short", short), ("long", long)):
        atoms.append(
            _evidence_atom(
                cell=role,
                kind=f"{role.upper()}_EVENT_RANGE",
                ordinal=0,
                reference_sha256=domain_hash(
                    DOMAINS["geometry_event_range"],
                    sensor["graph"]["event_range"],
                ),
            )
        )
    for action, raw in zip(actions, raw_actions):
        atoms.append(
            _evidence_atom(
                cell="capture",
                kind="CAPTURE",
                ordinal=action["sequence"],
                reference_sha256=sha256_bytes(raw),
            )
        )
    for action, decision in zip(actions, decisions):
        atoms.append(
            _evidence_atom(
                cell="decision",
                kind="CLASSICAL_DECISION",
                ordinal=action["sequence"],
                reference_sha256=decision["decision_sha256"],
            )
        )
        for rule_id in decision["matched_rule_ids"]:
            atoms.append(
                _evidence_atom(
                    cell="policy",
                    kind="CLASSICAL_RULE_MATCH",
                    ordinal=action["sequence"],
                    reference_sha256=domain_hash(
                        DOMAINS["geometry_rule_match"],
                        {
                            "action_sha256": decision["action_sha256"],
                            "rule_id": rule_id,
                        },
                    ),
                )
            )

    required_kinds = {
        "SHORT_FORMAN",
        "SHORT_SPECTRAL",
        "SHORT_HOLONOMY",
        "LONG_FORMAN",
        "LONG_SPECTRAL",
        "LONG_HOLONOMY",
    }
    present_kinds = {atom["kind"] for atom in atoms}
    missing = sorted(required_kinds - present_kinds)
    core = {
        "schema": "heresy-geom.evidence-manifest/v2",
        "profile": PROFILE_V2,
        "window_index": window_index,
        "short_event_range": short["graph"]["event_range"],
        "long_event_range": long["graph"]["event_range"],
        "required_companion_kinds": sorted(required_kinds),
        "atoms": sorted(atoms, key=lambda item: item["atom_id"]),
        "atom_count": len(atoms),
        "N_missing": len(missing),
        "missing_companion_kinds": missing,
    }
    return _self_hashed(
        _V2_DOMAINS["evidence_manifest"],
        core,
        "evidence_manifest_sha256",
    )


def _manifest_geometry(
    *,
    policy: dict[str, Any],
    window_index: int,
    endpoint: int,
    short: dict[str, Any],
    long: dict[str, Any],
) -> dict[str, Any]:
    core = {
        "schema": "heresy-geom.manifest-geometry/v2",
        "profile": PROFILE_V2,
        "fixture_set": FIXTURE_SET_V2,
        "window_index": window_index,
        "endpoint": endpoint,
        "window": policy["geometry"]["window"],
        "forman": policy["geometry"]["forman"],
        "quantize": policy["geometry"]["quantize"],
        "short_event_range": short["graph"]["event_range"],
        "long_event_range": long["graph"]["event_range"],
    }
    return _self_hashed(
        _V2_DOMAINS["manifest_geometry"],
        core,
        "manifest_geometry_sha256",
    )


def _window_bundle(
    *,
    window_index: int,
    endpoint: int,
    short: dict[str, Any],
    long: dict[str, Any],
    manifest_geometry: dict[str, Any],
) -> dict[str, Any]:
    delta_p = max(short["holonomy"]["delta_P"], long["holonomy"]["delta_P"])
    core = {
        "schema": "heresy-geom.window-bundle/v2",
        "profile": PROFILE_V2,
        "window_index": window_index,
        "endpoint": endpoint,
        "K_short": short["curvature"]["curvature_sha256"],
        "K_long": long["curvature"]["curvature_sha256"],
        "S_short": short["spectral"]["spectral_sha256"],
        "S_long": long["spectral"]["spectral_sha256"],
        "H_short": short["holonomy"]["holonomy_sha256"],
        "H_long": long["holonomy"]["holonomy_sha256"],
        "delta_P": delta_p,
        "manifest_geometry_sha256": manifest_geometry["manifest_geometry_sha256"],
    }
    return _self_hashed(_V2_DOMAINS["bundle"], core, "bundle_sha256")
