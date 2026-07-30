"""Spectral, holonomy and registry companion sensors for profile v2."""

from __future__ import annotations

from typing import Any, Iterable

from . import geometry as _geometry
from .canonical import domain_hash
from .geometry_profile_v2_policy import (
    PROFILE_V2,
    _V2_DOMAINS,
    _role_graph,
    _self_hashed,
    build_forman_curvature_v2,
)


_ORIGINAL_BUILD_SPECTRAL = _geometry.build_spectral
_ORIGINAL_BUILD_HOLONOMY = _geometry.build_holonomy
_ORIGINAL_BUILD_REGISTRY = _geometry.build_registry
_REGISTRY_BUNDLE_DOMAIN = "HERESY-GEOM/IMPOSSIBLE-CONFIGURATIONS-BUNDLE/v2"


def _role_spectral(
    graph: dict[str, Any],
    geometry: dict[str, Any],
    previous_spectrum: list[int],
    *,
    role: str,
) -> dict[str, Any]:
    spectral = _ORIGINAL_BUILD_SPECTRAL(graph, geometry, previous_spectrum)
    core = {
        key: value
        for key, value in spectral.items()
        if key not in {"schema", "spectral_sha256"}
    }
    core.update(
        {
            "schema": "heresy-geom.spectral/v2",
            "profile": PROFILE_V2,
            "window_role": role,
        }
    )
    return _self_hashed(_V2_DOMAINS["spectral"], core, "spectral_sha256")


def _role_holonomy(
    graph: dict[str, Any],
    geometry: dict[str, Any],
    *,
    role: str,
) -> dict[str, Any]:
    holonomy = _ORIGINAL_BUILD_HOLONOMY(graph, geometry)
    core = {
        key: value
        for key, value in holonomy.items()
        if key not in {"schema", "holonomy_sha256"}
    }
    core.update(
        {
            "schema": "heresy-geom.holonomy/v2",
            "profile": PROFILE_V2,
            "window_role": role,
        }
    )
    return _self_hashed(_V2_DOMAINS["holonomy"], core, "holonomy_sha256")


def _v2_obstruction(
    *,
    role: str,
    obstruction_type: str,
    residual: int,
    resolve_mode: str,
    edge_sha256s: Iterable[str],
    source_obstruction_sha256: str | None = None,
    threshold_kind: str | None = None,
) -> dict[str, Any]:
    core: dict[str, Any] = {
        "window_role": role,
        "obstruction_type": obstruction_type,
        "residual": residual,
        "resolve_mode": resolve_mode,
        "edge_sha256s": sorted(set(edge_sha256s)),
    }
    if source_obstruction_sha256 is not None:
        core["source_obstruction_sha256"] = source_obstruction_sha256
    if threshold_kind is not None:
        core["threshold_kind"] = threshold_kind
    return {
        **core,
        "obstruction_sha256": domain_hash(_V2_DOMAINS["obstruction"], core),
    }


def _role_registry(
    *,
    role: str,
    actions: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    graph: dict[str, Any],
    curvature: dict[str, Any],
    spectral: dict[str, Any],
    holonomy: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    inherited = _ORIGINAL_BUILD_REGISTRY(
        actions,
        decisions,
        graph,
        curvature,
        spectral,
        holonomy,
        policy,
    )
    rows = []
    for item in inherited["obstructions"]:
        if item["obstruction_type"] in {"FORMAN_THRESHOLD_TRIP", "SPECTRAL_DELTA_TRIP"}:
            continue
        rows.append(
            _v2_obstruction(
                role=role,
                obstruction_type=item["obstruction_type"],
                residual=item["residual"],
                resolve_mode=item["resolve_mode"],
                edge_sha256s=item["edge_sha256s"],
                source_obstruction_sha256=item["obstruction_sha256"],
            )
        )

    if not curvature["ok"]:
        max_observed = max(
            (abs(item["forman"]) for item in curvature["entries"]),
            default=0,
        )
        abs_excess = max(0, max_observed - curvature["max_forman_abs"])
        l1_excess = max(
            0,
            curvature["window_l1"] - curvature["max_forman_window_l1"],
        )
        kinds = []
        if curvature["abs_threshold_trips"]:
            kinds.append("edge_abs")
        if curvature["window_l1_trip"]:
            kinds.append("window_l1")
        rows.append(
            _v2_obstruction(
                role=role,
                obstruction_type="FORMAN_THRESHOLD_TRIP",
                residual=max(abs_excess, l1_excess, 1),
                resolve_mode="DISCHARGE",
                edge_sha256s=curvature["threshold_trips"],
                threshold_kind="+".join(kinds),
            )
        )
    if not spectral["ok"]:
        rows.append(
            _v2_obstruction(
                role=role,
                obstruction_type="SPECTRAL_DELTA_TRIP",
                residual=spectral["spectral_l2_delta"],
                resolve_mode="DISCHARGE",
                edge_sha256s=_geometry.graph_edge_ids(graph),
                threshold_kind="spectral_l2_delta",
            )
        )

    rows.sort(
        key=lambda item: (
            _geometry.RESOLVE_ORDER[item["resolve_mode"]],
            item["obstruction_type"],
            item["obstruction_sha256"],
        )
    )
    if any(item["resolve_mode"] == "DISCHARGE" for item in rows):
        effect = "DENY"
    elif rows:
        effect = "REVIEW"
    else:
        effect = "ALLOW"
    core = {
        "schema": "heresy-geom.impossible-configurations/v2",
        "profile": PROFILE_V2,
        "window_role": role,
        "graph_sha256": graph["graph_sha256"],
        "obstructions": rows,
        "obstruction_count": len(rows),
        "effect": effect,
    }
    return _self_hashed(_V2_DOMAINS["registry"], core, "registry_sha256")


def _sensor_window(
    *,
    role: str,
    window_index: int,
    raw_actions: list[bytes],
    actions: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    policy: dict[str, Any],
    previous_spectrum: list[int],
) -> dict[str, Any]:
    graph = _role_graph(actions, window_index=window_index, role=role)
    curvature = build_forman_curvature_v2(graph, policy["geometry"], role=role)
    spectral = _role_spectral(
        graph,
        policy["geometry"],
        previous_spectrum,
        role=role,
    )
    holonomy = _role_holonomy(graph, policy["geometry"], role=role)
    registry = _role_registry(
        role=role,
        actions=actions,
        decisions=decisions,
        graph=graph,
        curvature=curvature,
        spectral=spectral,
        holonomy=holonomy,
        policy=policy,
    )
    return {
        "raw_actions": raw_actions,
        "actions": actions,
        "decisions": decisions,
        "graph": graph,
        "curvature": curvature,
        "spectral": spectral,
        "holonomy": holonomy,
        "registry": registry,
    }


def _aggregate_registry(
    *,
    window_index: int,
    short: dict[str, Any],
    long: dict[str, Any],
) -> dict[str, Any]:
    rows = [
        item
        for sensor in (short, long)
        for item in sensor["registry"]["obstructions"]
    ]
    rows.sort(
        key=lambda item: (
            _geometry.RESOLVE_ORDER[item["resolve_mode"]],
            item["window_role"],
            item["obstruction_type"],
            item["obstruction_sha256"],
        )
    )
    if any(item["resolve_mode"] == "DISCHARGE" for item in rows):
        effect = "DENY"
    elif rows:
        effect = "REVIEW"
    else:
        effect = "ALLOW"
    core = {
        "schema": "heresy-geom.impossible-configurations-bundle/v2",
        "profile": PROFILE_V2,
        "window_index": window_index,
        "short_registry_sha256": short["registry"]["registry_sha256"],
        "long_registry_sha256": long["registry"]["registry_sha256"],
        "obstructions": rows,
        "obstruction_count": len(rows),
        "effect": effect,
    }
    return _self_hashed(_REGISTRY_BUNDLE_DOMAIN, core, "registry_sha256")
