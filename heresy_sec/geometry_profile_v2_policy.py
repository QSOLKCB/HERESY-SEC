"""Policy, curvature and profile-lock primitives for HERESY-GEOM profile v2."""

from __future__ import annotations

from contextlib import contextmanager
from threading import RLock
from typing import Any, Iterable

from . import geometry as _geometry
from .canonical import domain_hash, without_self_hash
from .errors import HeresySecError


PROFILE_V1 = "heresy-geom.profile/v1"
PROFILE_V2 = "heresy-geom.profile/v2"
MODULE = "heresy-geom"
MODULE_VERSION_V2 = "2"
FIXTURE_SET_V2 = "heresy-geom-conformance/v2"
MAX_WINDOW = 32
MAX_WEIGHT = 1_000_000
MAX_THRESHOLD = 1_000_000_000

_V2_DOMAINS = {
    "graph": "HERESY-GEOM/ACTION-GRAPH/v2",
    "curvature": "HERESY-GEOM/CURVATURE/v2",
    "spectral": "HERESY-GEOM/SPECTRAL/v2",
    "holonomy": "HERESY-GEOM/HOLONOMY/v2",
    "registry": "HERESY-GEOM/IMPOSSIBLE-CONFIGURATIONS/v2",
    "obstruction": "HERESY-GEOM/OBSTRUCTION/v2",
    "evidence_atom": "HERESY-GEOM/EVIDENCE-ATOM/v2",
    "evidence_manifest": "HERESY-GEOM/EVIDENCE-MANIFEST/v2",
    "manifest_geometry": "HERESY-GEOM/MANIFEST-GEOMETRY/v2",
    "bundle": "HERESY-GEOM/WINDOW-BUNDLE/v2",
    "commitment": "HERESY-GEOM/COMMITMENT/v2",
    "decision": "HERESY-GEOM/DECISION/v2",
    "receipt": "HERESY-GEOM/RECEIPT/v2",
}

_PROFILE_LOCK = RLock()
_ORIGINAL_NORMALIZE_GEOMETRY_POLICY = _geometry.normalize_geometry_policy
_ORIGINAL_BUILD_ACTION_GRAPH = _geometry.build_action_graph


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise HeresySecError("GEOMETRY_POLICY_INVALID", f"{label} must be an object")
    return value


def _exact_keys(
    value: dict[str, Any],
    *,
    required: Iterable[str],
    label: str,
) -> None:
    expected = set(required)
    if set(value) != expected:
        missing = sorted(expected - set(value))
        unexpected = sorted(set(value) - expected)
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected {', '.join(unexpected)}")
        raise HeresySecError(
            "GEOMETRY_POLICY_INVALID",
            f"{label} fields are invalid: {'; '.join(details)}",
        )


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise HeresySecError(
            "GEOMETRY_POLICY_INVALID",
            f"{label} must be an exact integer in {minimum}..{maximum}",
        )
    return value


def _action_label(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or not 3 <= len(value) <= 129
        or value != value.lower()
        or "." not in value
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for character in value)
    ):
        raise HeresySecError(
            "GEOMETRY_POLICY_INVALID",
            f"{label} must be a lower-case service.operation identifier",
        )
    return value


def _normalize_weight_map(value: Any, mode: str) -> dict[str, int]:
    mapping = _mapping(value, "policy.geometry.forman.weight_map")
    normalized: dict[str, int] = {}
    for raw_label, raw_weight in mapping.items():
        label = _action_label(raw_label, "geometry.forman.weight_map key")
        normalized[label] = _integer(
            raw_weight,
            f"geometry.forman.weight_map[{label}]",
            1,
            MAX_WEIGHT,
        )
    normalized = dict(sorted(normalized.items()))
    if mode == "unweighted" and normalized:
        raise HeresySecError(
            "GEOMETRY_POLICY_INVALID",
            "geometry.forman.weight_map must be empty in unweighted mode",
        )
    if mode == "weighted" and not normalized:
        raise HeresySecError(
            "GEOMETRY_POLICY_INVALID",
            "geometry.forman.weight_map must be non-empty in weighted mode",
        )
    return normalized


def normalize_geometry_policy_v2(value: Any) -> dict[str, Any]:
    """Normalize the indivisible Forman-resolution profile."""

    geometry = _mapping(value, "policy.geometry")
    _exact_keys(
        geometry,
        required=(
            "module",
            "version",
            "fixture_set",
            "window",
            "quantize",
            "forman",
            "max_spectral_l2_delta",
            "epsilon_P",
            "forbid_cycles",
            "require_delta_P",
        ),
        label="policy.geometry",
    )
    if geometry["module"] != MODULE or geometry["version"] != MODULE_VERSION_V2:
        raise HeresySecError(
            "GEOMETRY_MODULE_UNSUPPORTED",
            f"geometry module must be {MODULE} version {MODULE_VERSION_V2}",
        )
    if geometry["fixture_set"] != FIXTURE_SET_V2:
        raise HeresySecError(
            "GEOMETRY_FIXTURE_SET_UNSUPPORTED",
            f"geometry fixture_set must be {FIXTURE_SET_V2}",
        )

    window = _mapping(geometry["window"], "policy.geometry.window")
    _exact_keys(window, required=("short", "long", "stride"), label="policy.geometry.window")
    short = _integer(window["short"], "geometry.window.short", 1, MAX_WINDOW)
    long = _integer(window["long"], "geometry.window.long", 1, MAX_WINDOW)
    stride = _integer(window["stride"], "geometry.window.stride", 1, MAX_WINDOW)
    if short > long:
        raise HeresySecError(
            "GEOMETRY_POLICY_INVALID",
            "geometry.window.short must not exceed geometry.window.long",
        )
    if stride > short:
        raise HeresySecError(
            "GEOMETRY_POLICY_INVALID",
            "geometry.window.stride must not exceed geometry.window.short",
        )

    quantize = _mapping(geometry["quantize"], "policy.geometry.quantize")
    _exact_keys(quantize, required=("scale", "mode"), label="policy.geometry.quantize")
    if quantize["mode"] != "FLOOR":
        raise HeresySecError(
            "GEOMETRY_QUANTIZE_UNSUPPORTED",
            "geometry quantize mode must be FLOOR",
        )

    forman = _mapping(geometry["forman"], "policy.geometry.forman")
    _exact_keys(
        forman,
        required=("mode", "weight_map", "max_abs", "max_window_l1", "learning"),
        label="policy.geometry.forman",
    )
    mode = forman["mode"]
    if type(mode) is not str or mode not in {"unweighted", "weighted"}:
        raise HeresySecError(
            "GEOMETRY_FORMAN_MODE_UNSUPPORTED",
            "geometry.forman.mode must be unweighted or weighted",
        )
    if forman["learning"] != "forbidden":
        raise HeresySecError(
            "GEOMETRY_FORMAN_LEARNING_FORBIDDEN",
            "geometry.forman.learning must be exactly forbidden",
        )
    if type(geometry["require_delta_P"]) is not bool:
        raise HeresySecError(
            "GEOMETRY_POLICY_INVALID",
            "geometry.require_delta_P must be an exact boolean",
        )

    return {
        "module": MODULE,
        "version": MODULE_VERSION_V2,
        "fixture_set": FIXTURE_SET_V2,
        "window": {"short": short, "long": long, "stride": stride},
        "quantize": {
            "scale": _integer(
                quantize["scale"],
                "geometry.quantize.scale",
                1,
                _geometry.MAX_SCALE,
            ),
            "mode": "FLOOR",
        },
        "forman": {
            "mode": mode,
            "weight_map": _normalize_weight_map(forman["weight_map"], mode),
            "max_abs": _integer(
                forman["max_abs"],
                "geometry.forman.max_abs",
                0,
                MAX_THRESHOLD,
            ),
            "max_window_l1": _integer(
                forman["max_window_l1"],
                "geometry.forman.max_window_l1",
                0,
                MAX_THRESHOLD,
            ),
            "learning": "forbidden",
        },
        "max_spectral_l2_delta": _integer(
            geometry["max_spectral_l2_delta"],
            "geometry.max_spectral_l2_delta",
            0,
            MAX_THRESHOLD,
        ),
        "epsilon_P": _integer(geometry["epsilon_P"], "geometry.epsilon_P", 1, 4),
        "forbid_cycles": _geometry._normalize_forbidden_cycles(geometry["forbid_cycles"]),
        "require_delta_P": geometry["require_delta_P"],
    }


def default_forman_resolve_policy() -> dict[str, Any]:
    """Return the conservative default profile-v2 geometry block."""

    return normalize_geometry_policy_v2(
        {
            "module": MODULE,
            "version": MODULE_VERSION_V2,
            "fixture_set": FIXTURE_SET_V2,
            "window": {"short": 4, "long": 16, "stride": 4},
            "quantize": {"scale": 16, "mode": "FLOOR"},
            "forman": {
                "mode": "unweighted",
                "weight_map": {},
                "max_abs": 64,
                "max_window_l1": 512,
                "learning": "forbidden",
            },
            "max_spectral_l2_delta": 4096,
            "epsilon_P": 1,
            "forbid_cycles": [],
            "require_delta_P": True,
        }
    )


def normalize_geometry_policy(value: Any) -> dict[str, Any]:
    if type(value) is dict and value.get("version") == MODULE_VERSION_V2:
        return normalize_geometry_policy_v2(value)
    return _ORIGINAL_NORMALIZE_GEOMETRY_POLICY(value)


@contextmanager
def _profile(profile: str):
    """Serialize profile-sensitive calls into the frozen v1 implementation."""

    with _PROFILE_LOCK:
        previous = _geometry.PROFILE
        _geometry.PROFILE = profile
        try:
            yield
        finally:
            _geometry.PROFILE = previous


def _self_hashed(domain: str, core: dict[str, Any], hash_key: str) -> dict[str, Any]:
    output = {**core, hash_key: ""}
    output[hash_key] = domain_hash(domain, without_self_hash(output, hash_key))
    return output


def _role_graph(
    actions: list[dict[str, Any]],
    *,
    window_index: int,
    role: str,
) -> dict[str, Any]:
    graph = _ORIGINAL_BUILD_ACTION_GRAPH(actions, window_index)
    core = {
        key: value
        for key, value in graph.items()
        if key not in {"schema", "graph_sha256"}
    }
    core.update(
        {
            "schema": "heresy-geom.action-graph/v2",
            "profile": PROFILE_V2,
            "window_role": role,
        }
    )
    return _self_hashed(_V2_DOMAINS["graph"], core, "graph_sha256")


def _edge_weight(edge: dict[str, Any], forman: dict[str, Any]) -> int:
    if forman["mode"] == "unweighted":
        return 1
    label = edge["label"]
    try:
        return forman["weight_map"][label]
    except KeyError as exc:
        raise HeresySecError(
            "GEOMETRY_FORMAN_WEIGHT_MISSING",
            f"weighted Forman profile has no pinned weight for {label}",
        ) from exc


def build_forman_curvature_v2(
    graph: dict[str, Any],
    geometry: dict[str, Any],
    *,
    role: str,
) -> dict[str, Any]:
    """Build the pinned integer weighted/unweighted Forman profile.

    The weighted degree is the sum of incident edge weights, with loops
    contributing twice.  The edge curvature is ``4*w(e)-d_w(u)-d_w(v)``.
    """

    forman = geometry["forman"]
    weighted_degree = {vertex["vertex_sha256"]: 0 for vertex in graph["vertices"]}
    weights: dict[str, int] = {}
    for edge in graph["edges"]:
        weight = _edge_weight(edge, forman)
        weights[edge["edge_sha256"]] = weight
        source = edge["source_sha256"]
        target = edge["target_sha256"]
        if source == target:
            weighted_degree[source] += 2 * weight
        else:
            weighted_degree[source] += weight
            weighted_degree[target] += weight

    scale = geometry["quantize"]["scale"]
    entries = []
    abs_threshold_trips: list[str] = []
    window_l1 = 0
    for edge in graph["edges"]:
        weight = weights[edge["edge_sha256"]]
        curvature = (
            4 * weight
            - weighted_degree[edge["source_sha256"]]
            - weighted_degree[edge["target_sha256"]]
        )
        absolute = abs(curvature)
        window_l1 += absolute
        if absolute > forman["max_abs"]:
            abs_threshold_trips.append(edge["edge_sha256"])
        entries.append(
            {
                "edge_sha256": edge["edge_sha256"],
                "weight": weight,
                "forman": curvature,
                "quantized_forman": curvature * scale,
            }
        )

    window_l1_trip = window_l1 > forman["max_window_l1"]
    threshold_trips = set(abs_threshold_trips)
    if window_l1_trip:
        threshold_trips.update(edge["edge_sha256"] for edge in graph["edges"])
    core = {
        "schema": "heresy-geom.curvature/v2",
        "profile": PROFILE_V2,
        "window_role": role,
        "graph_sha256": graph["graph_sha256"],
        "formula": "INTEGER_WEIGHTED_FORMAN_4W_MINUS_WEIGHTED_DEGREES",
        "parallel_edges": "COUNT_MULTIPLICITY",
        "loop_incidence": "COUNT_TWICE",
        "mode": forman["mode"],
        "weight_map": forman["weight_map"],
        "learning": "forbidden",
        "quantize": geometry["quantize"],
        "max_forman_abs": forman["max_abs"],
        "max_forman_window_l1": forman["max_window_l1"],
        "window_l1": window_l1,
        "entries": sorted(entries, key=lambda item: item["edge_sha256"]),
        "abs_threshold_trips": sorted(abs_threshold_trips),
        "window_l1_trip": window_l1_trip,
        "threshold_trips": sorted(threshold_trips),
        "ok": not abs_threshold_trips and not window_l1_trip,
    }
    return _self_hashed(_V2_DOMAINS["curvature"], core, "curvature_sha256")
