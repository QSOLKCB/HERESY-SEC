"""Deterministic HERESY-GEOM implementation profile for policy v2 runs."""

from __future__ import annotations

import math
from collections import deque
from typing import Any, Iterable

from .canonical import DOMAINS, canonical_bytes, domain_hash, sha256_bytes, without_self_hash
from .errors import HeresySecError
from .geometry_math import quantized_real_spectrum


PROFILE = "heresy-geom.profile/v1"
MODULE = "heresy-geom"
MODULE_VERSION = "1"
FIXTURE_SET = "heresy-geom-conformance/v1"
MAX_WINDOW = 32
MAX_SCALE = 64
MAX_FORBIDDEN_PATTERNS = 16
MAX_CYCLE_PATTERN = 8
MAX_CYCLE_SEARCH_STEPS = 100_000

AUTHORITY_MASKS = {
    "SIM_ONLY": 0,
    "READ_ONLY_EXTERNAL": 1,
    "WORKSPACE_WRITE": 2,
    "NETWORK": 4,
    "CONTROLLED_EXECUTION": 8,
}
INBOUND_OPERATIONS = frozenset(
    {
        ("file", "read"),
        ("ipc", "read"),
        ("ipc", "recv"),
        ("model", "recv"),
        ("network", "download"),
        ("network", "recv"),
        ("network", "receive"),
        ("tool", "read"),
    }
)
EGRESS_OPERATIONS = frozenset(
    {
        ("network", "connect"),
        ("network", "send"),
        ("network", "upload"),
    }
)
RESOLVE_ORDER = {"DISCHARGE": 0, "GAP_LIFT": 1, "ATLAS_ONLY": 2}
EFFECT_ORDER = {"DENY": 0, "REVIEW": 1, "ALLOW": 2}


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
        detail = []
        if missing:
            detail.append(f"missing {', '.join(missing)}")
        if unexpected:
            detail.append(f"unexpected {', '.join(unexpected)}")
        raise HeresySecError(
            "GEOMETRY_POLICY_INVALID",
            f"{label} fields are invalid: {'; '.join(detail)}",
        )


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise HeresySecError(
            "GEOMETRY_POLICY_INVALID",
            f"{label} must be an exact integer in {minimum}..{maximum}",
        )
    return value


def _canonical_rotation(pattern: list[str]) -> list[str]:
    rotations = [pattern[index:] + pattern[:index] for index in range(len(pattern))]
    return min(rotations)


def _normalize_forbidden_cycles(value: Any) -> list[list[str]]:
    if type(value) is not list or len(value) > MAX_FORBIDDEN_PATTERNS:
        raise HeresySecError(
            "GEOMETRY_POLICY_INVALID",
            f"geometry.forbid_cycles must contain at most {MAX_FORBIDDEN_PATTERNS} patterns",
        )
    patterns: list[list[str]] = []
    for pattern_index, pattern in enumerate(value):
        if type(pattern) is not list or not 1 <= len(pattern) <= MAX_CYCLE_PATTERN:
            raise HeresySecError(
                "GEOMETRY_POLICY_INVALID",
                f"geometry.forbid_cycles[{pattern_index}] has invalid length",
            )
        normalized: list[str] = []
        for label_index, label in enumerate(pattern):
            if (
                type(label) is not str
                or not 3 <= len(label) <= 129
                or label != label.lower()
                or "." not in label
                or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for character in label)
            ):
                raise HeresySecError(
                    "GEOMETRY_POLICY_INVALID",
                    "forbidden-cycle labels must be lower-case service.operation identifiers",
                )
            normalized.append(label)
        patterns.append(_canonical_rotation(normalized))
    unique = sorted({tuple(pattern) for pattern in patterns})
    if len(unique) != len(patterns):
        raise HeresySecError(
            "GEOMETRY_POLICY_INVALID",
            "geometry.forbid_cycles cannot contain rotational duplicates",
        )
    return [list(pattern) for pattern in unique]


def normalize_geometry_policy(value: Any) -> dict[str, Any]:
    """Normalize the exact HERESY-GEOM v1 policy profile."""

    geometry = _mapping(value, "policy.geometry")
    _exact_keys(
        geometry,
        required=(
            "module",
            "version",
            "fixture_set",
            "window",
            "quantize",
            "max_forman_abs",
            "max_spectral_l2_delta",
            "epsilon_P",
            "forbid_cycles",
            "require_delta_P",
        ),
        label="policy.geometry",
    )
    if geometry["module"] != MODULE or geometry["version"] != MODULE_VERSION:
        raise HeresySecError(
            "GEOMETRY_MODULE_UNSUPPORTED",
            f"geometry module must be {MODULE} version {MODULE_VERSION}",
        )
    if geometry["fixture_set"] != FIXTURE_SET:
        raise HeresySecError(
            "GEOMETRY_FIXTURE_SET_UNSUPPORTED",
            f"geometry fixture_set must be {FIXTURE_SET}",
        )
    quantize = _mapping(geometry["quantize"], "policy.geometry.quantize")
    _exact_keys(
        quantize,
        required=("scale", "mode"),
        label="policy.geometry.quantize",
    )
    if quantize["mode"] != "FLOOR":
        raise HeresySecError(
            "GEOMETRY_QUANTIZE_UNSUPPORTED",
            "geometry quantize mode must be FLOOR",
        )
    if type(geometry["require_delta_P"]) is not bool:
        raise HeresySecError(
            "GEOMETRY_POLICY_INVALID",
            "geometry.require_delta_P must be an exact boolean",
        )
    return {
        "module": MODULE,
        "version": MODULE_VERSION,
        "fixture_set": FIXTURE_SET,
        "window": _integer(geometry["window"], "geometry.window", 1, MAX_WINDOW),
        "quantize": {
            "scale": _integer(
                quantize["scale"],
                "geometry.quantize.scale",
                1,
                MAX_SCALE,
            ),
            "mode": "FLOOR",
        },
        "max_forman_abs": _integer(
            geometry["max_forman_abs"],
            "geometry.max_forman_abs",
            0,
            1_000_000,
        ),
        "max_spectral_l2_delta": _integer(
            geometry["max_spectral_l2_delta"],
            "geometry.max_spectral_l2_delta",
            0,
            1_000_000_000,
        ),
        "epsilon_P": _integer(geometry["epsilon_P"], "geometry.epsilon_P", 1, 4),
        "forbid_cycles": _normalize_forbidden_cycles(geometry["forbid_cycles"]),
        "require_delta_P": geometry["require_delta_P"],
    }


def default_geometry_policy() -> dict[str, Any]:
    return normalize_geometry_policy(
        {
            "module": MODULE,
            "version": MODULE_VERSION,
            "fixture_set": FIXTURE_SET,
            "window": 16,
            "quantize": {"scale": 16, "mode": "FLOOR"},
            "max_forman_abs": 64,
            "max_spectral_l2_delta": 4096,
            "epsilon_P": 1,
            "forbid_cycles": [],
            "require_delta_P": True,
        }
    )


def _self_hashed(domain: str, core: dict[str, Any], hash_key: str) -> dict[str, Any]:
    output = {**core, hash_key: ""}
    output[hash_key] = domain_hash(domain, without_self_hash(output, hash_key))
    return output


def _actor_descriptor(action: dict[str, Any]) -> dict[str, Any]:
    producer = action["producer"]
    return {
        "kind": "ACTOR",
        "agent_id": producer["agent_id"],
        "workload_id": producer["workload_id"],
    }


def _resource_descriptor(action: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "RESOURCE",
        "service": action["service"],
        "target": action["target"],
        "slot": action["slot"] if action["service"] == "ipc" else None,
    }


def _vertex(descriptor: dict[str, Any]) -> dict[str, Any]:
    return {
        **descriptor,
        "vertex_sha256": domain_hash(DOMAINS["geometry_vertex"], descriptor),
    }


def build_action_graph(actions: list[dict[str, Any]], window_index: int) -> dict[str, Any]:
    if not actions:
        raise HeresySecError("GEOMETRY_GRAPH_INVALID", "geometry window cannot be empty")
    vertices: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for action in actions:
        actor = _vertex(_actor_descriptor(action))
        resource = _vertex(_resource_descriptor(action))
        vertices[actor["vertex_sha256"]] = actor
        vertices[resource["vertex_sha256"]] = resource
        if (action["service"], action["operation"]) in INBOUND_OPERATIONS:
            source_sha256 = resource["vertex_sha256"]
            target_sha256 = actor["vertex_sha256"]
        else:
            source_sha256 = actor["vertex_sha256"]
            target_sha256 = resource["vertex_sha256"]
        edge_core = {
            "schema": "heresy-geom.edge/v1",
            "sequence": action["sequence"],
            "action_id": action["action_id"],
            "source_sha256": source_sha256,
            "target_sha256": target_sha256,
            "service": action["service"],
            "operation": action["operation"],
            "label": f"{action['service']}.{action['operation']}",
            "authority": action["requested_authority"],
            "authority_mask": AUTHORITY_MASKS[action["requested_authority"]],
        }
        edges.append(
            {
                **edge_core,
                "edge_sha256": domain_hash(DOMAINS["geometry_edge"], edge_core),
            }
        )
    graph_core = {
        "schema": "heresy-geom.action-graph/v1",
        "profile": PROFILE,
        "window_index": window_index,
        "event_range": {
            "start_sequence": actions[0]["sequence"],
            "end_sequence": actions[-1]["sequence"],
        },
        "vertices": sorted(vertices.values(), key=lambda item: item["vertex_sha256"]),
        "edges": sorted(edges, key=lambda item: (item["sequence"], item["edge_sha256"])),
    }
    return _self_hashed(
        DOMAINS["geometry_graph"],
        graph_core,
        "graph_sha256",
    )


def build_curvature(graph: dict[str, Any], geometry: dict[str, Any]) -> dict[str, Any]:
    degree = {vertex["vertex_sha256"]: 0 for vertex in graph["vertices"]}
    for edge in graph["edges"]:
        source = edge["source_sha256"]
        target = edge["target_sha256"]
        if source == target:
            degree[source] += 2
        else:
            degree[source] += 1
            degree[target] += 1
    scale = geometry["quantize"]["scale"]
    entries = []
    threshold_trips: list[str] = []
    for edge in graph["edges"]:
        curvature = 4 - degree[edge["source_sha256"]] - degree[edge["target_sha256"]]
        if abs(curvature) > geometry["max_forman_abs"]:
            threshold_trips.append(edge["edge_sha256"])
        entries.append(
            {
                "edge_sha256": edge["edge_sha256"],
                "forman": curvature,
                "quantized_forman": curvature * scale,
            }
        )
    core = {
        "schema": "heresy-geom.curvature/v1",
        "profile": PROFILE,
        "graph_sha256": graph["graph_sha256"],
        "formula": "UNWEIGHTED_FORMAN_4_MINUS_DEGREES",
        "parallel_edges": "COUNT_MULTIPLICITY",
        "quantize": geometry["quantize"],
        "max_forman_abs": geometry["max_forman_abs"],
        "entries": sorted(entries, key=lambda item: item["edge_sha256"]),
        "threshold_trips": sorted(threshold_trips),
        "ok": not threshold_trips,
    }
    return _self_hashed(
        DOMAINS["geometry_curvature"],
        core,
        "curvature_sha256",
    )


def _laplacian(graph: dict[str, Any]) -> tuple[list[str], list[list[int]], int]:
    vertices = [vertex["vertex_sha256"] for vertex in graph["vertices"]]
    positions = {vertex: index for index, vertex in enumerate(vertices)}
    matrix = [[0] * len(vertices) for _ in vertices]
    degree = [0] * len(vertices)
    for edge in graph["edges"]:
        source = positions[edge["source_sha256"]]
        target = positions[edge["target_sha256"]]
        if source == target:
            continue
        degree[source] += 1
        degree[target] += 1
        matrix[source][target] -= 1
        matrix[target][source] -= 1
    for index, value in enumerate(degree):
        matrix[index][index] = value
    return vertices, matrix, max(degree, default=0)


def build_spectral(
    graph: dict[str, Any],
    geometry: dict[str, Any],
    previous_spectrum: list[int],
) -> dict[str, Any]:
    vertices, matrix, maximum_degree = _laplacian(graph)
    coefficients, spectrum = quantized_real_spectrum(
        matrix,
        scale=geometry["quantize"]["scale"],
        upper_bound=max(1, 2 * maximum_degree),
    )
    width = max(len(previous_spectrum), len(spectrum))
    previous = [0] * (width - len(previous_spectrum)) + list(previous_spectrum)
    current = [0] * (width - len(spectrum)) + list(spectrum)
    l2_delta = math.isqrt(
        sum((left - right) ** 2 for left, right in zip(previous, current))
    )
    core = {
        "schema": "heresy-geom.spectral/v1",
        "profile": PROFILE,
        "graph_sha256": graph["graph_sha256"],
        "projection": "UNDIRECTED_MULTIGRAPH_LAPLACIAN",
        "vertex_sha256s": vertices,
        "characteristic_coefficients_decimal": [str(value) for value in coefficients],
        "quantized_eigenvalues": spectrum,
        "previous_quantized_eigenvalues": previous_spectrum,
        "quantize": geometry["quantize"],
        "spectral_l2_delta": l2_delta,
        "max_spectral_l2_delta": geometry["max_spectral_l2_delta"],
        "ok": l2_delta <= geometry["max_spectral_l2_delta"],
    }
    return _self_hashed(
        DOMAINS["geometry_spectral"],
        core,
        "spectral_sha256",
    )


def build_holonomy(graph: dict[str, Any], geometry: dict[str, Any]) -> dict[str, Any]:
    adjacency: dict[str, list[tuple[str, int, str]]] = {
        vertex["vertex_sha256"]: [] for vertex in graph["vertices"]
    }
    for edge in graph["edges"]:
        source = edge["source_sha256"]
        target = edge["target_sha256"]
        item = (target, edge["authority_mask"], edge["edge_sha256"])
        reverse = (source, edge["authority_mask"], edge["edge_sha256"])
        adjacency[source].append(item)
        adjacency[target].append(reverse)
    for neighbours in adjacency.values():
        neighbours.sort(key=lambda item: (item[0], item[2]))

    potentials: dict[str, int] = {}
    residuals: dict[tuple[str, int], dict[str, Any]] = {}
    for start in sorted(adjacency):
        if start in potentials:
            continue
        potentials[start] = 0
        pending = deque([start])
        while pending:
            source = pending.popleft()
            for target, authority_mask, edge_sha256 in adjacency[source]:
                proposed = potentials[source] ^ authority_mask
                if target not in potentials:
                    potentials[target] = proposed
                    pending.append(target)
                    continue
                residual_mask = proposed ^ potentials[target]
                if residual_mask:
                    residuals[(edge_sha256, residual_mask)] = {
                        "edge_sha256": edge_sha256,
                        "residual_mask": residual_mask,
                        "residual": residual_mask.bit_count(),
                    }
    rows = sorted(
        residuals.values(),
        key=lambda item: (item["edge_sha256"], item["residual_mask"]),
    )
    maximum = max((item["residual"] for item in rows), default=0)
    delta_p = 1 if maximum >= geometry["epsilon_P"] else 0
    core = {
        "schema": "heresy-geom.holonomy/v1",
        "profile": PROFILE,
        "graph_sha256": graph["graph_sha256"],
        "authority_group": "Z2_POWER_4_XOR",
        "distance": "HAMMING_WEIGHT",
        "epsilon_P": geometry["epsilon_P"],
        "potentials": [
            {"vertex_sha256": vertex, "authority_mask": potentials[vertex]}
            for vertex in sorted(potentials)
        ],
        "residuals": rows,
        "max_residual": maximum,
        "delta_P": delta_p,
    }
    return _self_hashed(
        DOMAINS["geometry_holonomy"],
        core,
        "holonomy_sha256",
    )


def _canonical_edge_cycle(edge_sha256s: list[str]) -> tuple[str, ...]:
    rotations = [
        tuple(edge_sha256s[index:] + edge_sha256s[:index])
        for index in range(len(edge_sha256s))
    ]
    return min(rotations)


def _matching_cycles(graph: dict[str, Any], pattern: list[str]) -> list[list[str]]:
    adjacency: dict[str, list[dict[str, Any]]] = {}
    for edge in graph["edges"]:
        adjacency.setdefault(edge["source_sha256"], []).append(edge)
    for edges in adjacency.values():
        edges.sort(key=lambda item: item["edge_sha256"])
    matches: set[tuple[str, ...]] = set()
    steps = 0

    def walk(
        start: str,
        current: str,
        offset: int,
        edge_path: list[str],
        visited: set[str],
    ) -> None:
        nonlocal steps
        steps += 1
        if steps > MAX_CYCLE_SEARCH_STEPS:
            raise HeresySecError(
                "GEOMETRY_CYCLE_SEARCH_LIMIT",
                "forbidden-cycle search exceeded its deterministic bound",
            )
        if offset == len(pattern):
            if current == start:
                matches.add(_canonical_edge_cycle(edge_path))
            return
        for edge in adjacency.get(current, []):
            if edge["label"] != pattern[offset]:
                continue
            target = edge["target_sha256"]
            if target in visited and not (offset + 1 == len(pattern) and target == start):
                continue
            walk(
                start,
                target,
                offset + 1,
                edge_path + [edge["edge_sha256"]],
                visited | {target},
            )

    for start in sorted(adjacency):
        walk(start, start, 0, [], {start})
    return [list(match) for match in sorted(matches)]


def _obstruction(
    obstruction_type: str,
    residual: int,
    resolve_mode: str,
    edge_sha256s: Iterable[str],
) -> dict[str, Any]:
    core = {
        "obstruction_type": obstruction_type,
        "residual": residual,
        "resolve_mode": resolve_mode,
        "edge_sha256s": sorted(set(edge_sha256s)),
    }
    return {
        **core,
        "obstruction_sha256": domain_hash(DOMAINS["geometry_obstruction"], core),
    }


def build_registry(
    actions: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    graph: dict[str, Any],
    curvature: dict[str, Any],
    spectral: dict[str, Any],
    holonomy: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    geometry = policy["geometry"]
    obstructions: dict[str, dict[str, Any]] = {}

    holonomy_mode = "DISCHARGE" if geometry["require_delta_P"] else "GAP_LIFT"
    for residual in holonomy["residuals"]:
        item = _obstruction(
            "PRIVILEGE_PENROSE_LOOP",
            residual["residual"],
            holonomy_mode,
            [residual["edge_sha256"]],
        )
        obstructions[item["obstruction_sha256"]] = item

    for pattern in geometry["forbid_cycles"]:
        for edge_sha256s in _matching_cycles(graph, pattern):
            item = _obstruction(
                "FORBIDDEN_POLICY_CYCLE",
                len(pattern),
                "DISCHARGE",
                edge_sha256s,
            )
            obstructions[item["obstruction_sha256"]] = item

    edge_by_action = {edge["action_id"]: edge["edge_sha256"] for edge in graph["edges"]}
    for left_index, left in enumerate(actions):
        if (left["service"], left["operation"]) != ("file", "read"):
            continue
        for right in actions[left_index + 1 :]:
            if (
                (right["service"], right["operation"]) in EGRESS_OPERATIONS
                and right["producer"]["agent_id"] == left["producer"]["agent_id"]
            ):
                item = _obstruction(
                    "EGRESS_STAIRCASE",
                    right["sequence"] - left["sequence"],
                    "GAP_LIFT",
                    [edge_by_action[left["action_id"]], edge_by_action[right["action_id"]]],
                )
                obstructions[item["obstruction_sha256"]] = item

    actor_edges: dict[tuple[str, str | None], list[dict[str, Any]]] = {}
    graph_edges_by_action = {
        edge["action_id"]: edge
        for edge in graph["edges"]
    }
    for action in actions:
        edge = graph_edges_by_action[action["action_id"]]
        actor_key = (
            action["producer"]["agent_id"],
            action["producer"]["workload_id"],
        )
        actor_edges.setdefault(actor_key, []).append(edge)
    required_masks = {
        AUTHORITY_MASKS["READ_ONLY_EXTERNAL"],
        AUTHORITY_MASKS["WORKSPACE_WRITE"],
        AUTHORITY_MASKS["NETWORK"],
    }
    for edges in actor_edges.values():
        masks = {edge["authority_mask"] for edge in edges}
        targets = {edge["target_sha256"] for edge in edges}
        if required_masks <= masks and len(targets) >= 3:
            item = _obstruction(
                "TRIDENT_TAINT_FORK",
                len(targets),
                "GAP_LIFT",
                [edge["edge_sha256"] for edge in edges],
            )
            obstructions[item["obstruction_sha256"]] = item

    for index, decision in enumerate(decisions):
        if decision["effect"] != "DENY":
            continue
        target = actions[index]["target"]
        before = any(
            earlier["target"] == target and decisions[position]["effect"] != "DENY"
            for position, earlier in enumerate(actions[:index])
        )
        after = any(
            later["target"] == target and decisions[index + 1 + position]["effect"] != "DENY"
            for position, later in enumerate(actions[index + 1 :])
        )
        if before and after:
            item = _obstruction(
                "CRATE_LOG_OCCLUSION",
                1,
                "DISCHARGE",
                [edge_by_action[actions[index]["action_id"]]],
            )
            obstructions[item["obstruction_sha256"]] = item

    maximum_slots = policy["boundaries"]["max_ipc_slots"]
    for action in actions:
        if action["service"] == "ipc" and (
            action["slot"] is None or not 0 <= action["slot"] < maximum_slots
        ):
            item = _obstruction(
                "IPC_CARDINALITY_INVALID",
                1,
                "DISCHARGE",
                [edge_by_action[action["action_id"]]],
            )
            obstructions[item["obstruction_sha256"]] = item

    if not curvature["ok"]:
        item = _obstruction(
            "FORMAN_THRESHOLD_TRIP",
            len(curvature["threshold_trips"]),
            "DISCHARGE",
            curvature["threshold_trips"],
        )
        obstructions[item["obstruction_sha256"]] = item
    if not spectral["ok"]:
        item = _obstruction(
            "SPECTRAL_DELTA_TRIP",
            spectral["spectral_l2_delta"],
            "DISCHARGE",
            graph_edge_ids(graph),
        )
        obstructions[item["obstruction_sha256"]] = item

    rows = sorted(
        obstructions.values(),
        key=lambda item: (
            RESOLVE_ORDER[item["resolve_mode"]],
            item["obstruction_type"],
            item["obstruction_sha256"],
        ),
    )
    if any(item["resolve_mode"] == "DISCHARGE" for item in rows):
        effect = "DENY"
    elif rows:
        effect = "REVIEW"
    else:
        effect = "ALLOW"
    core = {
        "schema": "heresy-geom.impossible-configurations/v1",
        "profile": PROFILE,
        "graph_sha256": graph["graph_sha256"],
        "obstructions": rows,
        "obstruction_count": len(rows),
        "effect": effect,
    }
    return _self_hashed(
        DOMAINS["geometry_registry"],
        core,
        "registry_sha256",
    )


def graph_edge_ids(graph: dict[str, Any]) -> list[str]:
    return [edge["edge_sha256"] for edge in graph["edges"]]


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
        "atom_id": domain_hash(DOMAINS["evidence_atom"], core),
    }


def build_evidence_manifest(
    *,
    raw_actions: list[bytes],
    actions: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    policy_sha256: str,
    graph: dict[str, Any],
    curvature: dict[str, Any],
    spectral: dict[str, Any],
    holonomy: dict[str, Any],
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
            cell="geometry",
            kind="ACTION_GRAPH",
            ordinal=0,
            reference_sha256=graph["graph_sha256"],
        ),
        _evidence_atom(
            cell="geometry",
            kind="CURVATURE",
            ordinal=1,
            reference_sha256=curvature["curvature_sha256"],
        ),
        _evidence_atom(
            cell="geometry",
            kind="SPECTRAL",
            ordinal=2,
            reference_sha256=spectral["spectral_sha256"],
        ),
        _evidence_atom(
            cell="geometry",
            kind="HOLONOMY",
            ordinal=3,
            reference_sha256=holonomy["holonomy_sha256"],
        ),
        _evidence_atom(
            cell="geometry",
            kind="IMPOSSIBLE_CONFIGURATIONS",
            ordinal=4,
            reference_sha256=registry["registry_sha256"],
        ),
        _evidence_atom(
            cell="event",
            kind="EVENT_RANGE",
            ordinal=0,
            reference_sha256=domain_hash(
                DOMAINS["geometry_event_range"],
                graph["event_range"],
            ),
        ),
    ]
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
    core = {
        "schema": "heresy-geom.evidence-manifest/v1",
        "profile": PROFILE,
        "event_range": graph["event_range"],
        "atoms": sorted(atoms, key=lambda item: item["atom_id"]),
        "atom_count": len(atoms),
        "N_missing": 0,
    }
    return _self_hashed(
        DOMAINS["evidence_manifest"],
        core,
        "evidence_manifest_sha256",
    )


def _classical_effect(decisions: list[dict[str, Any]]) -> str:
    return min(
        (decision["effect"] for decision in decisions),
        key=lambda effect: EFFECT_ORDER[effect],
    )


def shadow_guard_transition(
    *,
    armed: bool,
    trip: bool,
    rearm_receipt_present: bool,
    revalidation_ok: bool,
) -> bool:
    """Apply the deterministic fuse rule; silent rearm is impossible."""

    values = (armed, trip, rearm_receipt_present, revalidation_ok)
    if any(type(value) is not bool for value in values):
        raise HeresySecError(
            "SHADOW_GUARD_INVALID",
            "Shadow Guard transition inputs must be exact booleans",
        )
    if trip:
        return False
    if armed:
        return True
    return rearm_receipt_present and revalidation_ok


def _is_rearm_action(action: dict[str, Any], decision: dict[str, Any]) -> bool:
    return (
        action["service"] == "system"
        and action["operation"] == "rearm"
        and action["target"] == "shadow-guard"
        and decision["effect"] == "ALLOW"
    )


def build_geometry_window(
    *,
    window_index: int,
    raw_actions: list[bytes],
    actions: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    receipts: list[dict[str, Any]],
    policy: dict[str, Any],
    previous_spectrum: list[int],
    previous_geometry_receipt_sha256: str,
    previously_armed: bool,
) -> dict[str, Any]:
    graph = build_action_graph(actions, window_index)
    curvature = build_curvature(graph, policy["geometry"])
    spectral = build_spectral(graph, policy["geometry"], previous_spectrum)
    holonomy = build_holonomy(graph, policy["geometry"])
    registry = build_registry(
        actions,
        decisions,
        graph,
        curvature,
        spectral,
        holonomy,
        policy,
    )
    policy_sha256 = domain_hash(DOMAINS["policy_v2"], policy)
    evidence = build_evidence_manifest(
        raw_actions=raw_actions,
        actions=actions,
        decisions=decisions,
        policy_sha256=policy_sha256,
        graph=graph,
        curvature=curvature,
        spectral=spectral,
        holonomy=holonomy,
        registry=registry,
    )
    geometry_core = {
        "schema": "heresy-geom.commitment/v1",
        "profile": PROFILE,
        "window_index": window_index,
        "event_range": graph["event_range"],
        "graph_sha256": graph["graph_sha256"],
        "curvature_sha256": curvature["curvature_sha256"],
        "spectral_sha256": spectral["spectral_sha256"],
        "holonomy_sha256": holonomy["holonomy_sha256"],
        "registry_sha256": registry["registry_sha256"],
        "evidence_manifest_sha256": evidence["evidence_manifest_sha256"],
        "delta_P": holonomy["delta_P"],
        "geometry_effect": registry["effect"],
    }
    commitment = _self_hashed(
        DOMAINS["geometry"],
        geometry_core,
        "geometry_sha256",
    )

    classical_effect = _classical_effect(decisions)
    geometry_effect = registry["effect"]
    preliminary_effect = min(
        (classical_effect, geometry_effect),
        key=lambda effect: EFFECT_ORDER[effect],
    )
    trip = preliminary_effect == "DENY" or geometry_effect == "REVIEW"
    rearm_present = _is_rearm_action(actions[0], decisions[0])
    armed = shadow_guard_transition(
        armed=previously_armed,
        trip=trip,
        rearm_receipt_present=rearm_present,
        revalidation_ok=geometry_effect == "ALLOW" and classical_effect != "DENY",
    )
    if not armed and preliminary_effect == "ALLOW":
        final_effect = "DENY"
    else:
        final_effect = preliminary_effect
    reason_codes = []
    if classical_effect != "ALLOW":
        reason_codes.append(f"CLASSICAL_{classical_effect}")
    reason_codes.extend(item["obstruction_type"] for item in registry["obstructions"])
    if not armed:
        reason_codes.append("SHADOW_GUARD_DISARMED")
    if not reason_codes:
        reason_codes.append("GEOMETRY_ALLOW")
    decision_core = {
        "schema": "heresy-geom.decision/v1",
        "profile": PROFILE,
        "window_index": window_index,
        "policy_sha256": policy_sha256,
        "geometry_sha256": commitment["geometry_sha256"],
        "evidence_manifest_sha256": evidence["evidence_manifest_sha256"],
        "classical_effect": classical_effect,
        "geometry_effect": geometry_effect,
        "effect": final_effect,
        "reason_codes": sorted(set(reason_codes)),
        "shadow_guard_armed": armed,
        "load_bearing_allow": (
            final_effect == "ALLOW"
            and armed
            and holonomy["delta_P"] == 0
            and evidence["N_missing"] == 0
            and curvature["ok"]
            and spectral["ok"]
        ),
        "N_missing": evidence["N_missing"],
    }
    geometry_decision = _self_hashed(
        DOMAINS["geometry_decision"],
        decision_core,
        "geometry_decision_sha256",
    )
    receipt_core = {
        "schema": "heresy-geom.receipt/v1",
        "profile": PROFILE,
        "window_index": window_index,
        "event_range": graph["event_range"],
        "geometry_sha256": commitment["geometry_sha256"],
        "geometry_decision_sha256": geometry_decision["geometry_decision_sha256"],
        "evidence_manifest_sha256": evidence["evidence_manifest_sha256"],
        "head_classical_receipt_sha256": receipts[-1]["receipt_sha256"],
        "previous_geometry_receipt_sha256": previous_geometry_receipt_sha256,
    }
    geometry_receipt = _self_hashed(
        DOMAINS["geometry_receipt"],
        receipt_core,
        "geometry_receipt_sha256",
    )
    return {
        "graph": graph,
        "curvature": curvature,
        "spectral": spectral,
        "holonomy": holonomy,
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
    width = policy["geometry"]["window"]
    windows: list[dict[str, Any]] = []
    previous_spectrum: list[int] = []
    previous_receipt = zero_hash
    armed = True
    for window_index, start in enumerate(range(0, len(actions), width)):
        stop = min(start + width, len(actions))
        window = build_geometry_window(
            window_index=window_index,
            raw_actions=raw_actions[start:stop],
            actions=actions[start:stop],
            decisions=decisions[start:stop],
            receipts=receipts[start:stop],
            policy=policy,
            previous_spectrum=previous_spectrum,
            previous_geometry_receipt_sha256=previous_receipt,
            previously_armed=armed,
        )
        windows.append(window)
        previous_spectrum = window["spectral"]["quantized_eigenvalues"]
        previous_receipt = window["receipt"]["geometry_receipt_sha256"]
        armed = window["decision"]["shadow_guard_armed"]
    return windows


def geometry_artifact_map(windows: list[dict[str, Any]]) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    log = []
    names = (
        ("action-graph.json", "graph"),
        ("curvature.json", "curvature"),
        ("spectral.json", "spectral"),
        ("holonomy.json", "holonomy"),
        ("impossible-configurations.json", "registry"),
        ("evidence-manifest.json", "evidence"),
        ("commitment.json", "commitment"),
        ("decision.json", "decision"),
        ("receipt.json", "receipt"),
    )
    for index, window in enumerate(windows):
        prefix = f"geometry/{index:06d}"
        for filename, key in names:
            files[f"{prefix}/{filename}"] = canonical_bytes(window[key])
        log.append(canonical_bytes(window["receipt"]) + b"\n")
    if windows:
        files["geometry-event-log.jsonl"] = b"".join(log)
    return dict(sorted(files.items()))


def geometry_effect_counts(windows: list[dict[str, Any]]) -> dict[str, int]:
    return {
        effect: sum(1 for window in windows if window["decision"]["effect"] == effect)
        for effect in ("ALLOW", "DENY", "REVIEW")
    }
