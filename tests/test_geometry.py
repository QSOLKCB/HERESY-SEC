from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from heresy_sec import geometry_math
from heresy_sec.artifacts import build_manifest
from heresy_sec.canonical import (
    DOMAINS,
    canonical_bytes,
    domain_hash,
    parse_json_bytes,
    without_self_hash,
)
from heresy_sec.contracts import normalize_policy
from heresy_sec.engine import (
    demo_documents,
    inspect_run,
    replay_run,
    run_actions,
    verify_run_directory,
)
from heresy_sec.errors import HeresySecError
from heresy_sec.geometry import (
    FIXTURE_SET,
    build_curvature,
    default_geometry_policy,
    shadow_guard_transition,
)
from heresy_sec.geometry_math import quantized_real_spectrum


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "geometry"
REGISTRY_FIXTURES = {
    row["name"]: row
    for row in json.loads(
        (FIXTURES / "registry_fixtures.json").read_text(encoding="utf-8")
    )["fixtures"]
}


def geometry_policy() -> dict[str, object]:
    _, policy = demo_documents()
    return {
        **policy,
        "schema": "heresy-sec.policy/v2",
        "geometry": default_geometry_policy(),
    }


def allow_authorities(
    policy: dict[str, object],
    authorities: list[str],
) -> dict[str, object]:
    output = copy.deepcopy(policy)
    output["boundaries"]["allowed_authorities"] = authorities
    return output


def action_variant(
    action: dict[str, object],
    *,
    action_id: str,
    sequence: int,
    service: str,
    operation: str,
    target: str,
    authority: str,
) -> dict[str, object]:
    output = copy.deepcopy(action)
    output.update(
        {
            "action_id": action_id,
            "sequence": sequence,
            "service": service,
            "operation": operation,
            "target": target,
            "requested_authority": authority,
        }
    )
    return output


class GeometryMathTests(unittest.TestCase):
    def test_fixture_set_is_named_in_registry_vectors(self) -> None:
        fixture = json.loads(
            (FIXTURES / "registry_fixtures.json").read_text(encoding="utf-8")
        )
        self.assertEqual(fixture["fixture_set"], FIXTURE_SET)

    def test_t2_forman_fixture_table(self) -> None:
        fixture = json.loads((FIXTURES / "forman_fixtures.json").read_text(encoding="utf-8"))
        geometry = default_geometry_policy()
        for row in fixture["fixtures"]:
            with self.subTest(name=row["name"]):
                vertices = sorted({vertex for edge in row["edges"] for vertex in edge})
                graph = {
                    "graph_sha256": "0" * 64,
                    "vertices": [{"vertex_sha256": vertex} for vertex in vertices],
                    "edges": [
                        {
                            "edge_sha256": f"{index:064x}",
                            "source_sha256": source,
                            "target_sha256": target,
                        }
                        for index, (source, target) in enumerate(row["edges"], start=1)
                    ],
                }
                curvature = build_curvature(graph, geometry)
                actual = [item["forman"] for item in curvature["entries"]]
                self.assertEqual(actual, row["expected_forman"])

    def test_t3_path_and_cycle_laplacian_spectra(self) -> None:
        fixture = json.loads((FIXTURES / "spectral_fixtures.json").read_text(encoding="utf-8"))
        matrices = {
            "path_3": [[1, -1, 0], [-1, 2, -1], [0, -1, 1]],
            "cycle_4": [
                [2, -1, 0, -1],
                [-1, 2, -1, 0],
                [0, -1, 2, -1],
                [-1, 0, -1, 2],
            ],
        }
        for row in fixture["fixtures"]:
            with self.subTest(name=row["name"]):
                coefficients, spectrum = quantized_real_spectrum(
                    matrices[row["name"]],
                    scale=fixture["quantize"]["scale"],
                    upper_bound=8,
                )
                self.assertEqual(coefficients, row["characteristic_coefficients"])
                self.assertEqual(spectrum, row["expected_quantized_eigenvalues"])

    def test_spectral_isolation_does_not_scan_the_full_grid(self) -> None:
        matrix = [
            [1, -1, 0, 0],
            [-1, 2, -1, 0],
            [0, -1, 2, -1],
            [0, 0, -1, 1],
        ]
        evaluate = geometry_math._evaluate
        with mock.patch.object(
            geometry_math,
            "_evaluate",
            wraps=evaluate,
        ) as monitored:
            _, spectrum = quantized_real_spectrum(
                matrix,
                scale=64,
                upper_bound=64,
            )
        self.assertEqual(spectrum, [0, 37, 128, 218])
        self.assertLess(monitored.call_count, 1_000)

    def test_spectral_isolation_work_limit_fails_closed(self) -> None:
        with mock.patch.object(
            geometry_math,
            "MAX_SPECTRAL_ISOLATION_POINTS",
            1,
        ):
            with self.assertRaises(HeresySecError) as raised:
                quantized_real_spectrum(
                    [[1, -1], [-1, 1]],
                    scale=64,
                    upper_bound=64,
                )
        self.assertEqual(
            raised.exception.code,
            "GEOMETRY_SPECTRAL_WORK_LIMIT",
        )

    def test_t5_shadow_guard_cannot_silently_rearm(self) -> None:
        self.assertFalse(
            shadow_guard_transition(
                armed=True,
                trip=True,
                rearm_receipt_present=False,
                revalidation_ok=True,
            )
        )
        self.assertFalse(
            shadow_guard_transition(
                armed=False,
                trip=False,
                rearm_receipt_present=False,
                revalidation_ok=True,
            )
        )
        self.assertTrue(
            shadow_guard_transition(
                armed=False,
                trip=False,
                rearm_receipt_present=True,
                revalidation_ok=True,
            )
        )


class GeometryEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.action, _ = demo_documents()

    def _allow_rules(self, operations: list[tuple[str, str]]) -> list[dict[str, object]]:
        return [
            {
                "schema": "heresy-sec.rule/v1",
                "rule_id": f"allow-{service}-{operation}-{index}",
                "priority": 100,
                "effect": "ALLOW",
                "services": [service],
                "operations": [operation],
                "target_prefixes": ["*"],
                "agent_ids": ["demo-agent"],
                "authorities": ["*"],
            }
            for index, (service, operation) in enumerate(operations)
        ]

    def _run(
        self,
        root: Path,
        name: str,
        actions: list[dict[str, object]],
        policy: dict[str, object],
    ) -> tuple[Path, dict[str, object]]:
        return run_actions(
            [canonical_bytes(action) for action in actions],
            canonical_bytes(policy),
            root,
            run_name=name,
        )

    def test_t1_geometry_replay_is_bit_identical(self) -> None:
        policy = geometry_policy()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, first_report = self._run(root, "first", [self.action], policy)
            second, second_report = self._run(root, "second", [self.action], policy)
            first_geometry = {
                path.relative_to(first).as_posix(): path.read_bytes()
                for path in first.rglob("*")
                if path.is_file()
                and path.relative_to(first).as_posix().startswith("geometry")
            }
            second_geometry = {
                path.relative_to(second).as_posix(): path.read_bytes()
                for path in second.rglob("*")
                if path.is_file()
                and path.relative_to(second).as_posix().startswith("geometry")
            }
            self.assertEqual(first_report["run_id"], second_report["run_id"])
            self.assertTrue(first_geometry)
            self.assertEqual(first_geometry, second_geometry)
            self.assertEqual(replay_run(first)["status"], "PASS")

    def test_t4_unauthorized_authority_flip_trips_holonomy(self) -> None:
        policy = allow_authorities(
            geometry_policy(),
            ["READ_ONLY_EXTERNAL", "WORKSPACE_WRITE"],
        )
        policy["rules"] = self._allow_rules([("file", "read"), ("file", "write")])
        read = action_variant(
            self.action,
            action_id="external-read",
            sequence=0,
            service="file",
            operation="read",
            target="workspace/evidence.txt",
            authority="READ_ONLY_EXTERNAL",
        )
        write = action_variant(
            self.action,
            action_id="workspace-write",
            sequence=1,
            service="file",
            operation="write",
            target="workspace/evidence.txt",
            authority="WORKSPACE_WRITE",
        )
        with tempfile.TemporaryDirectory() as directory:
            run_dir, report = self._run(Path(directory), "holonomy", [read, write], policy)
            holonomy = parse_json_bytes(
                (run_dir / "geometry/000000/holonomy.json").read_bytes()
            )
            decision = parse_json_bytes(
                (run_dir / "geometry/000000/decision.json").read_bytes()
            )
            registry = parse_json_bytes(
                (
                    run_dir
                    / "geometry/000000/impossible-configurations.json"
                ).read_bytes()
            )
            obstruction = next(
                item
                for item in registry["obstructions"]
                if item["obstruction_type"] == "PRIVILEGE_PENROSE_LOOP"
            )
            expected = REGISTRY_FIXTURES["privilege_penrose_loop"]
            self.assertEqual(holonomy["delta_P"], 1)
            self.assertEqual(decision["effect"], "DENY")
            self.assertFalse(decision["load_bearing_allow"])
            self.assertEqual(report["final_state"], "DENIED")
            self.assertEqual(
                obstruction["obstruction_type"],
                expected["expected_obstruction_type"],
            )
            self.assertEqual(obstruction["residual"], expected["expected_residual"])
            self.assertEqual(replay_run(run_dir)["status"], "PASS")

    def test_t5_shadow_guard_requires_logged_rearm_and_revalidation(self) -> None:
        policy = allow_authorities(
            geometry_policy(),
            ["READ_ONLY_EXTERNAL", "SIM_ONLY", "WORKSPACE_WRITE"],
        )
        policy["geometry"]["window"] = 2
        policy["rules"] = self._allow_rules(
            [("file", "read"), ("file", "write"), ("system", "rearm")]
        )
        trip_actions = [
            action_variant(
                self.action,
                action_id="external-read",
                sequence=0,
                service="file",
                operation="read",
                target="workspace/evidence.txt",
                authority="READ_ONLY_EXTERNAL",
            ),
            action_variant(
                self.action,
                action_id="workspace-write",
                sequence=1,
                service="file",
                operation="write",
                target="workspace/evidence.txt",
                authority="WORKSPACE_WRITE",
            ),
        ]
        safe_actions = [
            action_variant(
                self.action,
                action_id=f"safe-read-{index}",
                sequence=index,
                service="file",
                operation="read",
                target="workspace/safe.txt",
                authority="SIM_ONLY",
            )
            for index in (2, 3)
        ]
        rearm = action_variant(
            self.action,
            action_id="explicit-rearm",
            sequence=2,
            service="system",
            operation="rearm",
            target="shadow-guard",
            authority="SIM_ONLY",
        )
        revalidated_read = action_variant(
            self.action,
            action_id="post-rearm-read",
            sequence=3,
            service="file",
            operation="read",
            target="workspace/safe.txt",
            authority="SIM_ONLY",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blocked, _ = self._run(
                root,
                "silent-rearm",
                trip_actions + safe_actions,
                policy,
            )
            blocked_decision = parse_json_bytes(
                (blocked / "geometry/000001/decision.json").read_bytes()
            )
            self.assertEqual(blocked_decision["effect"], "DENY")
            self.assertFalse(blocked_decision["shadow_guard_armed"])

            rearmed, _ = self._run(
                root,
                "explicit-rearm",
                trip_actions + [rearm, revalidated_read],
                policy,
            )
            rearmed_decision = parse_json_bytes(
                (rearmed / "geometry/000001/decision.json").read_bytes()
            )
            self.assertEqual(rearmed_decision["effect"], "ALLOW")
            self.assertTrue(rearmed_decision["shadow_guard_armed"])
            self.assertTrue(rearmed_decision["load_bearing_allow"])

    def test_shadow_guard_review_cannot_revalidate_rearm(self) -> None:
        policy = allow_authorities(
            geometry_policy(),
            ["READ_ONLY_EXTERNAL", "SIM_ONLY", "WORKSPACE_WRITE"],
        )
        policy["geometry"]["window"] = 2
        policy["rules"] = self._allow_rules(
            [("file", "read"), ("file", "write"), ("system", "rearm")]
        )
        policy["rules"].append(
            {
                "schema": "heresy-sec.rule/v1",
                "rule_id": "review-revalidation-read",
                "priority": 200,
                "effect": "REVIEW",
                "services": ["file"],
                "operations": ["read"],
                "target_prefixes": ["workspace/review.txt"],
                "agent_ids": ["demo-agent"],
                "authorities": ["SIM_ONLY"],
            }
        )
        actions = [
            action_variant(
                self.action,
                action_id="trip-read",
                sequence=0,
                service="file",
                operation="read",
                target="workspace/evidence.txt",
                authority="READ_ONLY_EXTERNAL",
            ),
            action_variant(
                self.action,
                action_id="trip-write",
                sequence=1,
                service="file",
                operation="write",
                target="workspace/evidence.txt",
                authority="WORKSPACE_WRITE",
            ),
            action_variant(
                self.action,
                action_id="attempted-rearm",
                sequence=2,
                service="system",
                operation="rearm",
                target="shadow-guard",
                authority="SIM_ONLY",
            ),
            action_variant(
                self.action,
                action_id="reviewed-read",
                sequence=3,
                service="file",
                operation="read",
                target="workspace/review.txt",
                authority="SIM_ONLY",
            ),
            action_variant(
                self.action,
                action_id="safe-read-one",
                sequence=4,
                service="file",
                operation="read",
                target="workspace/safe.txt",
                authority="SIM_ONLY",
            ),
            action_variant(
                self.action,
                action_id="safe-read-two",
                sequence=5,
                service="file",
                operation="read",
                target="workspace/safe.txt",
                authority="SIM_ONLY",
            ),
        ]

        with tempfile.TemporaryDirectory() as directory:
            run_dir, _ = self._run(
                Path(directory),
                "reviewed-rearm",
                actions,
                policy,
            )
            reviewed = parse_json_bytes(
                (run_dir / "geometry/000001/decision.json").read_bytes()
            )
            following = parse_json_bytes(
                (run_dir / "geometry/000002/decision.json").read_bytes()
            )
            self.assertEqual(reviewed["classical_effect"], "REVIEW")
            self.assertEqual(reviewed["effect"], "REVIEW")
            self.assertFalse(reviewed["shadow_guard_armed"])
            self.assertEqual(following["classical_effect"], "ALLOW")
            self.assertEqual(following["geometry_effect"], "ALLOW")
            self.assertEqual(following["effect"], "DENY")
            self.assertFalse(following["shadow_guard_armed"])
            self.assertEqual(replay_run(run_dir)["status"], "PASS")

    def test_t6_missing_evidence_atom_rejects_after_manifest_rebuild(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir, report = self._run(
                Path(directory),
                "missing-atom",
                [self.action],
                geometry_policy(),
            )
            target = run_dir / "geometry/000000/evidence-manifest.json"
            evidence = parse_json_bytes(target.read_bytes())
            evidence["atoms"].pop()
            evidence["atom_count"] -= 1
            evidence["N_missing"] = 1
            evidence["evidence_manifest_sha256"] = domain_hash(
                DOMAINS["evidence_manifest"],
                without_self_hash(evidence, "evidence_manifest_sha256"),
            )
            target.write_bytes(canonical_bytes(evidence))
            self._rebuild_manifest(run_dir, report["run_id"])
            with self.assertRaises(HeresySecError) as raised:
                verify_run_directory(run_dir)
            self.assertEqual(raised.exception.code, "GEOMETRY_ARTIFACT_MISMATCH")

    def test_t7_registry_fixture_classes_are_typed_and_replay_stable(self) -> None:
        policy = allow_authorities(
            geometry_policy(),
            ["READ_ONLY_EXTERNAL", "WORKSPACE_WRITE", "NETWORK"],
        )
        policy["boundaries"].update(
            {
                "network_enabled": True,
                "allowed_network_hosts": ["approved.example"],
                "allowed_network_schemes": ["https"],
            }
        )
        policy["rules"] = self._allow_rules(
            [("file", "read"), ("file", "write"), ("network", "upload")]
        )
        actions = [
            action_variant(
                self.action,
                action_id="read",
                sequence=0,
                service="file",
                operation="read",
                target="workspace/source.txt",
                authority="READ_ONLY_EXTERNAL",
            ),
            action_variant(
                self.action,
                action_id="write",
                sequence=1,
                service="file",
                operation="write",
                target="workspace/result.txt",
                authority="WORKSPACE_WRITE",
            ),
            action_variant(
                self.action,
                action_id="upload",
                sequence=2,
                service="network",
                operation="upload",
                target="https://approved.example/result",
                authority="NETWORK",
            ),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, _ = self._run(root, "registry-first", actions, policy)
            second, _ = self._run(root, "registry-second", actions, policy)
            first_registry = (
                first / "geometry/000000/impossible-configurations.json"
            ).read_bytes()
            second_registry = (
                second / "geometry/000000/impossible-configurations.json"
            ).read_bytes()
            registry = parse_json_bytes(first_registry)
            rows = {
                item["obstruction_type"]: item
                for item in registry["obstructions"]
            }
            for fixture_name in ("egress_staircase", "trident_taint_fork"):
                expected = REGISTRY_FIXTURES[fixture_name]
                obstruction = rows[expected["expected_obstruction_type"]]
                self.assertEqual(
                    obstruction["residual"],
                    expected["expected_residual"],
                )
            self.assertEqual(first_registry, second_registry)

        crate_policy = geometry_policy()
        crate_actions = [
            action_variant(
                self.action,
                action_id="visible-before",
                sequence=0,
                service="file",
                operation="read",
                target="workspace/crate.log",
                authority="SIM_ONLY",
            ),
            action_variant(
                self.action,
                action_id="hidden-denial",
                sequence=1,
                service="file",
                operation="delete",
                target="workspace/crate.log",
                authority="SIM_ONLY",
            ),
            action_variant(
                self.action,
                action_id="visible-after",
                sequence=2,
                service="file",
                operation="read",
                target="workspace/crate.log",
                authority="SIM_ONLY",
            ),
        ]
        with tempfile.TemporaryDirectory() as directory:
            run_dir, _ = self._run(
                Path(directory),
                "crate-occlusion",
                crate_actions,
                crate_policy,
            )
            registry = parse_json_bytes(
                (
                    run_dir
                    / "geometry/000000/impossible-configurations.json"
                ).read_bytes()
            )
            expected = REGISTRY_FIXTURES["crate_log_occlusion"]
            obstruction = next(
                item
                for item in registry["obstructions"]
                if item["obstruction_type"]
                == expected["expected_obstruction_type"]
            )
            self.assertEqual(obstruction["residual"], expected["expected_residual"])
            self.assertEqual(replay_run(run_dir)["status"], "PASS")

    def test_trident_aggregation_keeps_workloads_separate(self) -> None:
        policy = allow_authorities(
            geometry_policy(),
            ["READ_ONLY_EXTERNAL", "WORKSPACE_WRITE", "NETWORK"],
        )
        policy["boundaries"].update(
            {
                "network_enabled": True,
                "allowed_network_hosts": ["approved.example"],
                "allowed_network_schemes": ["https"],
            }
        )
        policy["rules"] = self._allow_rules(
            [("file", "read"), ("file", "write"), ("network", "upload")]
        )
        action_specs = (
            (
                "read",
                "reader-workload",
                "file",
                "read",
                "workspace/source.txt",
                "READ_ONLY_EXTERNAL",
            ),
            (
                "write",
                "writer-workload",
                "file",
                "write",
                "workspace/result.txt",
                "WORKSPACE_WRITE",
            ),
            (
                "upload",
                "sender-workload",
                "network",
                "upload",
                "https://approved.example/result",
                "NETWORK",
            ),
        )
        actions = []
        for sequence, (
            action_id,
            workload_id,
            service,
            operation,
            target,
            authority,
        ) in enumerate(action_specs):
            action = action_variant(
                self.action,
                action_id=action_id,
                sequence=sequence,
                service=service,
                operation=operation,
                target=target,
                authority=authority,
            )
            action["producer"]["workload_id"] = workload_id
            actions.append(action)

        with tempfile.TemporaryDirectory() as directory:
            run_dir, _ = self._run(
                Path(directory),
                "separate-workloads",
                actions,
                policy,
            )
            registry = parse_json_bytes(
                (
                    run_dir
                    / "geometry/000000/impossible-configurations.json"
                ).read_bytes()
            )
            obstruction_types = {
                item["obstruction_type"]
                for item in registry["obstructions"]
            }
            self.assertNotIn("TRIDENT_TAINT_FORK", obstruction_types)
            self.assertEqual(replay_run(run_dir)["status"], "PASS")

    def test_forbidden_cycle_pattern_discharges(self) -> None:
        policy = geometry_policy()
        policy["geometry"]["forbid_cycles"] = [["file.read", "file.write"]]
        policy["rules"] = self._allow_rules([("file", "read"), ("file", "write")])
        actions = [
            action_variant(
                self.action,
                action_id="cycle-read",
                sequence=0,
                service="file",
                operation="read",
                target="workspace/cycle.txt",
                authority="SIM_ONLY",
            ),
            action_variant(
                self.action,
                action_id="cycle-write",
                sequence=1,
                service="file",
                operation="write",
                target="workspace/cycle.txt",
                authority="SIM_ONLY",
            ),
        ]
        with tempfile.TemporaryDirectory() as directory:
            run_dir, report = self._run(
                Path(directory),
                "forbidden-cycle",
                actions,
                policy,
            )
            registry = parse_json_bytes(
                (
                    run_dir
                    / "geometry/000000/impossible-configurations.json"
                ).read_bytes()
            )
            types = {
                item["obstruction_type"]
                for item in registry["obstructions"]
            }
            self.assertIn("FORBIDDEN_POLICY_CYCLE", types)
            self.assertEqual(report["final_state"], "DENIED")

    def test_evidence_atoms_include_event_range_and_rule_matches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir, _ = self._run(
                Path(directory),
                "evidence-atoms",
                [self.action],
                geometry_policy(),
            )
            evidence = parse_json_bytes(
                (
                    run_dir
                    / "geometry/000000/evidence-manifest.json"
                ).read_bytes()
            )
            kinds = {atom["kind"] for atom in evidence["atoms"]}
            self.assertIn("EVENT_RANGE", kinds)
            self.assertIn("CLASSICAL_RULE_MATCH", kinds)

    def test_t8_curvature_tamper_breaks_semantic_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir, report = self._run(
                Path(directory),
                "curvature-tamper",
                [self.action],
                geometry_policy(),
            )
            target = run_dir / "geometry/000000/curvature.json"
            curvature = parse_json_bytes(target.read_bytes())
            curvature["entries"][0]["forman"] += 1
            curvature["curvature_sha256"] = domain_hash(
                DOMAINS["geometry_curvature"],
                without_self_hash(curvature, "curvature_sha256"),
            )
            target.write_bytes(canonical_bytes(curvature))
            self._rebuild_manifest(run_dir, report["run_id"])
            with self.assertRaises(HeresySecError) as raised:
                replay_run(run_dir)
            self.assertEqual(raised.exception.code, "GEOMETRY_ARTIFACT_MISMATCH")

    def test_v1_artifacts_remain_geometry_free_and_v2_fields_fail_closed(self) -> None:
        _, v1 = demo_documents()
        with tempfile.TemporaryDirectory() as directory:
            run_dir, _ = self._run(Path(directory), "legacy", [self.action], v1)
            self.assertFalse((run_dir / "geometry").exists())
            self.assertEqual(verify_run_directory(run_dir)["status"], "PASS")

        invalid = geometry_policy()
        invalid["geometry"]["unexpected"] = True
        with self.assertRaises(HeresySecError) as raised:
            normalize_policy(invalid)
        self.assertEqual(raised.exception.code, "GEOMETRY_POLICY_INVALID")

    def test_inspection_exposes_geometry_without_claiming_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir, _ = self._run(
                Path(directory),
                "inspection",
                [self.action],
                geometry_policy(),
            )
            report = inspect_run(run_dir)
            self.assertEqual(report["geometry"][0]["effect"], "ALLOW")
            self.assertTrue(report["geometry"][0]["load_bearing_allow"])
            self.assertFalse(report["summary"]["actions_executed"])

    @staticmethod
    def _rebuild_manifest(run_dir: Path, run_id: str) -> None:
        files = {
            path.relative_to(run_dir).as_posix(): path.read_bytes()
            for path in run_dir.rglob("*")
            if path.is_file() and path.name != "manifest.json"
        }
        (run_dir / "manifest.json").write_bytes(build_manifest(files, run_id))


if __name__ == "__main__":
    unittest.main()
