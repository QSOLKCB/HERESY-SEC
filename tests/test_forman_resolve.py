from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from heresy_sec.artifacts import build_manifest
from heresy_sec.canonical import canonical_bytes, parse_json_bytes
from heresy_sec.contracts import normalize_policy
from heresy_sec.engine import (
    demo_documents,
    replay_run,
    run_actions,
    verify_run_directory,
)
from heresy_sec.errors import HeresySecError
from heresy_sec.geometry import default_geometry_policy
from heresy_sec.geometry_profile_v2 import (
    FIXTURE_SET_V2,
    PROFILE_V2,
    build_forman_curvature_v2,
    default_forman_resolve_policy,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "geometry" / "forman_threshold_fixtures.json"


def v2_policy() -> dict[str, object]:
    _, policy = demo_documents()
    return {
        **policy,
        "schema": "heresy-sec.policy/v2",
        "geometry": default_forman_resolve_policy(),
    }


def action_stream(count: int) -> list[dict[str, object]]:
    action, _ = demo_documents()
    output = []
    for index in range(count):
        item = copy.deepcopy(action)
        item.update(
            {
                "action_id": f"forman-{index:03d}",
                "sequence": index,
                "target": f"workspace/forman-{index:03d}.txt",
            }
        )
        output.append(item)
    return output


def raw_stream(actions: list[dict[str, object]]) -> list[bytes]:
    return [canonical_bytes(action) + b"\n" for action in actions]


def graph_from_fixture(row: dict[str, object]) -> dict[str, object]:
    vertices = sorted({vertex for edge in row["edges"] for vertex in edge[:2]})
    edges = []
    for index, edge in enumerate(row["edges"], start=1):
        source, target, label = edge
        edges.append(
            {
                "edge_sha256": f"{index:064x}",
                "source_sha256": source,
                "target_sha256": target,
                "label": label,
            }
        )
    return {
        "graph_sha256": "0" * 64,
        "vertices": [{"vertex_sha256": vertex} for vertex in vertices],
        "edges": edges,
    }


class FormanResolvePolicyTests(unittest.TestCase):
    def test_profile_v1_remains_frozen_and_available(self) -> None:
        geometry = default_geometry_policy()
        self.assertEqual(geometry["version"], "1")
        self.assertEqual(geometry["fixture_set"], "heresy-geom-conformance/v1")

    def test_v2_requires_indivisible_exact_schema(self) -> None:
        policy = v2_policy()
        normalized = normalize_policy(policy)
        self.assertEqual(normalized["geometry"]["version"], "2")
        self.assertEqual(normalized["geometry"]["fixture_set"], FIXTURE_SET_V2)
        self.assertEqual(normalized["geometry"]["forman"]["learning"], "forbidden")

        broken = copy.deepcopy(policy)
        del broken["geometry"]["forman"]["max_window_l1"]
        with self.assertRaises(HeresySecError) as raised:
            normalize_policy(broken)
        self.assertEqual(raised.exception.code, "GEOMETRY_POLICY_INVALID")

    def test_t2f_learning_field_is_a_hard_fail(self) -> None:
        policy = v2_policy()
        policy["geometry"]["forman"]["learning"] = "enabled"
        with self.assertRaises(HeresySecError) as raised:
            normalize_policy(policy)
        self.assertEqual(
            raised.exception.code,
            "GEOMETRY_FORMAN_LEARNING_FORBIDDEN",
        )

    def test_weighted_mode_requires_a_nonempty_pinned_map(self) -> None:
        policy = v2_policy()
        policy["geometry"]["forman"]["mode"] = "weighted"
        with self.assertRaises(HeresySecError) as raised:
            normalize_policy(policy)
        self.assertEqual(raised.exception.code, "GEOMETRY_POLICY_INVALID")


class FormanResolveFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURES.read_text(encoding="utf-8"))

    def test_fixture_set_is_profile_v2(self) -> None:
        self.assertEqual(self.fixture["fixture_set"], FIXTURE_SET_V2)

    def test_t2a_unweighted_forman_matches_frozen_profile(self) -> None:
        geometry = default_forman_resolve_policy()
        for row in self.fixture["unweighted"]:
            with self.subTest(name=row["name"]):
                curvature = build_forman_curvature_v2(
                    graph_from_fixture(row),
                    geometry,
                    role="short",
                )
                self.assertEqual(
                    [item["forman"] for item in curvature["entries"]],
                    row["expected_forman"],
                )

    def test_t2b_weighted_forman_matches_pinned_map(self) -> None:
        geometry = default_forman_resolve_policy()
        geometry["forman"] = {
            **geometry["forman"],
            "mode": "weighted",
            "weight_map": self.fixture["weighted"]["weight_map"],
        }
        row = self.fixture["weighted"]["fixture"]
        curvature = build_forman_curvature_v2(
            graph_from_fixture(row),
            geometry,
            role="long",
        )
        self.assertEqual(
            [item["weight"] for item in curvature["entries"]],
            row["expected_weights"],
        )
        self.assertEqual(
            [item["forman"] for item in curvature["entries"]],
            row["expected_forman"],
        )


class FormanResolveRunTests(unittest.TestCase):
    def test_t2c_dual_windows_are_bit_identical_under_replay(self) -> None:
        policy = v2_policy()
        policy["geometry"]["window"] = {"short": 2, "long": 4, "stride": 2}
        policy["geometry"]["max_spectral_l2_delta"] = 1_000_000_000
        policy["geometry"]["forman"]["max_window_l1"] = 1_000_000
        raw_policy = canonical_bytes(normalize_policy(policy)) + b"\n"
        raw_actions = raw_stream(action_stream(6))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, first_summary = run_actions(
                raw_actions,
                raw_policy,
                root,
                run_name="first",
            )
            second, second_summary = run_actions(
                raw_actions,
                raw_policy,
                root,
                run_name="second",
            )
            self.assertEqual(first_summary["geometry_profile"], PROFILE_V2)
            self.assertEqual(first_summary["geometry_window_count"], 3)
            self.assertEqual(
                (first / "geometry/000002/short/curvature.json").read_bytes(),
                (second / "geometry/000002/short/curvature.json").read_bytes(),
            )
            self.assertEqual(
                (first / "geometry/000002/long/spectral.json").read_bytes(),
                (second / "geometry/000002/long/spectral.json").read_bytes(),
            )
            self.assertEqual(
                (first / "geometry/000002/bundle.json").read_bytes(),
                (second / "geometry/000002/bundle.json").read_bytes(),
            )
            self.assertEqual(replay_run(first)["status"], "PASS")
            self.assertEqual(verify_run_directory(second)["status"], "PASS")
            self.assertEqual(
                first_summary["head_geometry_receipt_sha256"],
                second_summary["head_geometry_receipt_sha256"],
            )

    def test_t2d_single_edge_abs_threshold_trips_registry(self) -> None:
        fixture = json.loads(FIXTURES.read_text(encoding="utf-8"))["thresholds"]["edge_abs"]
        policy = v2_policy()
        policy["geometry"]["window"] = {"short": 6, "long": 6, "stride": 6}
        policy["geometry"]["forman"]["max_abs"] = fixture["max_abs"]
        policy["geometry"]["forman"]["max_window_l1"] = fixture["max_window_l1"]
        policy["geometry"]["max_spectral_l2_delta"] = 1_000_000_000

        with tempfile.TemporaryDirectory() as temporary:
            run_dir, summary = run_actions(
                raw_stream(action_stream(fixture["action_count"])),
                canonical_bytes(normalize_policy(policy)) + b"\n",
                Path(temporary),
            )
            curvature = parse_json_bytes(
                (run_dir / "geometry/000000/long/curvature.json").read_bytes()
            )
            registry = parse_json_bytes(
                (run_dir / "geometry/000000/impossible-configurations.json").read_bytes()
            )
            self.assertTrue(curvature["abs_threshold_trips"])
            self.assertFalse(curvature["window_l1_trip"])
            self.assertIn(
                "FORMAN_THRESHOLD_TRIP",
                {item["obstruction_type"] for item in registry["obstructions"]},
            )
            self.assertEqual(summary["final_state"], "DENIED")

    def test_t2e_distributed_window_l1_trips_without_edge_trip(self) -> None:
        fixture = json.loads(FIXTURES.read_text(encoding="utf-8"))["thresholds"]["window_l1"]
        policy = v2_policy()
        policy["geometry"]["window"] = {"short": 5, "long": 5, "stride": 5}
        policy["geometry"]["forman"]["max_abs"] = fixture["max_abs"]
        policy["geometry"]["forman"]["max_window_l1"] = fixture["max_window_l1"]
        policy["geometry"]["max_spectral_l2_delta"] = 1_000_000_000

        with tempfile.TemporaryDirectory() as temporary:
            run_dir, summary = run_actions(
                raw_stream(action_stream(fixture["action_count"])),
                canonical_bytes(normalize_policy(policy)) + b"\n",
                Path(temporary),
            )
            curvature = parse_json_bytes(
                (run_dir / "geometry/000000/long/curvature.json").read_bytes()
            )
            registry = parse_json_bytes(
                (run_dir / "geometry/000000/impossible-configurations.json").read_bytes()
            )
            self.assertEqual(curvature["abs_threshold_trips"], [])
            self.assertTrue(curvature["window_l1_trip"])
            trips = [
                item
                for item in registry["obstructions"]
                if item["obstruction_type"] == "FORMAN_THRESHOLD_TRIP"
            ]
            self.assertTrue(trips)
            self.assertTrue(all("window_l1" in item["threshold_kind"] for item in trips))
            self.assertEqual(summary["final_state"], "DENIED")

    def test_weighted_action_without_policy_weight_fails_closed(self) -> None:
        policy = v2_policy()
        policy["geometry"]["forman"]["mode"] = "weighted"
        policy["geometry"]["forman"]["weight_map"] = {"network.send": 3}
        raw_policy = canonical_bytes(normalize_policy(policy)) + b"\n"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(HeresySecError) as raised:
                run_actions(
                    raw_stream(action_stream(1)),
                    raw_policy,
                    Path(temporary),
                )
        self.assertEqual(
            raised.exception.code,
            "GEOMETRY_FORMAN_WEIGHT_MISSING",
        )

    def test_t2g_companion_atoms_are_mandatory_and_tamper_evident(self) -> None:
        policy = v2_policy()
        policy["geometry"]["window"] = {"short": 2, "long": 4, "stride": 2}
        policy["geometry"]["max_spectral_l2_delta"] = 1_000_000_000
        policy["geometry"]["forman"]["max_window_l1"] = 1_000_000

        with tempfile.TemporaryDirectory() as temporary:
            run_dir, _ = run_actions(
                raw_stream(action_stream(4)),
                canonical_bytes(normalize_policy(policy)) + b"\n",
                Path(temporary),
            )
            evidence_path = run_dir / "geometry/000001/evidence-manifest.json"
            evidence = parse_json_bytes(evidence_path.read_bytes())
            kinds = {atom["kind"] for atom in evidence["atoms"]}
            required = {
                "SHORT_FORMAN",
                "SHORT_SPECTRAL",
                "SHORT_HOLONOMY",
                "LONG_FORMAN",
                "LONG_SPECTRAL",
                "LONG_HOLONOMY",
            }
            self.assertTrue(required <= kinds)
            self.assertEqual(evidence["N_missing"], 0)

            evidence["atoms"] = [
                atom for atom in evidence["atoms"] if atom["kind"] != "SHORT_SPECTRAL"
            ]
            evidence["atom_count"] = len(evidence["atoms"])
            evidence["N_missing"] = 1
            evidence["missing_companion_kinds"] = ["SHORT_SPECTRAL"]
            evidence_path.write_bytes(canonical_bytes(evidence))

            files = {
                path.relative_to(run_dir).as_posix(): path.read_bytes()
                for path in run_dir.rglob("*")
                if path.is_file() and path.name != "manifest.json"
            }
            manifest = parse_json_bytes((run_dir / "manifest.json").read_bytes())
            (run_dir / "manifest.json").write_bytes(build_manifest(files, manifest["run_id"]))

            with self.assertRaises(HeresySecError) as raised:
                verify_run_directory(run_dir)
            self.assertEqual(
                raised.exception.code,
                "GEOMETRY_ARTIFACT_MISMATCH",
            )


if __name__ == "__main__":
    unittest.main()
