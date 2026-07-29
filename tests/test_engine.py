from __future__ import annotations

import tempfile
import unittest
import zipfile
from io import BytesIO
from pathlib import Path

from heresy_sec.archive import deterministic_zip_bytes, pack_run
from heresy_sec.artifacts import safe_run_directory
from heresy_sec.canonical import canonical_bytes
from heresy_sec.engine import (
    demo_documents,
    inspect_run,
    replay_run,
    run_actions,
    verify_run_directory,
)
from heresy_sec.errors import HeresySecError


class EngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.action, self.policy = demo_documents()

    def test_complete_run_verifies_and_replays_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir, report = run_actions(
                [canonical_bytes(self.action) + b"\n"],
                canonical_bytes(self.policy) + b"\n",
                Path(directory),
                run_name="complete",
            )
            before = {
                path.relative_to(run_dir).as_posix(): path.read_bytes()
                for path in run_dir.rglob("*")
                if path.is_file()
            }
            verified = verify_run_directory(run_dir)
            replayed = replay_run(run_dir)
            after = {
                path.relative_to(run_dir).as_posix(): path.read_bytes()
                for path in run_dir.rglob("*")
                if path.is_file()
            }
            self.assertEqual(report["final_state"], "ALLOWED")
            self.assertEqual(verified["status"], "PASS")
            self.assertEqual(replayed["status"], "PASS")
            self.assertEqual(before, after)
            self.assertEqual(inspect_run(run_dir)["decisions"][0]["effect"], "ALLOW")

    def test_raw_capture_bytes_affect_run_identity(self) -> None:
        compact = canonical_bytes(self.action)
        spaced = compact + b"\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, first = run_actions([compact], canonical_bytes(self.policy), root, run_name="compact")
            _, second = run_actions([spaced], canonical_bytes(self.policy), root, run_name="spaced")
            self.assertNotEqual(first["run_id"], second["run_id"])
            first_action = (root / "compact" / "actions" / "000000.json").read_bytes()
            second_action = (root / "spaced" / "actions" / "000000.json").read_bytes()
            self.assertEqual(first_action, second_action)

    def test_tamper_and_undeclared_file_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir, _ = run_actions(
                [canonical_bytes(self.action)],
                canonical_bytes(self.policy),
                root,
                run_name="tamper",
            )
            (run_dir / "summary.json").write_bytes(b"{}\n")
            with self.assertRaises(HeresySecError):
                verify_run_directory(run_dir)

            run_dir, _ = run_actions(
                [canonical_bytes(self.action)],
                canonical_bytes(self.policy),
                root,
                run_name="extra",
            )
            (run_dir / "undeclared.txt").write_text("unexpected", encoding="utf-8")
            with self.assertRaises(HeresySecError):
                verify_run_directory(run_dir)

    def test_receipt_chain_for_multiple_actions(self) -> None:
        second = dict(self.action)
        second["action_id"] = "second-action"
        second["sequence"] = 1
        with tempfile.TemporaryDirectory() as directory:
            run_dir, report = run_actions(
                [canonical_bytes(self.action), canonical_bytes(second)],
                canonical_bytes(self.policy),
                Path(directory),
                run_name="chain",
            )
            self.assertEqual(report["action_count"], 2)
            lines = (run_dir / "event-log.jsonl").read_bytes().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(verify_run_directory(run_dir)["action_count"], 2)

    def test_duplicate_or_out_of_order_sequences_rejected(self) -> None:
        duplicate = dict(self.action)
        duplicate["action_id"] = "duplicate-sequence"
        later = dict(self.action)
        later.update({"action_id": "later", "sequence": 2})
        earlier = dict(self.action)
        earlier.update({"action_id": "earlier", "sequence": 1})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(HeresySecError):
                run_actions(
                    [canonical_bytes(self.action), canonical_bytes(duplicate)],
                    canonical_bytes(self.policy),
                    root,
                )
            with self.assertRaises(HeresySecError):
                run_actions(
                    [canonical_bytes(later), canonical_bytes(earlier)],
                    canonical_bytes(self.policy),
                    root,
                )

    def test_deterministic_archive_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir, _ = run_actions(
                [canonical_bytes(self.action)],
                canonical_bytes(self.policy),
                root,
                run_name="archive",
            )
            first = deterministic_zip_bytes(run_dir)
            second = deterministic_zip_bytes(run_dir)
            self.assertEqual(first, second)
            with zipfile.ZipFile(BytesIO(first)) as archive:
                self.assertEqual(archive.comment, b"")
                self.assertEqual(archive.namelist(), sorted(archive.namelist()))
                self.assertTrue(
                    all(item.date_time == (1980, 1, 1, 0, 0, 0) for item in archive.infolist())
                )
                self.assertTrue(
                    all(item.compress_type == zipfile.ZIP_STORED for item in archive.infolist())
                )
            packed = pack_run(run_dir)
            self.assertTrue(Path(packed["path"]).is_file())

    def test_unsafe_and_existing_output_paths_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(HeresySecError):
                safe_run_directory(root, "../escape")
            occupied = root / "occupied"
            occupied.mkdir()
            (occupied / "user-file").write_text("preserve", encoding="utf-8")
            with self.assertRaises(HeresySecError):
                safe_run_directory(root, "occupied")
            self.assertEqual((occupied / "user-file").read_text(encoding="utf-8"), "preserve")


if __name__ == "__main__":
    unittest.main()

