from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CliAndExampleTests(unittest.TestCase):
    def command(self, *args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "heresy_sec", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_init_run_verify_replay_quick_start(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            demo = root / "demo"
            init = self.command("init", str(demo))
            self.assertEqual(init.returncode, 0, init.stderr)
            run = self.command(
                "run",
                str(demo / "action.json"),
                "--policy",
                str(demo / "policy.json"),
                "--runs-dir",
                str(root / "runs"),
                "--run-name",
                "quick-start",
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            report = json.loads(run.stdout)
            verify = self.command("verify", report["run_directory"])
            replay = self.command("replay", report["run_directory"])
            self.assertEqual(verify.returncode, 0, verify.stderr)
            self.assertEqual(replay.returncode, 0, replay.stderr)

    def test_unknown_command_error_is_json(self) -> None:
        result = self.command("not-a-command")
        self.assertEqual(result.returncode, 2)
        error = json.loads(result.stderr)
        self.assertEqual(error["error_code"], "CLI_ARGUMENT_INVALID")

    def test_output_path_failure_is_canonical_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runs_file = root / "runs"
            runs_file.write_text("preserve", encoding="utf-8")
            result = self.command(
                "run",
                str(ROOT / "examples" / "file_integrity" / "action.json"),
                "--policy",
                str(ROOT / "examples" / "file_integrity" / "policy.json"),
                "--runs-dir",
                str(runs_file),
                "--run-name",
                "controlled-error",
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            error = json.loads(result.stderr)
            self.assertEqual(error["error_code"], "OUTPUT_PATH_UNSAFE")
            self.assertEqual(runs_file.read_text(encoding="utf-8"), "preserve")

    def test_examples_have_expected_effects(self) -> None:
        expected = {
            "file_integrity": ("ALLOWED", 0),
            "network_constraint": ("DENIED", 3),
            "process_boundary": ("DENIED", 3),
            "ipc_slot_management": ("DENIED", 3),
        }
        with tempfile.TemporaryDirectory() as directory:
            runs = Path(directory) / "runs"
            for name, (state, exit_code) in expected.items():
                base = ROOT / "examples" / name
                result = self.command(
                    "run",
                    str(base / "action.json"),
                    "--policy",
                    str(base / "policy.json"),
                    "--runs-dir",
                    str(runs),
                    "--run-name",
                    name,
                )
                self.assertEqual(result.returncode, exit_code, result.stderr)
                self.assertEqual(json.loads(result.stdout)["final_state"], state)


if __name__ == "__main__":
    unittest.main()
