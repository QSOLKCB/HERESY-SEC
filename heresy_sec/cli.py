"""Command-line interface for HERESY-SEC."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .archive import pack_run
from .canonical import canonical_json
from .engine import (
    init_demo,
    inspect_run,
    replay_run,
    run_action_file,
    run_jsonl_file,
    validate_files,
    verify_run_directory,
)
from .errors import HeresySecError
from .selftest import run_selftest


class ControlledParser(argparse.ArgumentParser):
    def error(self, message: str) -> "None":
        raise HeresySecError("CLI_ARGUMENT_INVALID", message)


def _parser() -> ControlledParser:
    parser = ControlledParser(
        prog="heresy-sec",
        description="Deterministic policy receipts and exact replay for AI-agent actions.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create a runnable demonstration")
    init.add_argument("directory", nargs="?", default="demo")

    validate = sub.add_parser("validate", help="validate an action and policy")
    validate.add_argument("action")
    validate.add_argument("--policy", required=True)

    run = sub.add_parser("run", help="evaluate one action")
    run.add_argument("action")
    run.add_argument("--policy", required=True)
    run.add_argument("--runs-dir", default="runs")
    run.add_argument("--run-name")

    monitor = sub.add_parser("monitor", help="evaluate an ordered JSONL action stream")
    monitor.add_argument("events")
    monitor.add_argument("--policy", required=True)
    monitor.add_argument("--runs-dir", default="runs")
    monitor.add_argument("--run-name")

    verify = sub.add_parser("verify", help="verify hashes, lineage and artifact structure")
    verify.add_argument("run")

    replay = sub.add_parser("replay", help="recompute decisions and receipts exactly")
    replay.add_argument("run")

    inspect = sub.add_parser("inspect", help="show a verified run summary")
    inspect.add_argument("run")

    pack = sub.add_parser("pack", help="create a deterministic ZIP_STORED archive")
    pack.add_argument("run")
    pack.add_argument("--output")

    sub.add_parser("selftest", help="run installed-artifact checks")

    size = sub.add_parser("size", help="report an artifact's size")
    size.add_argument("artifact", nargs="?", default="dist/heresy_sec.pyz")
    return parser


def _emit(value: object, *, stream: object = sys.stdout) -> None:
    print(canonical_json(value), file=stream)


def _decision_exit(report: dict[str, object]) -> int:
    state = report.get("final_state")
    if state == "DENIED":
        return 3
    if state == "REVIEW_REQUIRED":
        return 4
    return 0


def _dispatch(args: argparse.Namespace) -> int:
    command = args.command
    if command == "init":
        _emit(init_demo(Path(args.directory)))
        return 0
    if command == "validate":
        _emit(validate_files(Path(args.action), Path(args.policy)))
        return 0
    if command == "run":
        _, report = run_action_file(
            Path(args.action),
            Path(args.policy),
            Path(args.runs_dir),
            run_name=args.run_name,
        )
        _emit(report)
        return _decision_exit(report)
    if command == "monitor":
        _, report = run_jsonl_file(
            Path(args.events),
            Path(args.policy),
            Path(args.runs_dir),
            run_name=args.run_name,
        )
        _emit(report)
        return _decision_exit(report)
    if command == "verify":
        _emit(verify_run_directory(Path(args.run)))
        return 0
    if command == "replay":
        _emit(replay_run(Path(args.run)))
        return 0
    if command == "inspect":
        _emit(inspect_run(Path(args.run)))
        return 0
    if command == "pack":
        _emit(pack_run(Path(args.run), Path(args.output) if args.output else None))
        return 0
    if command == "selftest":
        _emit(run_selftest())
        return 0
    if command == "size":
        path = Path(args.artifact)
        if not path.is_file() or path.is_symlink():
            raise HeresySecError("SIZE_ARTIFACT_MISSING", f"artifact does not exist: {path}")
        size = path.stat().st_size
        _emit({"status": "PASS", "path": str(path), "byte_length": size})
        return 0
    raise HeresySecError("CLI_ARGUMENT_INVALID", "unsupported command")


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        return _dispatch(args)
    except HeresySecError as exc:
        _emit(
            {"status": "ERROR", "error_code": exc.code, "message": exc.message},
            stream=sys.stderr,
        )
        return exc.exit_code
    except KeyboardInterrupt:
        _emit(
            {
                "status": "ERROR",
                "error_code": "INTERRUPTED",
                "message": "operation interrupted",
            },
            stream=sys.stderr,
        )
        return 130

