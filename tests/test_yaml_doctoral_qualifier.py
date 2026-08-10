from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "adversarial" / "yaml-doctoral-qualifier"
MANIFEST = CORPUS / "manifest.json"
ASSEMBLER_PATH = CORPUS / "assemble.py"

_spec = importlib.util.spec_from_file_location("yaml_doctoral_qualifier_assembler", ASSEMBLER_PATH)
assert _spec is not None and _spec.loader is not None
ASSEMBLER = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ASSEMBLER)


class YamlDoctoralQualifierTests(unittest.TestCase):
    def _manifest(self) -> dict[str, object]:
        return ASSEMBLER.parse_manifest(MANIFEST.read_bytes())

    def _assembled(self) -> bytes:
        payload, _ = ASSEMBLER.assemble()
        return payload

    def test_corpus_identity_is_pinned(self) -> None:
        payload, manifest = ASSEMBLER.assemble()
        expected = manifest["assembled"]

        self.assertEqual(len(payload), expected["bytes"])
        self.assertEqual(ASSEMBLER.line_count(payload), expected["lines"])
        self.assertEqual(ASSEMBLER._sha256(payload), expected["sha256"])

    def test_line_count_has_explicit_physical_line_semantics(self) -> None:
        self.assertEqual(ASSEMBLER.line_count(b""), 0)
        self.assertEqual(ASSEMBLER.line_count(b"one"), 1)
        self.assertEqual(ASSEMBLER.line_count(b"one\n"), 1)
        self.assertEqual(ASSEMBLER.line_count(b"one\ntwo"), 2)
        self.assertEqual(ASSEMBLER.line_count(b"one\ntwo\n"), 2)

    def test_manifest_parser_fails_closed(self) -> None:
        malformed = [
            b'{"schema":"heresy-sec.defensive-corpus/v1","schema":"duplicate"}',
            b'{"float":1.5}',
            b'{"unsafe_integer":9007199254740992}',
        ]
        for raw in malformed:
            with self.subTest(raw=raw), self.assertRaises(SystemExit):
                ASSEMBLER.parse_manifest(raw)

        raw = MANIFEST.read_bytes().rstrip()
        self.assertTrue(raw.endswith(b"}"))
        with self.assertRaises(SystemExit):
            ASSEMBLER.parse_manifest(raw[:-1] + b',"unexpected":true}')

    def test_part_paths_are_confined_to_regular_source_children(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            good = source / "part-01.yaml.part"
            good.write_bytes(b"fixture")

            self.assertEqual(
                ASSEMBLER._validated_part_path(root, source, "source/part-01.yaml.part"),
                good,
            )

            for bad in (
                "../outside.yaml.part",
                "source/../outside.yaml.part",
                "/tmp/outside.yaml.part",
                "source/nested/part.yaml.part",
                "source/./part-01.yaml.part",
            ):
                with self.subTest(path=bad), self.assertRaises(SystemExit):
                    ASSEMBLER._validated_part_path(root, source, bad)

            outside = root / "outside.yaml.part"
            outside.write_bytes(b"external")
            link = source / "linked.yaml.part"
            link.symlink_to(outside)
            with self.assertRaises(SystemExit):
                ASSEMBLER._validated_part_path(root, source, "source/linked.yaml.part")

    def test_output_is_exclusive_and_preserves_existing_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            existing = root / "existing.yaml"
            existing.write_bytes(b"KEEP")

            with self.assertRaises(SystemExit):
                ASSEMBLER.write_new_output(existing, b"REPLACE")
            self.assertEqual(existing.read_bytes(), b"KEEP")

            target = root / "target.yaml"
            link = root / "linked.yaml"
            link.symlink_to(target)
            with self.assertRaises(SystemExit):
                ASSEMBLER.write_new_output(link, b"REPLACE")
            self.assertFalse(target.exists())

            new_output = root / "new.yaml"
            ASSEMBLER.write_new_output(new_output, b"NEW")
            self.assertEqual(new_output.read_bytes(), b"NEW")

    def test_canonical_exam_is_not_auto_discoverable_yaml(self) -> None:
        self.assertFalse((CORPUS / "EXAM.yaml").exists())
        self.assertEqual(
            sorted(path.suffix for path in (CORPUS / "source").iterdir()),
            [".part"] * 7,
        )

    def test_shards_are_git_pinned_as_binary(self) -> None:
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn(
            "/adversarial/yaml-doctoral-qualifier/source/*.yaml.part binary",
            attributes.splitlines(),
        )

    def test_unsafe_python_tag_examples_remain_comments(self) -> None:
        text = self._assembled().decode("utf-8")
        for line_number, line in enumerate(text.splitlines(), 1):
            if "!!python/" in line:
                self.assertTrue(
                    line.lstrip().startswith("#"),
                    f"unsafe Python tag became active on line {line_number}",
                )

    def test_exam_identity_and_candidate_instruction_are_present(self) -> None:
        text = self._assembled().decode("utf-8")
        self.assertIn("YAML DOCTORAL QUALIFYING EXAMINATION", text)
        self.assertIn(
            "This examination is open-specification. Confidence without justification",
            text,
        )
        self.assertIn("P11U  = PyYAML unsafe Loader/load()", text)
        self.assertIn("(the RCE museum — sandbox only)", text)


if __name__ == "__main__":
    unittest.main()
