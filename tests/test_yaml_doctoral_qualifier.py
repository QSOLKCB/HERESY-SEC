from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "adversarial" / "yaml-doctoral-qualifier"
MANIFEST = CORPUS / "manifest.json"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class YamlDoctoralQualifierTests(unittest.TestCase):
    def _manifest(self) -> dict[str, object]:
        return json.loads(MANIFEST.read_text(encoding="utf-8"))

    def _assembled(self) -> bytes:
        manifest = self._manifest()
        chunks = []
        for entry in manifest["parts"]:
            data = (CORPUS / entry["path"]).read_bytes()
            self.assertEqual(len(data), entry["bytes"])
            self.assertEqual(sha256(data), entry["sha256"])
            chunks.append(data)
        return b"".join(chunks)

    def test_corpus_identity_is_pinned(self) -> None:
        manifest = self._manifest()
        payload = self._assembled()
        expected = manifest["assembled"]
        line_count = payload.count(b"\n") + (0 if payload.endswith(b"\n") else 1)

        self.assertEqual(len(payload), expected["bytes"])
        self.assertEqual(line_count, expected["lines"])
        self.assertEqual(sha256(payload), expected["sha256"])

    def test_canonical_exam_is_not_auto_discoverable_yaml(self) -> None:
        self.assertFalse((CORPUS / "EXAM.yaml").exists())
        self.assertEqual(
            sorted(path.suffix for path in (CORPUS / "source").iterdir()),
            [".part"] * 7,
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
