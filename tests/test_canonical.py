from __future__ import annotations

import unittest

from heresy_sec.canonical import (
    MAX_JSON_NESTING,
    canonical_bytes,
    canonical_json,
    domain_hash,
    parse_json_bytes,
)
from heresy_sec.errors import HeresySecError


class CanonicalTests(unittest.TestCase):
    def test_known_canonical_json(self) -> None:
        value = {"z": {"n": None, "b": True}, "a": [3, 2, 1]}
        self.assertEqual(canonical_json(value), '{"a":[3,2,1],"z":{"b":true,"n":null}}')
        self.assertEqual(canonical_bytes(value), canonical_json(value).encode("utf-8"))

    def test_dictionary_order_is_irrelevant_but_list_order_is_preserved(self) -> None:
        self.assertEqual(canonical_bytes({"b": 2, "a": 1}), canonical_bytes({"a": 1, "b": 2}))
        self.assertNotEqual(canonical_bytes([1, 2]), canonical_bytes([2, 1]))

    def test_domain_separation(self) -> None:
        self.assertNotEqual(domain_hash("A", {"x": 1}), domain_hash("B", {"x": 1}))

    def test_float_duplicate_key_and_trailing_data_rejected(self) -> None:
        cases = (
            b'{"x":1.0}',
            b'{"x":1,"x":2}',
            b'{"x":1}{"y":2}',
        )
        for body in cases:
            with self.subTest(body=body), self.assertRaises(HeresySecError):
                parse_json_bytes(body)

    def test_json_whitespace_is_symmetric_and_non_json_whitespace_is_rejected(self) -> None:
        value = {"nested": [1, 2, 3]}
        self.assertEqual(
            parse_json_bytes(b" \t\r\n" + canonical_bytes(value) + b"\r\n\t "),
            value,
        )
        with self.assertRaises(HeresySecError) as leading_non_json_whitespace:
            parse_json_bytes("\u00a0{}".encode("utf-8"))
        self.assertEqual(leading_non_json_whitespace.exception.code, "JSON_INVALID")
        with self.assertRaises(HeresySecError) as trailing_non_json_whitespace:
            parse_json_bytes("{}\u00a0".encode("utf-8"))
        self.assertEqual(
            trailing_non_json_whitespace.exception.code,
            "JSON_TRAILING_DATA",
        )

    def test_excessive_json_nesting_is_a_controlled_failure(self) -> None:
        permitted = b"[" * MAX_JSON_NESTING + b"0" + b"]" * MAX_JSON_NESTING
        self.assertEqual(
            parse_json_bytes(permitted),
            self._nested_list(MAX_JSON_NESTING),
        )
        excessive = b"[" * (MAX_JSON_NESTING + 1) + b"0" + b"]" * (
            MAX_JSON_NESTING + 1
        )
        with self.assertRaises(HeresySecError) as raised:
            parse_json_bytes(excessive)
        self.assertEqual(raised.exception.code, "JSON_NESTING_TOO_DEEP")

        hostile = b"[" * 2000 + b"0" + b"]" * 2000
        with self.assertRaises(HeresySecError) as hostile_raised:
            parse_json_bytes(hostile)
        self.assertEqual(hostile_raised.exception.code, "JSON_NESTING_TOO_DEEP")

    @staticmethod
    def _nested_list(depth: int) -> object:
        value: object = 0
        for _ in range(depth):
            value = [value]
        return value

    def test_non_string_key_cycle_and_unsafe_integer_rejected(self) -> None:
        with self.assertRaises(HeresySecError):
            canonical_bytes({1: "bad"})
        cycle: list[object] = []
        cycle.append(cycle)
        with self.assertRaises(HeresySecError):
            canonical_bytes(cycle)
        with self.assertRaises(HeresySecError):
            canonical_bytes({"x": 2**53})


if __name__ == "__main__":
    unittest.main()
