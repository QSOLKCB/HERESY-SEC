from __future__ import annotations

import copy
import unittest

from heresy_sec.engine import demo_documents
from heresy_sec.policy import evaluate_action


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.action, self.policy = demo_documents()

    def test_safe_file_read_is_allowed(self) -> None:
        decision = evaluate_action(self.action, self.policy)
        self.assertEqual(decision["effect"], "ALLOW")
        self.assertEqual(decision["selected_rule_id"], "allow-demo-read")
        self.assertEqual(decision["reason_codes"], ["RULE_ALLOW"])

    def test_network_boundary_overrides_matching_allow_rule(self) -> None:
        action = copy.deepcopy(self.action)
        action.update(
            {
                "action_id": "network-attempt",
                "service": "network",
                "operation": "connect",
                "target": "https://forbidden.example/upload",
                "requested_authority": "NETWORK",
            }
        )
        policy = copy.deepcopy(self.policy)
        policy["rules"].append(
            {
                "schema": "heresy-sec.rule/v1",
                "rule_id": "allow-network-rule",
                "priority": 1000,
                "effect": "ALLOW",
                "services": ["network"],
                "operations": ["connect"],
                "target_prefixes": ["https://"],
                "agent_ids": ["*"],
                "authorities": ["*"],
            }
        )
        decision = evaluate_action(action, policy)
        self.assertEqual(decision["effect"], "DENY")
        self.assertIn("NETWORK_DISABLED", decision["reason_codes"])
        self.assertIn("AUTHORITY_NOT_GRANTED", decision["reason_codes"])
        self.assertIn("allow-network-rule", decision["matched_rule_ids"])

    def test_file_traversal_fails_closed(self) -> None:
        action = copy.deepcopy(self.action)
        action["action_id"] = "path-traversal"
        action["target"] = "workspace/../secrets.txt"
        decision = evaluate_action(action, self.policy)
        self.assertEqual(decision["effect"], "DENY")
        self.assertIn("FILE_TARGET_INVALID", decision["reason_codes"])

    def test_ipc_slot_boundary(self) -> None:
        action = copy.deepcopy(self.action)
        action.update(
            {
                "action_id": "invalid-ipc-slot",
                "service": "ipc",
                "operation": "allocate",
                "target": "ipc/control",
                "slot": 32,
            }
        )
        decision = evaluate_action(action, self.policy)
        self.assertEqual(decision["effect"], "DENY")
        self.assertEqual(decision["reason_codes"], ["IPC_SLOT_INVALID"])

    def test_equal_priority_conflict_fails_toward_deny(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["rules"].append(
            {
                "schema": "heresy-sec.rule/v1",
                "rule_id": "deny-same-priority",
                "priority": 100,
                "effect": "DENY",
                "services": ["file"],
                "operations": ["read"],
                "target_prefixes": ["workspace/"],
                "agent_ids": ["demo-agent"],
                "authorities": ["SIM_ONLY"],
            }
        )
        decision = evaluate_action(self.action, policy)
        self.assertEqual(decision["effect"], "DENY")
        self.assertEqual(decision["selected_rule_id"], "deny-same-priority")

    def test_model_kind_does_not_change_policy_semantics(self) -> None:
        open_decision = evaluate_action(self.action, self.policy)
        closed = copy.deepcopy(self.action)
        closed["producer"]["model_kind"] = "CLOSED"
        closed["producer"]["model_id"] = "closed/frontier-model"
        closed_decision = evaluate_action(closed, self.policy)
        self.assertEqual(open_decision["effect"], closed_decision["effect"])
        self.assertNotEqual(open_decision["action_sha256"], closed_decision["action_sha256"])


if __name__ == "__main__":
    unittest.main()

