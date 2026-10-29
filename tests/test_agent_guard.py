"""
AgentGuard runtime-check tests.

assert_safe must evaluate guards with the standalone checker's
semantics: guards are parsed to canonical DNF over atoms, state keys
address atoms by exact identity (raw or canonical text), and atoms
missing from the state default to False.  Regression coverage for the
old substring evaluator, which treated any condition whose text
contained "false" (e.g. an atom named false_start_ok) as disabled and
defaulted unknown atoms by name shape.

protect() must actually gate on the audit, and audit_graph() must
return the standalone result shape backed by the real engine.
"""

import os
import sys
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PYTHON_DIR = os.path.join(ROOT_DIR, "python")
if PYTHON_DIR not in sys.path:
    sys.path.insert(0, PYTHON_DIR)

from sharplogic import AgentGuard, audit_graph  # noqa: E402
from sharplogic.agent_guard import AgentInvariantViolation  # noqa: E402

WORKFLOW = {
    "nodes": ["Tool_Executor", "Critic_Fallback", "Human_Approval_Gate"],
    "terminals": ["Human_Approval_Gate"],
    "edges": [
        {"from": "Tool_Executor", "to": "Critic_Fallback", "condition": ""},
        {"from": "Tool_Executor", "to": "Human_Approval_Gate", "condition": "not tool_timeout and not execution_error"},
        {"from": "Critic_Fallback", "to": "Tool_Executor", "condition": "retry_prompt_generated and retry_count <= 3"},
        {"from": "Critic_Fallback", "to": "Human_Approval_Gate", "condition": "not retry_prompt_generated or retry_count > 3"},
    ],
}


class TestAssertSafeSemantics(unittest.TestCase):
    def test_atom_named_with_false_substring(self):
        g = AgentGuard(graph={
            "nodes": ["A", "B"], "terminals": ["B"],
            "edges": [{"from": "A", "to": "B", "condition": "false_start_ok"}],
        })
        self.assertTrue(g.assert_safe("A", "B", state={"false_start_ok": True}))
        # Absent from state -> defaults to False -> transition disabled.
        with self.assertRaises(AgentInvariantViolation):
            g.assert_safe("A", "B", state={})

    def test_comparison_atoms_share_one_atom_across_spellings(self):
        g = AgentGuard(graph={
            "nodes": ["A", "B"], "terminals": ["B"],
            "edges": [{"from": "A", "to": "B", "condition": "retry_count <= 3"}],
        })
        self.assertTrue(g.assert_safe("A", "B", state={"retry_count > 3": False}))
        with self.assertRaises(AgentInvariantViolation):
            g.assert_safe("A", "B", state={"retry_count > 3": True})
        self.assertTrue(g.assert_safe("A", "B", retry_count=2))
        with self.assertRaises(AgentInvariantViolation):
            g.assert_safe("A", "B", retry_count=5)

    def test_readme_quick_start_transition(self):
        g = AgentGuard(graph=WORKFLOW)
        self.assertTrue(
            g.assert_safe(
                "Critic_Fallback", "Tool_Executor",
                state={"retry_prompt_generated": True}, retry_count=2,
            )
        )
        with self.assertRaises(AgentInvariantViolation):
            g.assert_safe(
                "Critic_Fallback", "Tool_Executor",
                state={"retry_prompt_generated": True}, retry_count=9,
            )

    def test_destination_deadlock_is_caught(self):
        g = AgentGuard(graph={
            "nodes": ["A", "B", "C"], "terminals": ["C"],
            "edges": [
                {"from": "A", "to": "B", "condition": ""},
                {"from": "B", "to": "C", "condition": "flag_x"},
            ],
        })
        with self.assertRaises(AgentInvariantViolation):
            g.assert_safe("A", "B", state={})
        self.assertTrue(g.assert_safe("A", "B", state={"flag_x": True}))


class TestProtectAndAuditGraph(unittest.TestCase):
    def test_protect_blocks_trapped_workflow(self):
        trapped = AgentGuard(graph={
            "nodes": ["A", "B"], "terminals": ["B"],
            "edges": [
                {"from": "A", "to": "B", "condition": "flag_x"},
                {"from": "A", "to": "A", "condition": "flag_y"},
            ],
        })
        ran = []

        @trapped.protect
        def route():
            ran.append(True)
            return "ran"

        with self.assertRaises(AgentInvariantViolation):
            route()
        self.assertEqual(ran, [])  # the wrapped function never executed

    def test_protect_passes_clean_workflow_and_records_history(self):
        clean = AgentGuard(graph=WORKFLOW)

        @clean.protect
        def route():
            return "ran"

        self.assertEqual(route(), "ran")
        self.assertEqual(len(clean._history), 1)

    def test_audit_graph_shape_and_count(self):
        res = audit_graph(WORKFLOW)
        self.assertEqual(res["exact_count"], 0)
        self.assertEqual(res["condition_variables"], 4)
        self.assertEqual(res["total_assignments"], 16)
        self.assertIsNone(res["witness"])

        trapped = audit_graph({
            "nodes": ["A", "B"], "terminals": ["B"],
            "edges": [{"from": "A", "to": "B", "condition": "flag_x"}],
        })
        self.assertEqual(trapped["exact_count"], 1)
        self.assertIsNotNone(trapped["witness"])


if __name__ == "__main__":
    unittest.main()
