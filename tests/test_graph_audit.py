"""
Graph trap-audit tests: the compiler must encode real trap semantics.

Each graph's expected #F below was derived by hand from the semantics
(a trap assignment is a valuation of the guard atoms under which a
reachable non-terminal node has every exit disabled, or a reachable
cycle/region has every exit disabled; complementary-guard retry loops
are guarded, and terminal nodes are absorbing).

Also covers the engine's loud limits: formulas past MAX_VARS variables
must raise, never silently truncate.
"""

import json
import os
import sys
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PYTHON_DIR = os.path.join(ROOT_DIR, "python")
if PYTHON_DIR not in sys.path:
    sys.path.insert(0, PYTHON_DIR)

from sharplogic import RustSharpLogicEngine, evaluate_custom_rules  # noqa: E402
from sharplogic.compiler import Autoformalizer  # noqa: E402


def audit(graph):
    return evaluate_custom_rules(json.dumps(graph))


class TestGraphTrapAudit(unittest.TestCase):
    def test_dag_with_complementary_guards_is_clean(self):
        g = {
            "nodes": [{"id": n} for n in ["start", "decide", "fast", "slow", "merge", "END"]],
            "edges": [
                {"source": "start", "target": "decide", "condition": ""},
                {"source": "decide", "target": "fast", "condition": "is_high_priority"},
                {"source": "decide", "target": "slow", "condition": "not is_high_priority"},
                {"source": "fast", "target": "merge", "condition": ""},
                {"source": "slow", "target": "merge", "condition": ""},
                {"source": "merge", "target": "END", "condition": ""},
            ],
        }
        res = audit(g)
        self.assertEqual(res["audit"]["exact_count"], 0)

    def test_dag_with_forgotten_branch_is_a_trap(self):
        # Two independent guard atoms: when both are false the decide
        # node has no enabled exit (the forgotten "medium" case).
        g = {
            "nodes": [{"id": n} for n in ["start", "decide", "fast", "slow", "merge", "END"]],
            "edges": [
                {"source": "start", "target": "decide", "condition": ""},
                {"source": "decide", "target": "fast", "condition": "priority == 'high'"},
                {"source": "decide", "target": "slow", "condition": "priority == 'low'"},
                {"source": "fast", "target": "merge", "condition": ""},
                {"source": "slow", "target": "merge", "condition": ""},
                {"source": "merge", "target": "END", "condition": ""},
            ],
        }
        res = audit(g)
        self.assertEqual(res["audit"]["exact_count"], 1)
        self.assertTrue(any("decide" in w for w in res["trap_witness"]))

    def test_self_loop_retry_counts_deadlock_and_livelock(self):
        # worker: exit needs is_done, loop needs should_retry.
        # deadlock: both false (1); livelock: retry true, done false (1).
        g = {
            "nodes": [{"id": n} for n in ["start", "worker", "END"]],
            "edges": [
                {"source": "start", "target": "worker", "condition": ""},
                {"source": "worker", "target": "worker", "condition": "should_retry"},
                {"source": "worker", "target": "END", "condition": "is_done"},
            ],
        }
        res = audit(g)
        self.assertEqual(res["audit"]["exact_count"], 2)

    def test_dead_end_graph(self):
        # flag_x false -> stuck at A; flag_x true -> reaches sink C.
        g = {
            "nodes": [{"id": n} for n in ["A", "B", "C"]],
            "edges": [
                {"source": "A", "target": "B", "condition": "flag_x"},
                {"source": "B", "target": "C", "condition": ""},
            ],
        }
        res = audit(g)
        self.assertEqual(res["audit"]["exact_count"], 2)
        types = {f["type"] for f in res["graph_analysis"]["findings"]}
        self.assertIn("dead_end", types)

    def test_single_node_graph_is_sane(self):
        res = audit({"nodes": [{"id": "only_node"}], "edges": []})
        self.assertEqual(res["audit"]["exact_count"], 0)

    def test_guarded_retry_is_clean(self):
        # Bounded retry: loop while retry_count < 3, exit when >= 3.
        g = {
            "nodes": [{"id": n} for n in ["start", "attempt", "END"]],
            "edges": [
                {"source": "start", "target": "attempt", "condition": ""},
                {"source": "attempt", "target": "attempt", "condition": "retry_count < 3"},
                {"source": "attempt", "target": "END", "condition": "retry_count >= 3"},
            ],
        }
        res = audit(g)
        self.assertEqual(res["audit"]["exact_count"], 0)
        types = {f["type"] for f in res["graph_analysis"]["findings"]}
        self.assertIn("guarded_cycle", types)

    def test_unguarded_retry_has_traps(self):
        # Exit guarded by the same condition as the loop: when it is
        # false both exits are disabled -> exactly one trap assignment.
        g = {
            "nodes": [{"id": n} for n in ["start", "attempt", "END"]],
            "edges": [
                {"source": "start", "target": "attempt", "condition": ""},
                {"source": "attempt", "target": "attempt", "condition": "retry_count < 3"},
                {"source": "attempt", "target": "END", "condition": "retry_count < 3"},
            ],
        }
        res = audit(g)
        self.assertEqual(res["audit"]["exact_count"], 1)


class TestLoudLimits(unittest.TestCase):
    def test_bridge_rejects_oversized_formula(self):
        eng = RustSharpLogicEngine()
        try:
            with self.assertRaises(ValueError):
                eng.solve_cnf(65, [[1]], [0.5] * 65)
        finally:
            eng.close()

    def test_bridge_rejects_out_of_range_literal(self):
        eng = RustSharpLogicEngine()
        try:
            with self.assertRaises(ValueError):
                eng.solve_cnf(3, [[7]], [0.5] * 3)
        finally:
            eng.close()

    def test_compiler_rejects_graph_beyond_variable_limit(self):
        # A wide router graph whose trap encoding needs > 64 variables.
        nodes = [{"id": "start"}, {"id": "router"}, {"id": "END"}] + [
            {"id": f"tool_{i}"} for i in range(60)
        ]
        edges = [{"source": "start", "target": "router", "condition": ""}]
        for i in range(60):
            edges.append(
                {"source": "router", "target": f"tool_{i}", "condition": f"use_tool_{i}"}
            )
            edges.append({"source": f"tool_{i}", "target": "END", "condition": ""})
        with self.assertRaises(ValueError):
            Autoformalizer.compile_custom_rules(
                json.dumps({"nodes": nodes, "edges": edges})
            )


if __name__ == "__main__":
    unittest.main()
