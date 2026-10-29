"""
Endpoint tests for POST /api/graph-audit (zero-friction browser trial).

The six fixture graphs are the same acceptance oracle as
tests/test_graph_audit.py: expected trap counts were derived by hand
from the trap semantics and are asserted here through the HTTP
dispatcher, so the endpoint is pinned to the real compiler/engine -
any canned or re-implemented verdict would drift from these numbers.

Graphs are sent in the AgentGuard shape (string node ids, from/to
edges, terminals list) - the shape the homepage trial UI posts.
"""

import itertools
import os
import sys
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PYTHON_DIR = os.path.join(ROOT_DIR, "python")
if PYTHON_DIR not in sys.path:
    sys.path.insert(0, PYTHON_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from server import dispatch_api_request  # noqa: E402

_IP_COUNTER = itertools.count(1)


def audit(graph):
    # Distinct client IPs keep the dispatcher's per-IP rate limiter
    # from coupling these tests to the rest of the suite.
    ip = f"10.7.0.{next(_IP_COUNTER)}"
    return dispatch_api_request(
        "POST", "/api/graph-audit", body={"graph": graph}, client_ip=ip
    )


class TestGraphAuditEndpoint(unittest.TestCase):
    def test_clean_dag_complementary_guards(self):
        g = {
            "nodes": ["start", "decide", "fast", "slow", "merge", "END"],
            "terminals": ["END"],
            "edges": [
                {"from": "start", "to": "decide", "condition": ""},
                {"from": "decide", "to": "fast", "condition": "is_high_priority"},
                {"from": "decide", "to": "slow", "condition": "not is_high_priority"},
                {"from": "fast", "to": "merge", "condition": ""},
                {"from": "slow", "to": "merge", "condition": ""},
                {"from": "merge", "to": "END", "condition": ""},
            ],
        }
        status, res = audit(g)
        self.assertEqual(status, 200)
        self.assertTrue(res["ok"])
        self.assertEqual(res["trap_count"], 0)
        self.assertEqual(res["total_assignments"], 2)
        self.assertEqual(res["verdict"], "clean")
        self.assertIsInstance(res["solve_time_us"], (int, float))

    def test_self_loop_counts_deadlock_and_livelock(self):
        g = {
            "nodes": ["start", "worker", "END"],
            "terminals": ["END"],
            "edges": [
                {"from": "start", "to": "worker", "condition": ""},
                {"from": "worker", "to": "worker", "condition": "should_retry"},
                {"from": "worker", "to": "END", "condition": "is_done"},
            ],
        }
        status, res = audit(g)
        self.assertEqual(status, 200)
        self.assertEqual(res["trap_count"], 2)
        self.assertEqual(res["total_assignments"], 4)
        self.assertEqual(res["verdict"], "traps_found")
        self.assertTrue(res["witnesses"])

    def test_dead_end_sink(self):
        g = {
            "nodes": ["A", "B", "C"],
            "edges": [
                {"from": "A", "to": "B", "condition": "flag_x"},
                {"from": "B", "to": "C", "condition": ""},
            ],
        }
        status, res = audit(g)
        self.assertEqual(status, 200)
        self.assertEqual(res["trap_count"], 2)
        types = {f["type"] for f in res["structural_issues"]}
        self.assertIn("dead_end", types)

    def test_guarded_retry_is_clean(self):
        g = {
            "nodes": ["start", "attempt", "END"],
            "terminals": ["END"],
            "edges": [
                {"from": "start", "to": "attempt", "condition": ""},
                {"from": "attempt", "to": "attempt", "condition": "retry_count < 3"},
                {"from": "attempt", "to": "END", "condition": "retry_count >= 3"},
            ],
        }
        status, res = audit(g)
        self.assertEqual(status, 200)
        self.assertEqual(res["trap_count"], 0)
        types = {f["type"] for f in res["structural_issues"]}
        self.assertIn("guarded_cycle", types)

    def test_unguarded_retry_has_one_trap(self):
        g = {
            "nodes": ["start", "attempt", "END"],
            "terminals": ["END"],
            "edges": [
                {"from": "start", "to": "attempt", "condition": ""},
                {"from": "attempt", "to": "attempt", "condition": "retry_count < 3"},
                {"from": "attempt", "to": "END", "condition": "retry_count < 3"},
            ],
        }
        status, res = audit(g)
        self.assertEqual(status, 200)
        self.assertEqual(res["trap_count"], 1)
        self.assertEqual(res["total_assignments"], 2)
        self.assertTrue(any("attempt" in w for w in res["witnesses"]))

    def test_single_node_empty_graph(self):
        status, res = audit({"nodes": ["only_node"], "edges": []})
        self.assertEqual(status, 200)
        self.assertEqual(res["trap_count"], 0)
        self.assertEqual(res["total_assignments"], 1)

    def test_invalid_graphs_return_400(self):
        bad_bodies = [
            {"graph": {"nodes": [], "edges": []}},                      # no nodes
            {"graph": {"edges": []}},                                   # nodes missing
            {"graph": {"nodes": ["a"], "edges": [{"from": "a"}]}},      # edge without 'to'
            {"graph": {"nodes": ["a"], "edges": "not-a-list"}},         # edges wrong type
            {"graph": "not json at all"},                               # graph not an object
            {},                                                         # graph missing entirely
        ]
        for body in bad_bodies:
            ip = f"10.7.1.{next(_IP_COUNTER)}"
            status, res = dispatch_api_request(
                "POST", "/api/graph-audit", body=body, client_ip=ip
            )
            self.assertEqual(status, 400, body)
            self.assertFalse(res["ok"])
            self.assertTrue(res["error"])

    def test_too_many_atoms_is_a_loud_400(self):
        # 17 distinct condition atoms exceed the trial's exact-
        # enumeration limit (same MAX_ATOMS = 16 as the standalone
        # checker): the endpoint must refuse loudly, not approximate.
        nodes = ["start", "router", "END"]
        edges = [{"from": "start", "to": "router", "condition": ""}]
        for i in range(17):
            t = f"tool_{i}"
            nodes.append(t)
            edges.append({"from": "router", "to": t, "condition": f"use_tool_{i}"})
            edges.append({"from": t, "to": "END", "condition": ""})
        status, res = audit({"nodes": nodes, "terminals": ["END"], "edges": edges})
        self.assertEqual(status, 400)
        self.assertIn("16", res["error"])
        # The 400 copy must not promise an estimate the fallback
        # never computes.
        self.assertNotIn("sampled", res["error"])

    def test_oversized_fallback_is_structural_only(self):
        # Opt-in fallback for oversized graphs returns structural
        # findings only: no exact count and no sampled estimate.
        nodes = ["start", "router", "END"]
        edges = [{"from": "start", "to": "router", "condition": ""}]
        for i in range(17):
            t = f"tool_{i}"
            nodes.append(t)
            edges.append({"from": "router", "to": t, "condition": f"use_tool_{i}"})
            edges.append({"from": t, "to": "END", "condition": ""})
        ip = f"10.7.2.{next(_IP_COUNTER)}"
        status, res = dispatch_api_request(
            "POST", "/api/graph-audit",
            body={"graph": {"nodes": nodes, "terminals": ["END"], "edges": edges},
                  "fallback": True},
            client_ip=ip,
        )
        self.assertEqual(status, 200)
        self.assertTrue(res["ok"])
        self.assertEqual(res["verdict"], "structural_fallback")
        self.assertIsNone(res["trap_count"])
        self.assertIsNone(res["estimated_trap_rate"])
        self.assertNotIn("sampled", res["engine"])


if __name__ == "__main__":
    unittest.main()
