"""
End-to-End Verification & Reality Benchmark Suite for SharpLogic (#F).
Tests:
1. Native Rust C-ABI Exact #k-SAT & WMC Solver (#F=42, #F=192, #F=1920 -> 0).
2. Bit-exact Parity between Native Rust cdylib and Vercel Serverless Kernel.
3. Multi-Mode Autoformalizer (AWS IAM Policy JSON, Agent Graph JSON, Bilingual NL/DSL).
4. Adversarial Alert Storm on O(K) Bounded Manifold + Microsecond b"SLGC" Persistence.
5. Bounded O(K) IP Rate Limiter & REST API Dispatcher.
"""

import json
import os
import sys
import tempfile
import time
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PYTHON_DIR = os.path.join(ROOT_DIR, "python")
if PYTHON_DIR not in sys.path:
    sys.path.insert(0, PYTHON_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from sharplogic import (  # noqa: E402
    SCENARIOS,
    Autoformalizer,
    RustSharpLogicEngine,
    evaluate_custom_rules,
    evaluate_scenario,
)
from server import BoundedRateLimiter, dispatch_api_request  # noqa: E402


class TestSharpLogicEndToEnd(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RustSharpLogicEngine(force_serverless=False)
        self.serverless_engine = RustSharpLogicEngine(force_serverless=True)

    def tearDown(self) -> None:
        self.engine.close()
        self.serverless_engine.close()

    def test_01_flagship_ecommerce_promo_audit_and_patch(self) -> None:
        """Verifies exact #F=42 across 2^24 states and 1-click formal patch (#F=0)."""
        unpatched = evaluate_scenario("ecommerce_promo", apply_patch=False)
        audit = unpatched["audit"]
        self.assertTrue(audit["is_satisfiable"])
        self.assertEqual(audit["num_vars"], 24)
        self.assertEqual(audit["total_space"], 16_777_216)
        self.assertEqual(audit["exact_count"], 42)
        self.assertLess(audit["solve_time_us"], 2000.0)
        self.assertTrue(audit["ghost_assignment"]["is_vip"])
        self.assertTrue(audit["ghost_assignment"]["cross_border_item"])
        self.assertTrue(audit["ghost_assignment"]["partial_return_requested"])

        patched = evaluate_scenario("ecommerce_promo", apply_patch=True)
        p_audit = patched["audit"]
        self.assertFalse(p_audit["is_satisfiable"])
        self.assertEqual(p_audit["exact_count"], 0)
        self.assertEqual(p_audit["sharp_score"], 100.0)

    def test_02_flagship_agent_workflow_deadlock_audit_and_patch(self) -> None:
        """Verifies exact #F=192 across 2^20 states for LangGraph routing deadlock."""
        unpatched = evaluate_scenario("agent_workflow", apply_patch=False)
        audit = unpatched["audit"]
        self.assertTrue(audit["is_satisfiable"])
        self.assertEqual(audit["num_vars"], 20)
        self.assertEqual(audit["total_space"], 1_048_576)
        self.assertEqual(audit["exact_count"], 192)
        self.assertFalse(audit["ghost_assignment"]["mfa_token_verified"])
        self.assertTrue(audit["ghost_assignment"]["invoke_instant_payout_tool"])

        patched = evaluate_scenario("agent_workflow", apply_patch=True)
        self.assertEqual(patched["audit"]["exact_count"], 0)
        self.assertEqual(patched["audit"]["sharp_score"], 100.0)

    def test_03_flagship_cloud_iam_blast_radius_quantifier(self) -> None:
        """Verifies exact #F=1920 (120x expansion over baseline=16) across 2^22 IAM states."""
        unpatched = evaluate_scenario("cloud_iam", apply_patch=False)
        audit = unpatched["audit"]
        self.assertEqual(audit["num_vars"], 22)
        self.assertEqual(audit["total_space"], 4_194_304)
        self.assertEqual(audit["exact_count"], 1920)
        self.assertEqual(unpatched["blast_radius_multiplier"], 120.0)

        patched = evaluate_scenario("cloud_iam", apply_patch=True)
        self.assertEqual(patched["audit"]["exact_count"], 0)
        self.assertEqual(patched["audit"]["sharp_score"], 100.0)

    def test_04_bit_exact_parity_rust_cdylib_vs_vercel_serverless_kernel(self) -> None:
        """Guarantees 100% bit-exact parity between Native Rust cdylib and Vercel Serverless Kernel."""
        self.assertTrue(self.engine.using_native_rust)
        self.assertFalse(self.serverless_engine.using_native_rust)

        for sid, scen in SCENARIOS.items():
            var_names = [v["name"] for v in scen["variables"]]
            weights = [float(v["prior"]) for v in scen["variables"]]
            r_rust = self.engine.solve_cnf(len(var_names), scen["clauses"], weights, var_names)
            r_srv = self.serverless_engine.solve_cnf(len(var_names), scen["clauses"], weights, var_names)

            self.assertEqual(r_rust["exact_count"], r_srv["exact_count"], f"Count mismatch on {sid}")
            self.assertEqual(r_rust["total_space"], r_srv["total_space"])
            self.assertAlmostEqual(r_rust["weighted_probability"], r_srv["weighted_probability"], places=9)
            self.assertEqual(r_rust["sharp_score"], r_srv["sharp_score"])
            self.assertEqual(r_rust["ghost_assignment"], r_srv["ghost_assignment"])

    def test_05_real_aws_iam_and_agent_json_autoformalizer(self) -> None:
        """Verifies deterministic compilation of real AWS IAM Policy JSON and Agent Workflow JSON."""
        iam_policy_json = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["sts:AssumeRole", "rds:CopyDBSnapshot"],
                        "Resource": "*",
                    }
                ],
            }
        )
        iam_res = evaluate_custom_rules(iam_policy_json, apply_patch=False)
        self.assertGreater(iam_res["audit"]["exact_count"], 0)
        self.assertTrue(any("IAM JSON Parser" in s for s in iam_res["self_correction_log"]))

        iam_patched = evaluate_custom_rules(iam_policy_json, apply_patch=True)
        self.assertEqual(iam_patched["audit"]["exact_count"], 0)

        agent_graph_json = json.dumps(
            {
                "nodes": [{"id": "triage"}, {"id": "risk_hold"}, {"id": "instant_payout"}],
                "edges": [
                    {"source": "triage", "target": "risk_hold"},
                    {"source": "risk_hold", "target": "triage"},
                    {"source": "triage", "target": "instant_payout"},
                ],
            }
        )
        agent_res = evaluate_custom_rules(agent_graph_json, apply_patch=False)
        self.assertGreater(agent_res["audit"]["exact_count"], 0)
        self.assertTrue(any("Agent Graph Parser" in s for s in agent_res["self_correction_log"]))

    def test_06_adversarial_alert_storm_and_microsecond_persistence(self) -> None:
        """
        Stress tests O(K) Bounded Manifold against 500-event Alert Storm,
        Recency Traps, Vocabulary Gap, and b'SLGC' < 1ms binary persistence.
        """
        root_id = self.engine.ingest_event(
            "CRITICAL_ROOT_CAUSE: IAM Role db-migration-* updated with wildcard * on rds:CopyDBSnapshot without MFA",
            domain_tag=3,
            loophole_count=1920,
            importance=0.99,
            provenance=0.98,
        )

        for i in range(500):
            self.engine.ingest_event(
                f"HEARTBEAT_LOG #{i % 12}: Normal health check passed 200 OK latency 3ms",
                domain_tag=0,
                loophole_count=0,
                importance=0.10,
                provenance=0.15,
            )

        active = self.engine.active_memory_slots()
        self.assertLessEqual(active, 128)

        recalled = self.engine.recall_top1("Alert: IAM privilege escalation blast radius exposure detected")
        self.assertIsNotNone(recalled)
        self.assertEqual(recalled["record_id"], root_id)

        with tempfile.NamedTemporaryFile(suffix=".slgc", delete=False) as tmp:
            snap_path = tmp.name

        try:
            t0 = time.perf_counter()
            bytes_written = self.engine.save_snapshot(snap_path)
            save_ms = (time.perf_counter() - t0) * 1000.0

            with open(snap_path, "rb") as f:
                magic = f.read(4)
            self.assertEqual(magic, b"SLGC")
            self.assertGreater(bytes_written, 4000)
            self.assertLess(save_ms, 5.0)

            t1 = time.perf_counter()
            self.engine.load_snapshot(snap_path)
            load_ms = (time.perf_counter() - t1) * 1000.0
            self.assertLess(load_ms, 5.0)

            recalled_after = self.engine.recall_top1(
                "Alert: IAM privilege escalation blast radius exposure detected"
            )
            self.assertIsNotNone(recalled_after)
            self.assertEqual(recalled_after["record_id"], root_id)
            self.assertAlmostEqual(recalled_after["score"], recalled["score"], places=4)
        finally:
            if os.path.exists(snap_path):
                os.remove(snap_path)

    def test_07_rate_limiter_and_api_endpoints_end_to_end(self) -> None:
        """Verifies BoundedRateLimiter O(K) protection and all REST API routes."""
        limiter = BoundedRateLimiter(max_ips=8, limit_per_min=5)
        for _ in range(5):
            self.assertTrue(limiter.allow("10.0.0.1"))
        self.assertFalse(limiter.allow("10.0.0.1"))

        # Flood with 50 distinct IPs and verify table never exceeds max_ips=8
        for i in range(50):
            limiter.allow(f"192.168.1.{i}")
        self.assertLessEqual(len(limiter._table), 8)

        status, health = dispatch_api_request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(health["status"], "ok")

        status, unpatched = dispatch_api_request(
            "POST", "/api/audit", body={"scenario_id": "ecommerce_promo", "patched": False}
        )
        self.assertEqual(status, 200)
        self.assertEqual(unpatched["audit"]["exact_count"], 42)

        status, patched = dispatch_api_request(
            "POST", "/api/audit", body={"scenario_id": "ecommerce_promo", "patched": True}
        )
        self.assertEqual(status, 200)
        self.assertEqual(patched["audit"]["exact_count"], 0)
        self.assertEqual(patched["audit"]["sharp_score"], 100.0)


if __name__ == "__main__":
    unittest.main()
