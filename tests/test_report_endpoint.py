"""
Endpoint tests for POST /api/report (browser-trial email capture).

The server must re-run the submitted graph through the real compiler /
exact engine, email a report built from the server's own numbers, and
store the resulting lead. The homepage's prefilled graph is the oracle:
its unguarded Critic exit has exactly one trap assignment out of two.
"""

import itertools
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PYTHON_DIR = os.path.join(ROOT_DIR, "python")
if PYTHON_DIR not in sys.path:
    sys.path.insert(0, PYTHON_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import server  # noqa: E402
from server import StorageError, append_lead, dispatch_api_request, load_leads  # noqa: E402

_IP_COUNTER = itertools.count(1)


def _ip():
    return f"10.8.0.{next(_IP_COUNTER)}"


DEMO_GRAPH = {
    "nodes": ["Start", "Tool_Executor", "Critic", "END"],
    "terminals": ["END"],
    "edges": [
        {"from": "Start", "to": "Tool_Executor", "condition": ""},
        {"from": "Tool_Executor", "to": "Critic", "condition": ""},
        {"from": "Critic", "to": "Tool_Executor", "condition": "retry_count < 3"},
        {"from": "Critic", "to": "END", "condition": "retry_count < 3"},
    ],
}

CLEAN_GRAPH = {
    "nodes": ["Start", "Tool_Executor", "Critic", "END"],
    "terminals": ["END"],
    "edges": [
        {"from": "Start", "to": "Tool_Executor", "condition": ""},
        {"from": "Tool_Executor", "to": "Critic", "condition": ""},
        {"from": "Critic", "to": "Tool_Executor", "condition": "retry_count < 3"},
        {"from": "Critic", "to": "END", "condition": "retry_count >= 3"},
    ],
}


class TestReportEndpoint(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.leads_path = os.path.join(self._tmp.name, "sharplogic_leads.json")
        self.stats_path = os.path.join(self._tmp.name, "sharplogic_stats.json")
        self.sent = []
        self.send_result = ("msg-test-123", None)

        def fake_send(to_email, subject, text_body, html_body):
            self.sent.append(
                {
                    "to": to_email,
                    "subject": subject,
                    "text": text_body,
                    "html": html_body,
                }
            )
            return self.send_result

        self._patchers = [
            mock.patch.object(server, "_database_url", lambda: None),
            mock.patch.object(server, "LEADS_FILE", self.leads_path),
            mock.patch.object(server, "STATS_FILE", self.stats_path),
            mock.patch.object(server, "_send_report_email", fake_send),
        ]
        for patcher in self._patchers:
            patcher.start()

    def tearDown(self):
        for patcher in self._patchers:
            patcher.stop()
        self._tmp.cleanup()

    def report(self, email="dev@example.com", graph=None, ip=None):
        return dispatch_api_request(
            "POST",
            "/api/report",
            body={"email": email, "graph": DEMO_GRAPH if graph is None else graph},
            client_ip=ip or _ip(),
        )

    def test_bad_email_is_400_and_stores_nothing(self):
        for email in ("", "not-an-email", "a@b", "a b@c.com", "@example.com", "a@.com"):
            status, res = self.report(email=email)
            self.assertEqual(status, 400, email)
            self.assertFalse(res["ok"])
            self.assertIn("valid email", res["error"])
        self.assertEqual(self.sent, [])
        self.assertEqual(load_leads(), [])
        self.assertFalse(os.path.exists(self.leads_path))

    def test_bad_graph_is_400_and_stores_nothing(self):
        bad_graphs = [
            {"nodes": [], "edges": []},
            {"edges": []},
            {"nodes": ["a"], "edges": [{"from": "a"}]},
            {"nodes": ["a"], "edges": "not-a-list"},
            "not json at all",
        ]
        for graph in bad_graphs:
            status, res = self.report(graph=graph)
            self.assertEqual(status, 400, graph)
            self.assertFalse(res["ok"])
            self.assertTrue(res["error"])
        status, res = dispatch_api_request(
            "POST", "/api/report", body={"email": "dev@example.com"}, client_ip=_ip()
        )
        self.assertEqual(status, 400)
        self.assertEqual(self.sent, [])
        self.assertEqual(load_leads(), [])

    def test_demo_graph_report_contains_server_computed_numbers(self):
        status, res = self.report()
        self.assertEqual(status, 200)
        self.assertTrue(res["ok"])
        self.assertTrue(res["sent"])
        self.assertEqual(res["message_id"], "msg-test-123")
        self.assertEqual(res["exact_count"], 1)
        self.assertEqual(res["total_space"], 2)

        self.assertEqual(len(self.sent), 1)
        message = self.sent[0]
        self.assertEqual(message["to"], "dev@example.com")
        self.assertIn("#F = 1", message["subject"])
        self.assertIn("Trap assignments (#F): 1", message["text"])
        self.assertIn("Total condition assignments: 2", message["text"])
        self.assertIn("Share that traps: 50%", message["text"])
        self.assertIn("Critic", message["text"])
        self.assertIn("https://sharplogic.vercel.app/#try", message["text"])
        self.assertIn("Trap assignments (#F): 1", message["html"])
        self.assertIn("Critic", message["html"])

    def test_clean_graph_report_contains_zero_count(self):
        status, res = self.report(graph=CLEAN_GRAPH)
        self.assertEqual(status, 200)
        self.assertEqual(res["exact_count"], 0)
        self.assertEqual(res["total_space"], 2)
        self.assertIn("#F = 0", self.sent[0]["subject"])
        self.assertIn("Share that traps: 0%", self.sent[0]["text"])
        self.assertIn("no condition assignment traps this workflow", self.sent[0]["text"])

    def test_lead_storage_write_and_read_in_file_mode(self):
        status, _ = self.report(email="lead@example.com")
        self.assertEqual(status, 200)
        self.assertTrue(os.path.exists(self.leads_path))
        with open(self.leads_path, "r", encoding="utf-8") as f:
            stored = json.load(f)
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["email"], "lead@example.com")
        self.assertEqual(stored[0]["exact_count"], 1)
        self.assertEqual(stored[0]["total_space"], 2)
        self.assertEqual(stored[0]["source"], "browser-trial")
        self.assertEqual(stored[0]["status"], "sent")
        self.assertTrue(stored[0]["ts"].endswith("Z"))
        self.assertEqual(load_leads(), stored)

        direct = {
            "email": "direct@example.com",
            "ts": "2026-10-29T00:00:00Z",
            "exact_count": 0,
            "total_space": 1,
            "source": "browser-trial",
            "status": "sent",
        }
        append_lead(direct)
        self.assertEqual(load_leads()[-1], direct)

    def test_send_failure_is_502_and_lead_is_marked_send_failed(self):
        self.send_result = (None, "simulated provider failure")
        status, res = self.report()
        self.assertEqual(status, 502)
        self.assertFalse(res["ok"])
        self.assertIn("simulated provider failure", res["error"])
        leads = load_leads()
        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0]["status"], "send_failed")

    def test_failed_sends_do_not_consume_daily_cap(self):
        self.send_result = (None, "simulated provider failure")
        for _ in range(3):
            status, _ = self.report()
            self.assertEqual(status, 502)
        self.send_result = ("msg-after-failures", None)
        status, res = self.report()
        self.assertEqual(status, 200)
        self.assertEqual(res["message_id"], "msg-after-failures")

    def test_daily_cap_per_email(self):
        for _ in range(3):
            status, _ = self.report(email="cap@example.com")
            self.assertEqual(status, 200)
        status, res = self.report(email="cap@example.com")
        self.assertEqual(status, 429)
        self.assertIn("already received 3 reports today", res["error"])
        self.assertEqual(len(self.sent), 3)
        self.assertEqual(len(load_leads()), 3)

    def test_daily_cap_per_ip(self):
        ip = "10.8.9.9"
        for i in range(3):
            status, _ = self.report(email=f"person{i}@example.com", ip=ip)
            self.assertEqual(status, 200)
        status, res = self.report(email="another@example.com", ip=ip)
        self.assertEqual(status, 429)
        self.assertIn("this network today", res["error"])
        self.assertEqual(len(self.sent), 3)
        self.assertEqual(len(load_leads()), 3)

    def test_stats_include_lead_count(self):
        status, res = dispatch_api_request("GET", "/api/stats", client_ip=_ip())
        self.assertEqual(status, 200)
        self.assertEqual(res["stats"]["leads"], 0)

        status, _ = self.report()
        self.assertEqual(status, 200)

        status, res = dispatch_api_request("GET", "/api/stats", client_ip=_ip())
        self.assertEqual(status, 200)
        self.assertEqual(res["stats"]["leads"], 1)
        self.assertEqual(res["stats"]["total_visits"], 2)

    def test_too_many_atoms_is_a_loud_400(self):
        nodes = ["start", "router", "END"]
        edges = [{"from": "start", "to": "router", "condition": ""}]
        for i in range(17):
            tool = f"tool_{i}"
            nodes.append(tool)
            edges.append({"from": "router", "to": tool, "condition": f"use_tool_{i}"})
            edges.append({"from": tool, "to": "END", "condition": ""})
        status, res = self.report(graph={"nodes": nodes, "terminals": ["END"], "edges": edges})
        self.assertEqual(status, 400)
        self.assertIn("16", res["error"])
        self.assertEqual(self.sent, [])
        self.assertEqual(load_leads(), [])


class TestSendReportEmailTransport(unittest.TestCase):
    def test_resend_request_carries_browser_user_agent_and_parses_id(self):
        # Regression pin for the first live attempt: Resend is behind
        # Cloudflare, which rejects the default Python-urllib signature
        # with HTTP 403 / error code 1010. The request must carry a
        # browser User-Agent, and the accepted message id must be parsed
        # from the JSON response.
        captured = {}

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b'{"id": "msg-live-42"}'

        def fake_urlopen(req, timeout=None):
            captured["req"] = req
            captured["timeout"] = timeout
            return _Resp()

        with mock.patch.dict(
            os.environ, {server._RESEND_KEY_ENV_NAME: "test-key-not-real"}
        ), mock.patch.object(server.urllib.request, "urlopen", fake_urlopen):
            message_id, error = server._send_report_email(
                "dev@example.com", "subj", "text body", "<p>html body</p>"
            )
        self.assertIsNone(error)
        self.assertEqual(message_id, "msg-live-42")
        req = captured["req"]
        self.assertIn("Mozilla/5.0", req.get_header("User-agent"))
        self.assertEqual(req.full_url, "https://api.resend.com/emails")
        body = json.loads(req.data.decode("utf-8"))
        self.assertEqual(body["from"], "SharpLogic <hello@mail.quotalis.app>")
        self.assertEqual(body["to"], ["dev@example.com"])
        self.assertEqual(body["subject"], "subj")
        self.assertEqual(body["text"], "text body")
        self.assertEqual(body["html"], "<p>html body</p>")


class TestLeadStorageDatabaseGuard(unittest.TestCase):
    def test_append_lead_db_outage_raises_and_never_falls_back_to_file(self):
        tmp = tempfile.TemporaryDirectory()
        leads_path = os.path.join(tmp.name, "sharplogic_leads.json")

        def dead_connect():
            raise ConnectionError("Neon compute is suspended (simulated)")

        try:
            with mock.patch.object(
                server, "_database_url", lambda: "postgres://fake.invalid/db"
            ), mock.patch.object(server, "LEADS_FILE", leads_path), mock.patch.object(
                server, "_db_connect", dead_connect
            ), mock.patch.object(server, "_DB_RETRY_DELAY_SECONDS", 0):
                with self.assertRaises(StorageError):
                    append_lead({"email": "db@example.com", "status": "sent"})
            self.assertFalse(os.path.exists(leads_path))
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
