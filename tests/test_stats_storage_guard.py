"""
Storage-guard regression tests for the 2026-10-29 production incident.

That morning the Postgres stats doc was silently reset (visits 21 /
audits 16 -> ~0): Neon free-tier compute suspends when idle, a cold-start
connect failed inside mutate_stats, the code fell back to a default/file
document, and the next save persisted that near-zero doc over the real
one. These tests pin the fixed behaviour with a fake DB connection:

- write paths (mutate / register / waitlist / save) retry the DB once and
  then raise StorageError WITHOUT writing anything;
- a retry that succeeds preserves the stored counters exactly;
- the monotonic guard: no save can lower a counter or drop stored
  users/codes, however stale the in-memory copy is.
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
from server import (  # noqa: E402
    StorageError,
    append_waitlist_entry,
    dispatch_api_request,
    mutate_stats,
    save_stats,
)

_IP_COUNTER = itertools.count(1)


def _ip():
    return f"10.9.0.{next(_IP_COUNTER)}"


class _FakeCursor:
    """Minimal cursor over a dict-backed sharplogic_store table.

    Understands exactly the statements server.py issues (SELECT doc ...
    [FOR UPDATE], INSERT ... ON CONFLICT DO NOTHING, UPDATE doc)."""

    def __init__(self, store):
        self.store = store
        self._row = None

    def execute(self, sql, params=()):
        s = " ".join(str(sql).split()).upper()
        if s.startswith("CREATE TABLE"):
            return
        if s.startswith("SELECT DOC FROM SHARPLOGIC_STORE"):
            doc = self.store.get(params[0])
            self._row = (json.loads(json.dumps(doc)),) if doc is not None else None
            return
        if s.startswith("INSERT INTO SHARPLOGIC_STORE"):
            key, raw = params[0], params[1]
            if key not in self.store:  # ON CONFLICT DO NOTHING
                self.store[key] = json.loads(raw)
            return
        if s.startswith("UPDATE SHARPLOGIC_STORE"):
            raw, key = params[0], params[1]
            self.store[key] = json.loads(raw)
            return
        raise AssertionError(f"unexpected SQL in fake DB: {sql}")

    def fetchone(self):
        return self._row

    def close(self):
        pass


class _FakeConn:
    def __init__(self, store):
        self.store = store

    def cursor(self):
        return _FakeCursor(self.store)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


def _stored_stats(visits=21, audits=16):
    return {
        "total_visits": visits,
        "total_unlocked": 1,
        "total_audits": audits,
        "codes_used": {"ETH-2026": 3},
        "users": {
            "sl_user_aaa": {
                "identity": "alice",
                "token": "sl_user_aaa",
                "ref_code": "AGENT-ALICE",
                "invited_count": 2,
                "referred_by": None,
                "created_at": "2026-10-28T00:00:00Z",
            }
        },
        "referral_codes": {"AGENT-ALICE": "sl_user_aaa"},
    }


class TestStatsStorageGuard(unittest.TestCase):
    def setUp(self):
        self.store = {}
        self._tmp = tempfile.TemporaryDirectory()
        self.stats_path = os.path.join(self._tmp.name, "sharplogic_stats.json")
        self.waitlist_path = os.path.join(self._tmp.name, "waitlist_signups.jsonl")
        self._patchers = [
            mock.patch.object(server, "_database_url", lambda: "postgres://fake.invalid/db"),
            mock.patch.object(server, "STATS_FILE", self.stats_path),
            mock.patch.object(server, "WAITLIST_FILE", self.waitlist_path),
            mock.patch.object(server, "_DB_RETRY_DELAY_SECONDS", 0),
        ]
        for p in self._patchers:
            p.start()

    def tearDown(self):
        for p in self._patchers:
            p.stop()
        self._tmp.cleanup()

    def _use_fake_db(self):
        return mock.patch.object(server, "_db_connect", lambda: _FakeConn(self.store))

    def _use_dead_db(self):
        def _boom():
            raise ConnectionError("Neon compute is suspended (simulated)")

        return mock.patch.object(server, "_db_connect", _boom)

    # -- outage behaviour: no write, loud error -------------------------

    def test_mutate_db_outage_raises_and_writes_nothing(self):
        self.store["stats"] = _stored_stats()
        with self._use_dead_db():
            with self.assertRaises(StorageError):
                mutate_stats(lambda s: s.__setitem__("total_visits", s["total_visits"] + 1))
        self.assertEqual(self.store["stats"], _stored_stats())
        self.assertFalse(os.path.exists(self.stats_path))  # no file fallback write

    def test_stats_endpoint_db_outage_returns_500(self):
        self.store["stats"] = _stored_stats()
        with self._use_dead_db():
            status, payload = dispatch_api_request("GET", "/api/stats", client_ip=_ip())
        self.assertEqual(status, 500)
        self.assertIn("nothing was written", payload["error"])
        self.assertEqual(self.store["stats"], _stored_stats())

    def test_register_db_outage_returns_500_and_writes_nothing(self):
        with self._use_dead_db():
            status, _ = dispatch_api_request(
                "POST",
                "/api/register",
                body={"identity": "bob", "invite_code": "ETH-2026"},
                client_ip=_ip(),
            )
        self.assertEqual(status, 500)
        self.assertEqual(self.store, {})  # no stats doc created at all
        self.assertFalse(os.path.exists(self.stats_path))

    def test_waitlist_db_outage_raises_and_writes_nothing(self):
        with self._use_dead_db():
            with self.assertRaises(StorageError):
                append_waitlist_entry({"email": "a@b.co", "role": "AI Engineer"})
        self.assertEqual(self.store, {})
        self.assertFalse(os.path.exists(self.waitlist_path))

    # -- retry recovers: counters preserved, never reset -----------------

    def test_mutate_retry_recovers_and_preserves_counters(self):
        self.store["stats"] = _stored_stats()
        calls = {"n": 0}
        store = self.store

        def flaky_connect():
            calls["n"] += 1
            if calls["n"] == 1:
                raise ConnectionError("cold start (simulated)")
            return _FakeConn(store)

        with mock.patch.object(server, "_db_connect", flaky_connect):
            result = mutate_stats(lambda s: s.__setitem__("total_visits", s["total_visits"] + 1))
        self.assertEqual(result["total_visits"], 22)  # 21 + 1, NOT 0 + 1
        self.assertEqual(result["total_audits"], 16)
        self.assertEqual(self.store["stats"]["total_visits"], 22)
        self.assertEqual(self.store["stats"]["total_audits"], 16)

    def test_register_db_ok_then_stale_save_cannot_clobber(self):
        with self._use_fake_db():
            status, payload = dispatch_api_request(
                "POST",
                "/api/register",
                body={"identity": "carol", "invite_code": "ETH-2026"},
                client_ip=_ip(),
            )
            self.assertEqual(status, 200)
            self.assertIn("token", payload)
            doc = self.store["stats"]
            self.assertEqual(doc["total_unlocked"], 1)
            self.assertEqual(len(doc["users"]), 1)
            # A stale near-zero doc (the incident's failure shape) must
            # not be able to overwrite what registration just stored.
            save_stats(server._default_stats())
            doc = self.store["stats"]
            self.assertEqual(doc["total_unlocked"], 1)
            self.assertEqual(len(doc["users"]), 1)

    # -- monotonic guard --------------------------------------------------

    def test_save_stats_monotonic_guard(self):
        self.store["stats"] = _stored_stats()
        stale = server._default_stats()  # all counters 0, no users
        stale["total_visits"] = 2
        stale["users"] = {
            "sl_user_bbb": {
                "identity": "bob",
                "token": "sl_user_bbb",
                "ref_code": "AGENT-BOB",
                "invited_count": 0,
                "referred_by": None,
                "created_at": "2026-10-29T00:00:00Z",
            }
        }
        with self._use_fake_db():
            save_stats(stale)
        doc = self.store["stats"]
        self.assertEqual(doc["total_visits"], 21)   # stored higher value kept
        self.assertEqual(doc["total_audits"], 16)
        self.assertEqual(doc["total_unlocked"], 1)
        self.assertEqual(doc["codes_used"], {"ETH-2026": 3})
        self.assertIn("sl_user_aaa", doc["users"])  # stored user preserved
        self.assertIn("sl_user_bbb", doc["users"])  # new user still added
        self.assertEqual(doc["referral_codes"], {"AGENT-ALICE": "sl_user_aaa"})

    def test_mutate_cannot_lower_a_counter(self):
        self.store["stats"] = _stored_stats()
        with self._use_fake_db():
            result = mutate_stats(lambda s: s.__setitem__("total_visits", 0))
        self.assertEqual(result["total_visits"], 21)
        self.assertEqual(self.store["stats"]["total_visits"], 21)

    def test_merge_stats_monotonic_unit(self):
        stored = _stored_stats()
        incoming = server._default_stats()
        incoming["users"] = {
            "sl_user_aaa": {**stored["users"]["sl_user_aaa"], "invited_count": 5, "identity": "mallory"}
        }
        incoming["codes_used"] = {"ETH-2026": 9, "VIP-INVITE": 1}
        merged = server._merge_stats_monotonic(stored, incoming)
        self.assertEqual(merged["total_visits"], 21)
        self.assertEqual(merged["total_audits"], 16)
        # stored identity fields win on conflict...
        self.assertEqual(merged["users"]["sl_user_aaa"]["identity"], "alice")
        # ...but numeric progress is never lowered either way
        self.assertEqual(merged["users"]["sl_user_aaa"]["invited_count"], 5)
        self.assertEqual(merged["codes_used"], {"ETH-2026": 9, "VIP-INVITE": 1})


if __name__ == "__main__":
    unittest.main()
