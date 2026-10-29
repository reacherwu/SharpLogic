#!/usr/bin/env python3
"""
SharpLogic Production Multi-Threaded HTTP Server & Serverless Router.
Includes:
- ThreadingHTTPServer for concurrent traffic spikes (X / Hacker News launches)
- Strictly Bounded O(K) IP Rate Limiter (MAX_IPS = 256)
- Payload size protection (64 KB hard cap)
- Read-only serverless filesystem detection (/tmp fallback for Vercel Lambda)
"""

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON_DIR = os.path.join(ROOT_DIR, "python")
WEB_DIR = os.path.join(ROOT_DIR, "web")
if PYTHON_DIR not in sys.path:
    sys.path.insert(0, PYTHON_DIR)

from sharplogic import (  # noqa: E402
    SCENARIOS,
    evaluate_custom_rules,
    evaluate_scenario,
    get_engine,
)

# Serverless read-only filesystem protection (Vercel / AWS Lambda only allow writes to /tmp)
_WRITABLE_DIR = ROOT_DIR if os.access(ROOT_DIR, os.W_OK) else "/tmp"
WAITLIST_FILE = os.path.join(_WRITABLE_DIR, "waitlist_signups.jsonl")
SNAPSHOT_FILE = os.path.join(_WRITABLE_DIR, "sharplogic_manifold.slgc")
STATS_FILE = os.path.join(_WRITABLE_DIR, "sharplogic_stats.json")

VALID_INVITE_CODES = {
    "ETH-2026",
    "SHARP-AGENT",
    "OPENAI-MATH",
    "AGENT-SAT",
    "VIP-INVITE",
    "LANGGRAPH-AI",
    "DIFY-AGENT",
}

def _default_stats() -> dict:
    return {
        "total_visits": 0,
        "total_unlocked": 0,
        "total_audits": 0,
        "codes_used": {},
        "users": {},
        "referral_codes": {},
    }


# ---------------------------------------------------------------------------
# Persistent document storage (stats + waitlist).
#
# On Vercel the filesystem is ephemeral per function instance, so the
# original /tmp JSON file silently reset counters and discarded
# registrations on every cold start. When a Postgres connection URL is
# configured, the documents live in a `sharplogic_store` table (one JSONB
# row per document) and every read-modify-write runs in a single
# transaction with a row lock. Without a database URL (local development),
# the original file behaviour is kept.
# ---------------------------------------------------------------------------

_DB_ENV_NAMES = (
    "SHARPLOGIC_DATABASE_URL",
    "DATABASE_URL",
    "POSTGRES_URL",
    "DATABASE_URL_UNPOOLED",
    "POSTGRES_URL_NON_POOLING",
)
_DB_TABLE_READY = False
_DB_LOCK = threading.Lock()


def _database_url() -> Optional[str]:
    for name in _DB_ENV_NAMES:
        value = os.environ.get(name, "").strip()
        if value.startswith("postgres://") or value.startswith("postgresql://"):
            return value
    return None


def storage_backend() -> str:
    return "postgres" if _database_url() else "file"


def _db_connect():
    import ssl as ssl_module
    from urllib.parse import parse_qs, urlparse

    import pg8000.dbapi

    url = _database_url()
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    sslmode = (query.get("sslmode", [""])[0] or "").lower()
    host = parsed.hostname or "localhost"
    use_ssl = sslmode in ("require", "verify-ca", "verify-full") or (
        sslmode != "disable" and host not in ("localhost", "127.0.0.1")
    )
    conn = pg8000.dbapi.connect(
        user=parsed.username or "",
        password=parsed.password or "",
        host=host,
        port=parsed.port or 5432,
        database=(parsed.path or "/").lstrip("/") or "postgres",
        ssl_context=ssl_module.create_default_context() if use_ssl else None,
        timeout=15,
    )
    global _DB_TABLE_READY
    if not _DB_TABLE_READY:
        with _DB_LOCK:
            if not _DB_TABLE_READY:
                cur = conn.cursor()
                cur.execute(
                    "CREATE TABLE IF NOT EXISTS sharplogic_store ("
                    "key TEXT PRIMARY KEY, "
                    "doc JSONB NOT NULL, "
                    "updated_at TIMESTAMPTZ NOT NULL DEFAULT now())"
                )
                conn.commit()
                cur.close()
                _DB_TABLE_READY = True
    return conn


def _db_load_doc(key: str, default):
    conn = _db_connect()
    try:
        cur = conn.cursor()
        cur.execute("SELECT doc FROM sharplogic_store WHERE key = %s", (key,))
        row = cur.fetchone()
        cur.close()
        if row is None:
            return json.loads(json.dumps(default))
        doc = row[0]
        return doc if isinstance(doc, (dict, list)) else json.loads(doc)
    finally:
        conn.close()


def _db_save_doc(key: str, doc) -> None:
    conn = _db_connect()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO sharplogic_store (key, doc, updated_at) VALUES (%s, %s::jsonb, now()) "
            "ON CONFLICT (key) DO UPDATE SET doc = EXCLUDED.doc, updated_at = now()",
            (key, json.dumps(doc)),
        )
        conn.commit()
        cur.close()
    finally:
        conn.close()


def _db_mutate_doc(key: str, default, fn):
    """Atomic read-modify-write of one stored document under a row lock."""
    conn = _db_connect()
    try:
        cur = conn.cursor()
        cur.execute("SELECT doc FROM sharplogic_store WHERE key = %s FOR UPDATE", (key,))
        row = cur.fetchone()
        if row is None:
            doc = json.loads(json.dumps(default))
            cur.execute(
                "INSERT INTO sharplogic_store (key, doc) VALUES (%s, %s::jsonb) "
                "ON CONFLICT (key) DO NOTHING",
                (key, json.dumps(doc)),
            )
            cur.execute("SELECT doc FROM sharplogic_store WHERE key = %s FOR UPDATE", (key,))
            row = cur.fetchone()
            if row is not None and isinstance(row[0], (dict, list)):
                doc = row[0]
        elif isinstance(row[0], (dict, list)):
            doc = row[0]
        else:
            doc = json.loads(row[0])
        result = fn(doc)
        cur.execute(
            "UPDATE sharplogic_store SET doc = %s::jsonb, updated_at = now() WHERE key = %s",
            (json.dumps(doc), key),
        )
        conn.commit()
        cur.close()
        return result, doc
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


def load_stats() -> dict:
    if _database_url():
        try:
            data = _db_load_doc("stats", _default_stats())
            return {**_default_stats(), **data}
        except Exception:
            pass  # fall through to file so a DB outage never breaks reads
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {**_default_stats(), **data}
        except Exception:
            pass
    return _default_stats()


def save_stats(stats: dict) -> None:
    if _database_url():
        try:
            _db_save_doc("stats", stats)
            return
        except Exception:
            pass  # fall through to file fallback
    try:
        with open(STATS_FILE, "w", encoding="utf-8") as f:
            json.dump(stats, f)
    except Exception:
        pass


def mutate_stats(fn) -> dict:
    """Run fn(stats) as one atomic read-modify-write; returns final stats."""
    if _database_url():
        try:
            def _apply(doc):
                merged = {**_default_stats(), **doc}
                fn(merged)
                doc.clear()
                doc.update(merged)

            _, doc = _db_mutate_doc("stats", _default_stats(), _apply)
            return {**_default_stats(), **doc}
        except Exception:
            pass  # fall through to file fallback
    stats = load_stats()
    fn(stats)
    save_stats(stats)
    return stats


def append_waitlist_entry(entry: dict) -> None:
    if _database_url():
        try:
            def _append(lst):
                lst.append(entry)

            _db_mutate_doc("waitlist", [], _append)
            return
        except Exception:
            pass  # fall through to file fallback
    try:
        with open(WAITLIST_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass

MAX_PAYLOAD_BYTES = 65536  # 64 KB cap
MAX_TRACKED_IPS = 256      # Strictly bounded O(K) rate-limiter table
RATE_LIMIT_PER_MIN = 120   # 120 requests / min per IP


class BoundedRateLimiter:
    """Strictly bounded O(K) sliding-window IP rate limiter."""

    def __init__(self, max_ips: int = MAX_TRACKED_IPS, limit_per_min: int = RATE_LIMIT_PER_MIN) -> None:
        self.max_ips = max_ips
        self.limit_per_min = limit_per_min
        self._lock = threading.Lock()
        self._table: Dict[str, Tuple[float, int]] = {}

    def allow(self, client_ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if client_ip in self._table:
                win_start, count = self._table[client_ip]
                if now - win_start > 60.0:
                    self._table[client_ip] = (now, 1)
                    return True
                if count >= self.limit_per_min:
                    return False
                self._table[client_ip] = (win_start, count + 1)
                return True

            if len(self._table) >= self.max_ips:
                # Evict oldest window entry to maintain strict O(K) bound
                oldest_ip = min(self._table.items(), key=lambda kv: kv[1][0])[0]
                del self._table[oldest_ip]

            self._table[client_ip] = (now, 1)
            return True


_RATE_LIMITER = BoundedRateLimiter()
_SEEDED = False
_SEED_LOCK = threading.Lock()


def ensure_seeded() -> None:
    global _SEEDED
    if not _SEEDED:
        with _SEED_LOCK:
            if not _SEEDED:
                for sid in ["ecommerce_promo", "agent_workflow", "cloud_iam", "ap_invoice_matching"]:
                    evaluate_scenario(sid, apply_patch=False)
                _SEEDED = True


def dispatch_api_request(
    method: str,
    path: str,
    query_params: Optional[Dict[str, List[str]]] = None,
    body: Optional[Dict[str, Any]] = None,
    client_ip: str = "127.0.0.1",
) -> Tuple[int, Dict[str, Any]]:
    """Pure in-process API router (used by local ThreadingHTTPServer, Vercel Function, and tests)."""
    ensure_seeded()
    if not _RATE_LIMITER.allow(client_ip):
        return 429, {"error": "Rate limit exceeded. Please wait a moment and try again."}

    query_params = query_params or {}
    body = body or {}

    if method == "GET":
        if path == "/api/health":
            engine = get_engine()
            return 200, {
                "status": "ok",
                "engine": "sharplogic-core (Native Rust C-ABI)" if engine.using_native_rust else "sharplogic-core (Serverless Exact Kernel)",
                "using_native_rust": engine.using_native_rust,
                "active_manifold_slots": engine.active_memory_slots(),
                "max_manifold_slots": 128,
            }
        if path == "/api/scenarios":
            summary = [
                evaluate_scenario(sid, apply_patch=False)
                for sid in ["ecommerce_promo", "agent_workflow", "cloud_iam", "ap_invoice_matching"]
            ]
            return 200, {"scenarios": summary}
        if path == "/api/audit":
            sid = query_params.get("scenario_id", ["ecommerce_promo"])[0]
            patched = query_params.get("patched", ["false"])[0].lower() in ("true", "1", "yes")
            try:
                def _inc_audit(s):
                    s["total_audits"] = s.get("total_audits", 0) + 1

                mutate_stats(_inc_audit)
                return 200, evaluate_scenario(sid, apply_patch=patched)
            except Exception as exc:
                return 400, {"error": str(exc)}

        if path == "/api/stats":
            def _inc_visit(s):
                s["total_visits"] = s.get("total_visits", 0) + 1

            stats = mutate_stats(_inc_visit)
            return 200, {
                "ok": True,
                "stats": stats,
                "storage": storage_backend(),
                "accepted_invite_codes": sorted(list(VALID_INVITE_CODES)),
            }

        if path == "/api/me":
            token = query_params.get("token", [""])[0]
            if not token:
                return 400, {"ok": False, "error": "Token required"}
            stats = load_stats()
            users = stats.get("users", {})
            if token not in users:
                return 404, {"ok": False, "error": "User not found"}
            user = users[token]
            invited = user.get("invited_count", 0)
            tiers = ["cli_offline_guard"]
            if invited >= 1:
                tiers.append("auto_patch")
            if invited >= 3:
                tiers.append("cicd_action")
            if invited >= 5:
                tiers.append("github_sentinel_hall")
            return 200, {
                "ok": True,
                "token": token,
                "identity": user.get("identity", "developer"),
                "ref_code": user.get("ref_code", "AGENT-DEV"),
                "ref_url": f"https://sharplogic.vercel.app/?ref={user.get('ref_code', 'AGENT-DEV')}",
                "invited_count": invited,
                "unlocked_tiers": tiers,
                "install_cmd": f"curl -fsSL https://sharplogic.vercel.app/install.py | python3 - --token {token}",
            }

    if method == "POST":
        if path == "/api/register":
            import hashlib
            import re
            identity = str(body.get("identity", "")).strip() or str(body.get("username", "")).strip() or str(body.get("email", "")).strip()
            if not identity:
                return 400, {"ok": False, "error": "Please provide a GitHub username or email."}
            invite_code = str(body.get("invite_code", "")).strip().upper() or str(body.get("code", "")).strip().upper()
            ref = str(body.get("ref", "")).strip().upper()

            stats = load_stats()
            users = stats.setdefault("users", {})
            referral_codes = stats.setdefault("referral_codes", {})

            is_valid = (
                (invite_code in VALID_INVITE_CODES) or
                (invite_code in referral_codes) or
                invite_code.startswith("SL-") or
                invite_code.startswith("AGENT-") or
                (ref in referral_codes)
            )

            if not is_valid:
                return 403, {
                    "ok": False,
                    "error": f"Invalid invite code '{invite_code}'. Use genesis code 'ETH-2026' from the launch tweet.",
                }

            clean_name = re.sub(r"[^A-Za-z0-9]", "", identity.split("@")[0]).upper()
            if not clean_name:
                clean_name = "SENTINEL"
            token_hash = hashlib.sha256(f"sharplogic:user:{identity.lower()}".encode("utf-8")).hexdigest()[:16]
            token = f"sl_user_{token_hash}"

            ref_code = f"AGENT-{clean_name[:8]}"
            if ref_code in referral_codes and referral_codes[ref_code] != token:
                ref_code = f"AGENT-{clean_name[:6]}-{token_hash[:4].upper()}"

            actual_referrer = ref if (ref and ref in referral_codes) else None
            if not actual_referrer and invite_code in referral_codes:
                actual_referrer = invite_code

            if token in users:
                user = users[token]
            else:
                user = {
                    "identity": identity,
                    "token": token,
                    "ref_code": ref_code,
                    "invited_count": 0,
                    "referred_by": actual_referrer,
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
                users[token] = user
                referral_codes[ref_code] = token
                stats["total_unlocked"] = stats.get("total_unlocked", 0) + 1
                code_key = invite_code or actual_referrer or "ETH-2026"
                stats["codes_used"][code_key] = stats["codes_used"].get(code_key, 0) + 1

                if actual_referrer and actual_referrer in referral_codes and referral_codes[actual_referrer] != token:
                    referrer_token = referral_codes[actual_referrer]
                    if referrer_token in users:
                        users[referrer_token]["invited_count"] = users[referrer_token].get("invited_count", 0) + 1

                save_stats(stats)

            invited = user.get("invited_count", 0)
            tiers = ["cli_offline_guard"]
            if invited >= 1:
                tiers.append("auto_patch")
            if invited >= 3:
                tiers.append("cicd_action")
            if invited >= 5:
                tiers.append("github_sentinel_hall")

            in_agent_sample = '''from sharplogic import AgentGuard

# Local guardrail: exact deadlock/livelock audit of your workflow graph
# (0 cloud calls; analysis runs entirely on your machine).
WORKFLOW = {
    "nodes": ["Tool_Executor", "Critic_Fallback", "Human_Approval_Gate"],
    "terminals": ["Human_Approval_Gate"],
    "edges": [
        {"from": "Tool_Executor", "to": "Critic_Fallback",
         "condition": "tool_timeout or execution_error"},
        {"from": "Critic_Fallback", "to": "Tool_Executor",
         "condition": "retry_prompt_generated and retry_count <= 3"},
        {"from": "Critic_Fallback", "to": "Human_Approval_Gate",
         "condition": "not retry_prompt_generated or retry_count > 3"},
    ],
}
guard = AgentGuard(token="__TOKEN__", graph=WORKFLOW)

# Audit the whole graph: counts the condition assignments that trap it
report = guard.audit()
print(report["exact_count"])  # trap assignments (#F); 0 = no traps found

# Runtime check of one transition against the current conditions
guard.assert_safe("Critic_Fallback", "Tool_Executor",
                  state={"retry_prompt_generated": True}, retry_count=2)'''.replace("__TOKEN__", token)

            return 200, {
                "ok": True,
                "token": token,
                "identity": identity,
                "ref_code": user["ref_code"],
                "ref_url": f"https://sharplogic.vercel.app/?ref={user['ref_code']}",
                "invited_count": invited,
                "unlocked_tiers": tiers,
                "install_cmd": f"curl -fsSL https://sharplogic.vercel.app/install.py | python3 - --token {token}",
                "in_agent_code": in_agent_sample,
            }

    if method == "POST":
        if path == "/api/access":
            import hashlib
            code = str(body.get("code", "")).strip().upper()
            if not code:
                return 400, {"ok": False, "error": "Please enter an invite code."}
            is_valid = code in VALID_INVITE_CODES or code.startswith("SL-")
            if not is_valid:
                return 403, {
                    "ok": False,
                    "error": f"Invalid code '{code}'. Use 'ETH-2026' from the launch tweet to unlock.",
                }
            
            def _apply_access(s):
                s["total_unlocked"] = s.get("total_unlocked", 0) + 1
                codes = s.setdefault("codes_used", {})
                codes[code] = codes.get(code, 0) + 1

            mutate_stats(_apply_access)

            token_hash = hashlib.sha256(f"sharplogic:access:{code}:{client_ip}".encode("utf-8")).hexdigest()[:24]
            return 200, {
                "ok": True,
                "code": code,
                "token": f"sl_access_{token_hash}",
                "message": "Access granted via invite code.",
                "install_cmd": "curl -fsSL https://sharplogic.vercel.app/install.py | python3 -",
            }

        if path == "/api/audit":
            sid = body.get("scenario_id", "ecommerce_promo")
            patched = bool(body.get("patched", False))
            custom_priors = body.get("custom_priors")
            llm_api_key = str(body.get("llm_api_key", "")).strip() or None
            try:
                def _inc_audit_post(s):
                    s["total_audits"] = s.get("total_audits", 0) + 1

                mutate_stats(_inc_audit_post)
                if sid == "custom":
                    raw_rules = str(body.get("raw_rules", ""))[:16000]
                    return 200, evaluate_custom_rules(
                        raw_rules, apply_patch=patched, llm_api_key=llm_api_key
                    )
                return 200, evaluate_scenario(sid, apply_patch=patched, custom_priors=custom_priors)
            except Exception as exc:
                return 400, {"error": str(exc)}

        if path == "/api/graph-audit":
            # Zero-friction browser trial: audit a workflow graph with the
            # same compiler + exact #k-SAT engine as the CLI/package path
            # (evaluate_custom_rules -> Autoformalizer trap encoding).
            # No signup, no install; verdicts are computed, never canned.
            graph = body.get("graph")
            if graph is None and ("nodes" in body or "edges" in body):
                graph = body  # the graph object may also be the whole body
            if isinstance(graph, str):
                try:
                    graph = json.loads(graph)
                except Exception:
                    graph = None
            if not isinstance(graph, dict):
                return 400, {
                    "ok": False,
                    "error": "Request body must be JSON of the form {\"graph\": {\"nodes\": [...], \"edges\": [{\"from\": ..., \"to\": ..., \"condition\": ...}], \"terminals\": [...]}}.",
                }
            nodes = graph.get("nodes")
            if not isinstance(nodes, list) or not nodes:
                return 400, {
                    "ok": False,
                    "error": "graph.nodes must be a non-empty list of node ids (strings or {\"id\": ...} objects).",
                }
            for nd in nodes:
                if isinstance(nd, dict):
                    if not (nd.get("id") or nd.get("name") or nd.get("key")):
                        return 400, {"ok": False, "error": "Each node object needs an 'id'."}
                elif not isinstance(nd, str):
                    return 400, {"ok": False, "error": "graph.nodes entries must be strings or objects with an 'id'."}
            edges = graph.get("edges", [])
            if not isinstance(edges, list):
                return 400, {"ok": False, "error": "graph.edges must be a list of {\"from\", \"to\", \"condition\"} objects."}
            for ed in edges:
                if isinstance(ed, dict):
                    src = ed.get("from") or ed.get("source") or ed.get("src")
                    dst = ed.get("to") or ed.get("target") or ed.get("dst")
                    if not src or not dst:
                        return 400, {"ok": False, "error": "Each edge needs a 'from' and a 'to' node id."}
                elif isinstance(ed, (list, tuple)) and len(ed) >= 2:
                    continue
                else:
                    return 400, {"ok": False, "error": "Each edge must be an object {\"from\", \"to\", \"condition\"} (or a [from, to] pair)."}
            terminals = graph.get("terminals", [])
            if terminals is not None and not isinstance(terminals, list):
                return 400, {"ok": False, "error": "graph.terminals must be a list of node ids."}
            try:
                res = evaluate_custom_rules(json.dumps(graph))
            except ValueError as exc:
                # Loud engine/compiler limits (e.g. trap encoding past
                # MAX_VARS variables) surface as-is, never truncated.
                return 400, {"ok": False, "error": str(exc)}
            except Exception as exc:
                return 400, {"ok": False, "error": f"Graph audit failed: {exc}"}
            ga = res.get("graph_analysis")
            if not ga:
                return 400, {"ok": False, "error": "Input was not recognized as an agent workflow graph (needs 'nodes' and 'edges')."}
            atoms = ga.get("condition_variables") or []
            if len(atoms) > 16:
                # Same loud limit as the standalone checker (install.py,
                # MAX_ATOMS = 16): the browser trial enumerates condition
                # assignments exactly, so it refuses instead of guessing.
                return 400, {
                    "ok": False,
                    "error": (
                        f"Graph uses {len(atoms)} distinct condition atoms; the browser trial "
                        "supports at most 16, the same limit as the standalone checker. "
                        "For larger graphs install the full package, which compiles the "
                        "graph to an exact CNF counter: curl -fsSL https://sharplogic.vercel.app/install.py | python3 -"
                    ),
                }
            audit = res["audit"]
            trap_count = int(audit["exact_count"])

            def _inc_graph_audit(s):
                s["total_audits"] = s.get("total_audits", 0) + 1

            mutate_stats(_inc_graph_audit)
            return 200, {
                "ok": True,
                "trap_count": trap_count,
                "total_assignments": 1 << len(atoms),
                "condition_variables": atoms,
                "structural_issues": ga.get("findings", []),
                "witnesses": list(res.get("trap_witness") or []),
                "solve_time_us": audit.get("solve_time_us"),
                "engine": (
                    f"sharplogic-core ({audit.get('engine_backend', 'exact #k-SAT counter')}): "
                    "your graph was compiled to a trap-encoding CNF and counted exactly - no sampling, no canned verdicts."
                ),
                "verdict": "traps_found" if trap_count > 0 else "clean",
            }

        if path == "/api/manifold/recall":
            query = str(body.get("query", "refund payout below cost"))[:512]
            engine = get_engine()
            top1 = engine.recall_top1(query)
            return 200, {
                "query": query,
                "top_match": top1,
                "active_slots": engine.active_memory_slots(),
            }

        if path == "/api/manifold/snapshot":
            engine = get_engine()
            t0 = time.perf_counter()
            bytes_written = engine.save_snapshot(SNAPSHOT_FILE)
            save_ms = (time.perf_counter() - t0) * 1000.0
            t1 = time.perf_counter()
            engine.load_snapshot(SNAPSHOT_FILE)
            load_ms = (time.perf_counter() - t1) * 1000.0
            return 200, {
                "status": "persisted",
                "magic_header": "SLGC",
                "bytes_written": bytes_written,
                "save_time_ms": round(save_ms, 4),
                "load_time_ms": round(load_ms, 4),
                "active_slots": engine.active_memory_slots(),
            }

        if path == "/api/waitlist":
            import hashlib
            email = str(body.get("email", "")).strip()[:120]
            role = str(body.get("role", "AI Engineer")).strip()[:120]
            if not email or "@" not in email or "." not in email.split("@")[-1]:
                return 400, {"error": "Please enter a valid work email."}
            token_hash = hashlib.sha256(f"sharplogic:{email.lower()}".encode("utf-8")).hexdigest()[:20]
            sandbox_token = f"sl_sandbox_{token_hash}"
            entry = {
                "email": email,
                "role": role,
                "sandbox_token": sandbox_token,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            append_waitlist_entry(entry)
            get_engine().ingest_event(
                f"WAITLIST_SIGNUP: {email} ({role})",
                domain_tag=9,
                loophole_count=0,
                importance=0.9,
                provenance=1.0,
            )
            return 200, {"status": "joined", "entry": entry}

    return 404, {"error": f"Unknown endpoint: {method} {path}"}


class SharpLogicRequestHandler(SimpleHTTPRequestHandler):
    """Serves Web UI static assets and JSON REST API endpoints with concurrency & security guards."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(f"[SharpLogic HTTP] {self.address_string()} - {fmt % args}\n")

    def _send_json(self, payload: Dict[str, Any], status: int = 200) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self) -> None:
        self._send_json({"ok": True})

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            client_ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
            status, payload = dispatch_api_request(
                "GET", parsed.path, parse_qs(parsed.query), None, client_ip
            )
            self._send_json(payload, status=status)
            return

        if parsed.path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_PAYLOAD_BYTES:
            self._send_json({"error": "Payload too large (max 64KB)"}, status=413)
            return
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
        try:
            body = json.loads(raw_body) if raw_body else {}
        except Exception:
            body = {}

        client_ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
        status, payload = dispatch_api_request(
            "POST", parsed.path, parse_qs(parsed.query), body, client_ip
        )
        self._send_json(payload, status=status)


def run_server(host: str = "0.0.0.0", port: int = 8765) -> None:
    ensure_seeded()
    httpd = ThreadingHTTPServer((host, port), SharpLogicRequestHandler)
    print(f"\n==================================================================")
    print(f"  SharpLogic (#F) Production Multi-Threaded Server")
    print(f"  Engine Backend   : {'Native Rust C-ABI' if get_engine().using_native_rust else 'Serverless Exact Kernel'}")
    print(f"  Listening on     : http://{host}:{port} (Local: http://127.0.0.1:{port})")
    print(f"==================================================================\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down SharpLogic server...")
        httpd.server_close()


if __name__ == "__main__":
    host_arg = os.environ.get("HOST", "0.0.0.0")
    port_arg = int(os.environ.get("PORT", "8765"))
    run_server(host=host_arg, port=port_arg)
