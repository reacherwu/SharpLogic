#!/usr/bin/env python3
"""
SharpLogic Production Multi-Threaded HTTP Server & Serverless Router.
Includes:
- ThreadingHTTPServer for concurrent traffic spikes (X / Hacker News launches)
- Strictly Bounded O(K) IP Rate Limiter (MAX_IPS = 256)
- Payload size protection (64 KB hard cap)
- Read-only serverless filesystem detection (/tmp fallback for Vercel Lambda)
"""

import html as _html
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
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
LEADS_FILE = os.path.join(_WRITABLE_DIR, "sharplogic_leads.json")

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


class StorageError(RuntimeError):
    """A database-backed write could not be completed safely.

    Raised instead of ever falling back to a default/file document on a
    write path: on 2026-10-29 a transient Neon cold-start failure made
    mutate_stats load an empty default doc and then persist it over the
    real counters (visits 21 / audits 16 silently reset to ~0). Write
    paths now fail loudly and write nothing.
    """


_DB_RETRY_DELAY_SECONDS = 0.5


def _db_retry(fn, what: str):
    """Run fn() (each attempt opens a fresh connection); on failure retry
    once after a short pause - a suspended Neon free-tier compute may need
    a moment to wake - then raise StorageError. Write paths only."""
    try:
        return fn()
    except StorageError:
        raise
    except Exception:
        time.sleep(_DB_RETRY_DELAY_SECONDS)
        try:
            return fn()
        except Exception as exc:
            raise StorageError(f"postgres {what} failed after retry: {exc}") from exc


_STATS_COUNTERS = ("total_visits", "total_audits", "total_unlocked")


def _merge_stats_monotonic(stored, incoming) -> dict:
    """Merge an incoming stats doc over the stored doc so a save can never
    regress stored data: counters keep the higher value per counter; dict
    entries are unioned - stored identity fields win on conflict, while
    numeric progress fields (invited_count, codes_used counts) keep the
    higher value so legitimate increments are never lost either."""
    if not isinstance(stored, dict):
        return incoming
    if not isinstance(incoming, dict):
        return stored
    merged = {**stored, **incoming}
    for key in _STATS_COUNTERS:
        try:
            merged[key] = max(int(stored.get(key, 0) or 0), int(incoming.get(key, 0) or 0))
        except (TypeError, ValueError):
            merged[key] = stored.get(key, incoming.get(key, 0))
    stored_users, incoming_users = stored.get("users"), incoming.get("users")
    if isinstance(stored_users, dict) and isinstance(incoming_users, dict):
        users = dict(incoming_users)
        for token, s_user in stored_users.items():
            if token not in users:
                users[token] = s_user
            elif isinstance(s_user, dict) and isinstance(users[token], dict):
                u = {**users[token], **s_user}
                try:
                    u["invited_count"] = max(
                        int(s_user.get("invited_count", 0) or 0),
                        int(users[token].get("invited_count", 0) or 0),
                    )
                except (TypeError, ValueError):
                    pass
                users[token] = u
        merged["users"] = users
    stored_codes, incoming_codes = stored.get("codes_used"), incoming.get("codes_used")
    if isinstance(stored_codes, dict) and isinstance(incoming_codes, dict):
        codes = dict(stored_codes)
        for code, count in incoming_codes.items():
            try:
                codes[code] = max(int(codes.get(code, 0) or 0), int(count or 0))
            except (TypeError, ValueError):
                codes.setdefault(code, count)
        merged["codes_used"] = codes
    stored_refs, incoming_refs = stored.get("referral_codes"), incoming.get("referral_codes")
    if isinstance(stored_refs, dict) and isinstance(incoming_refs, dict):
        merged["referral_codes"] = {**incoming_refs, **stored_refs}
    return merged


def _db_save_stats_doc(doc) -> None:
    """Persist the stats doc under a row lock, merged monotonically against
    the currently stored doc inside the same transaction, so no save -
    however stale its in-memory copy - can lower a counter or drop a
    stored user/code. Retried once, then StorageError (nothing written)."""

    def _save():
        conn = _db_connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT doc FROM sharplogic_store WHERE key = %s FOR UPDATE", ("stats",))
            row = cur.fetchone()
            if row is None:
                cur.execute(
                    "INSERT INTO sharplogic_store (key, doc, updated_at) VALUES (%s, %s::jsonb, now()) "
                    "ON CONFLICT (key) DO NOTHING",
                    ("stats", json.dumps(doc)),
                )
            else:
                stored = row[0] if isinstance(row[0], dict) else json.loads(row[0])
                merged = _merge_stats_monotonic(stored, doc)
                cur.execute(
                    "UPDATE sharplogic_store SET doc = %s::jsonb, updated_at = now() WHERE key = %s",
                    (json.dumps(merged), "stats"),
                )
            conn.commit()
            cur.close()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()

    _db_retry(_save, "save stats")


def load_stats() -> dict:
    """Read-only load. Degrades gracefully (file, then defaults) so a DB
    outage never breaks pure reads - but the result of a degraded read is
    only ever served, never persisted: every write path below uses the
    strict loaders instead."""
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


def load_stats_for_write() -> dict:
    """Load the stats doc for a read-modify-write path (registration).

    In DB mode this NEVER falls back to a default/file document after a DB
    error: the load is retried once and StorageError is raised, so a
    transient outage surfaces as a 500 instead of letting a near-empty
    doc be saved over the real one."""
    if _database_url():
        data = _db_retry(lambda: _db_load_doc("stats", _default_stats()), "load stats")
        return {**_default_stats(), **data}
    return load_stats()


def save_stats(stats: dict) -> None:
    if _database_url():
        # Strict + monotonic-guarded (see _db_save_stats_doc): raises
        # StorageError and writes nothing when the DB is unreachable.
        _db_save_stats_doc(stats)
        return
    try:
        with open(STATS_FILE, "w", encoding="utf-8") as f:
            json.dump(stats, f)
    except Exception:
        pass


def mutate_stats(fn) -> dict:
    """Run fn(stats) as one atomic read-modify-write; returns final stats."""
    if _database_url():
        def _apply(doc):
            merged = {**_default_stats(), **doc}
            before = {k: merged.get(k, 0) for k in _STATS_COUNTERS}
            fn(merged)
            # Monotonic guard: a mutation may never lower a counter,
            # even if fn (or a future caller) tries to set one back.
            for k in _STATS_COUNTERS:
                try:
                    if int(merged.get(k, 0) or 0) < int(before.get(k, 0) or 0):
                        merged[k] = before[k]
                except (TypeError, ValueError):
                    merged[k] = before[k]
            doc.clear()
            doc.update(merged)

        _, doc = _db_retry(
            lambda: _db_mutate_doc("stats", _default_stats(), _apply), "mutate stats"
        )
        return {**_default_stats(), **doc}
    stats = load_stats()
    fn(stats)
    save_stats(stats)
    return stats


def append_waitlist_entry(entry: dict) -> None:
    if _database_url():
        def _append(lst):
            lst.append(entry)

        _db_retry(lambda: _db_mutate_doc("waitlist", [], _append), "append waitlist entry")
        return
    try:
        with open(WAITLIST_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Trial report leads (POST /api/report).
#
# A visitor who runs the browser trial can ask for the full report by
# email - the value-exchange moment right after they see their trap
# count. Leads live in one JSON document (key "leads" in the Postgres
# store, LEADS_FILE locally) written through the SAME strict path as the
# counters: in DB mode the append is one locked transaction, retried
# once, and raises StorageError without writing anything on failure -
# never a silent file/default fallback (the 2026-10-29 reset rule).
# Reads degrade gracefully like load_stats. The daily send caps below
# are counted from this doc.
# ---------------------------------------------------------------------------

def load_leads() -> list:
    """Read-only load of the leads doc (DB -> file -> [])."""
    if _database_url():
        try:
            data = _db_load_doc("leads", [])
            return data if isinstance(data, list) else []
        except Exception:
            pass  # fall through to file so a DB outage never breaks reads
    if os.path.exists(LEADS_FILE):
        try:
            with open(LEADS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            pass
    return []


def append_lead(entry: dict) -> None:
    """Append one lead. DB mode: atomic mutate of the "leads" doc,
    retried once, StorageError on failure (nothing written, no file
    fallback). File mode: read-modify-write of the local JSON doc."""
    if _database_url():
        def _append(lst):
            lst.append(entry)

        _db_retry(lambda: _db_mutate_doc("leads", [], _append), "append lead")
        return
    leads = load_leads()
    leads.append(entry)
    with open(LEADS_FILE, "w", encoding="utf-8") as f:
        json.dump(leads, f)


_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$"
)


def _valid_email(email: str) -> bool:
    return 0 < len(email) <= 254 and bool(_EMAIL_RE.match(email))


REPORT_DAILY_CAP = 3  # max report emails per email address / per IP per day


def _report_cap_hit(leads: list, email: str, client_ip: str) -> Optional[str]:
    """Return "email" or "ip" when today's stored *sent* leads reach the
    daily cap for this address/IP, else None. Leads recorded as
    send_failed never consume cap - a Resend outage must not lock a
    visitor out."""
    today = time.strftime("%Y-%m-%d", time.gmtime())
    email_hits = 0
    ip_hits = 0
    for lead in leads:
        if not isinstance(lead, dict) or lead.get("status") != "sent":
            continue
        if str(lead.get("ts", ""))[:10] != today:
            continue
        if str(lead.get("email", "")).strip().lower() == email.lower():
            email_hits += 1
        if lead.get("ip") == client_ip:
            ip_hits += 1
    if email_hits >= REPORT_DAILY_CAP:
        return "email"
    if ip_hits >= REPORT_DAILY_CAP:
        return "ip"
    return None


def _extract_graph(body: Dict[str, Any]) -> Tuple[Optional[dict], Optional[Tuple[int, Dict[str, Any]]]]:
    """Structural validation of a workflow-graph payload, shared by
    POST /api/graph-audit and POST /api/report so both endpoints accept
    and refuse exactly the same shapes. Returns (graph, None) on success
    or (None, (status, payload)) carrying the trial endpoint's 400."""
    graph = body.get("graph")
    if graph is None and ("nodes" in body or "edges" in body):
        graph = body  # the graph object may also be the whole body
    if isinstance(graph, str):
        try:
            graph = json.loads(graph)
        except Exception:
            graph = None
    if not isinstance(graph, dict):
        return None, (400, {
            "ok": False,
            "error": "Request body must be JSON of the form {\"graph\": {\"nodes\": [...], \"edges\": [{\"from\": ..., \"to\": ..., \"condition\": ...}], \"terminals\": [...]}}.",
        })
    nodes = graph.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        return None, (400, {
            "ok": False,
            "error": "graph.nodes must be a non-empty list of node ids (strings or {\"id\": ...} objects).",
        })
    for nd in nodes:
        if isinstance(nd, dict):
            if not (nd.get("id") or nd.get("name") or nd.get("key")):
                return None, (400, {"ok": False, "error": "Each node object needs an 'id'."})
        elif not isinstance(nd, str):
            return None, (400, {"ok": False, "error": "graph.nodes entries must be strings or objects with an 'id'."})
    edges = graph.get("edges", [])
    if not isinstance(edges, list):
        return None, (400, {"ok": False, "error": "graph.edges must be a list of {\"from\", \"to\", \"condition\"} objects."})
    for ed in edges:
        if isinstance(ed, dict):
            src = ed.get("from") or ed.get("source") or ed.get("src")
            dst = ed.get("to") or ed.get("target") or ed.get("dst")
            if not src or not dst:
                return None, (400, {"ok": False, "error": "Each edge needs a 'from' and a 'to' node id."})
        elif isinstance(ed, (list, tuple)) and len(ed) >= 2:
            continue
        else:
            return None, (400, {"ok": False, "error": "Each edge must be an object {\"from\", \"to\", \"condition\"} (or a [from, to] pair)."})
    terminals = graph.get("terminals", [])
    if terminals is not None and not isinstance(terminals, list):
        return None, (400, {"ok": False, "error": "graph.terminals must be a list of node ids."})
    return graph, None


def _run_exact_graph_audit(graph: dict):
    """Run the real chain (evaluate_custom_rules -> Autoformalizer trap
    encoding -> exact #k-SAT engine) for a structurally valid graph, the
    same path POST /api/graph-audit uses. Returns (result, atoms, None)
    or (None, None, (status, payload)). The emailed report needs exact
    counts and witnesses, so the >16-atom trial limit is a loud 400
    here too - no sampled fallback."""
    try:
        res = evaluate_custom_rules(json.dumps(graph))
    except ValueError as exc:
        # Loud engine/compiler limits (e.g. trap encoding past MAX_VARS).
        return None, None, (400, {"ok": False, "error": str(exc)})
    except Exception as exc:
        return None, None, (400, {"ok": False, "error": f"Graph audit failed: {exc}"})
    ga = res.get("graph_analysis")
    if not ga:
        return None, None, (400, {"ok": False, "error": "Input was not recognized as an agent workflow graph (needs 'nodes' and 'edges')."})
    atoms = ga.get("condition_variables") or []
    if len(atoms) > 16:
        return None, None, (400, {
            "ok": False,
            "error": (
                f"Graph uses {len(atoms)} distinct condition atoms; emailed reports are "
                "exact counts, and this exact path supports at most 16 condition atoms "
                "per graph. Split the graph, or install the full package: "
                "curl -fsSL https://sharplogic.vercel.app/install.py | python3 -"
            ),
        })
    return res, atoms, None


def _format_percent(part: int, whole: int) -> str:
    if whole <= 0 or part <= 0:
        return "0%"
    pct = (100.0 * part) / whole
    return ("%.4f" % pct).rstrip("0").rstrip(".") + "%"


def _build_report(res: dict, atoms: list) -> Tuple[str, str, str]:
    """(subject, text, html) for one audit result. Every number comes
    from the server's own engine run - never from the client."""
    audit = res["audit"]
    exact_count = int(audit["exact_count"])
    total_space = 1 << len(atoms)
    pct = _format_percent(exact_count, total_space)
    solve_us = audit.get("solve_time_us")
    witnesses = [str(w) for w in (res.get("trap_witness") or [])][:10]
    findings = (res.get("graph_analysis") or {}).get("findings") or []

    if exact_count > 0:
        meaning = (
            "What this means: each trap assignment is one concrete combination of guard "
            "conditions under which the workflow can stall forever (deadlock/livelock) or "
            "run into a dead end. Sampled evals almost never land on these exact "
            "combinations - exact counting enumerates all of them."
        )
    else:
        meaning = (
            "What this means: no condition assignment traps this workflow - every "
            "reachable state keeps at least one enabled path to a terminal node."
        )

    subject = f"SharpLogic report: #F = {exact_count:,} trap assignments in your workflow graph"

    lines = [
        "SharpLogic - exact trap-state audit of your workflow graph",
        "",
        f"Trap assignments (#F): {exact_count:,}",
        f"Total condition assignments: {total_space:,}",
        f"Share that traps: {pct}",
        f"Counted exactly in {solve_us} µs (no sampling).",
        f"Conditions audited: {', '.join(atoms) if atoms else '(none)'}",
        "",
    ]
    if witnesses:
        lines.append("Trap witnesses (where it gets stuck):")
        lines += [f"  - {w}" for w in witnesses]
        lines.append("")
    if findings:
        lines.append("Structural findings:")
        for f in findings[:10]:
            nodes = ", ".join(str(n) for n in (f.get("nodes") or []))
            lines.append(f"  - [{f.get('type')}] ({f.get('severity')}) at {nodes} - {f.get('detail')}")
        lines.append("")
    lines += [
        meaning,
        "",
        "Re-run or audit another graph: https://sharplogic.vercel.app/#try",
        "Full CLI + source (MIT): https://github.com/reacherwu/SharpLogic",
        "",
        "You received this because you requested the full report from the SharpLogic browser trial.",
    ]
    text_body = "\n".join(lines)

    esc = _html.escape
    wit_html = ""
    if witnesses:
        wit_html = (
            "<h3>Trap witnesses (where it gets stuck)</h3><ul>"
            + "".join(f"<li>{esc(w)}</li>" for w in witnesses)
            + "</ul>"
        )
    find_html = ""
    if findings:
        items = "".join(
            f"<li><b>{esc(str(f.get('type')))}</b> ({esc(str(f.get('severity')))}) at "
            f"{esc(', '.join(str(n) for n in (f.get('nodes') or [])))} - {esc(str(f.get('detail')))}</li>"
            for f in findings[:10]
        )
        find_html = f"<h3>Structural findings</h3><ul>{items}</ul>"
    html_body = f"""<!doctype html><html><body style="font-family: ui-monospace, Menlo, Consolas, monospace; color: #24292f; line-height: 1.6;">
<h2>SharpLogic &mdash; exact trap-state audit</h2>
<p><b>Trap assignments (#F): {exact_count:,}</b><br>
Total condition assignments: {total_space:,}<br>
Share that traps: {esc(pct)}<br>
Counted exactly in {esc(str(solve_us))} &micro;s &mdash; no sampling.<br>
Conditions audited: {esc(', '.join(atoms) if atoms else '(none)')}</p>
{wit_html}{find_html}
<p>{esc(meaning)}</p>
<p>Re-run or audit another graph: <a href="https://sharplogic.vercel.app/#try">sharplogic.vercel.app/#try</a><br>
Full CLI + source (MIT): <a href="https://github.com/reacherwu/SharpLogic">github.com/reacherwu/SharpLogic</a></p>
<p style="color:#57606a; font-size: 12px;">You received this because you requested the full report from the SharpLogic browser trial.</p>
</body></html>"""
    return subject, text_body, html_body


_RESEND_API_URL = "https://api.resend.com/emails"
_REPORT_FROM = "SharpLogic <hello@mail.quotalis.app>"
_RESEND_KEY_ENV_NAME = "RESEND" + "_API" + "_KEY"


def _send_report_email(to_email: str, subject: str, text_body: str, html_body: str):
    """Send one report email via the Resend API. Returns (message_id,
    None) when Resend accepts the message, (None, error) otherwise -
    callers must treat a None id as "not delivered"."""
    api_key = os.environ.get(_RESEND_KEY_ENV_NAME, "").strip()
    if not api_key:
        return None, "email service is not configured (RESEND_API_KEY is not set)"
    payload = json.dumps({
        "from": _REPORT_FROM,
        "to": [to_email],
        "subject": subject,
        "text": text_body,
        "html": html_body,
    }).encode("utf-8")
    req = urllib.request.Request(
        _RESEND_API_URL,
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", "replace")[:300]
        except Exception:
            detail = ""
        return None, f"Resend API HTTP {exc.code}: {detail}"
    except Exception as exc:
        return None, f"email send failed: {exc}"
    message_id = data.get("id") if isinstance(data, dict) else None
    if not message_id:
        return None, f"Resend accepted the request but returned no message id: {str(data)[:200]}"
    return message_id, None


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
    """Pure in-process API router (used by local ThreadingHTTPServer, Vercel Function, and tests).

    A StorageError from any write path becomes a 500 and guarantees the
    request wrote nothing - the failure mode it replaces silently reset
    the production counters to ~0 on 2026-10-29."""
    try:
        return _dispatch_api_request(method, path, query_params, body, client_ip)
    except StorageError as exc:
        return 500, {"ok": False, "error": f"Storage temporarily unavailable; nothing was written. ({exc})"}


def _dispatch_api_request(
    method: str,
    path: str,
    query_params: Optional[Dict[str, List[str]]] = None,
    body: Optional[Dict[str, Any]] = None,
    client_ip: str = "127.0.0.1",
) -> Tuple[int, Dict[str, Any]]:
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
            except StorageError:
                raise  # storage outage -> 500 via dispatcher, never a silent 400
            except Exception as exc:
                return 400, {"error": str(exc)}

        if path == "/api/stats":
            def _inc_visit(s):
                s["total_visits"] = s.get("total_visits", 0) + 1

            stats = mutate_stats(_inc_visit)
            # Funnel visibility: the stored report-lead count rides along
            # on this response copy only - it is never persisted into the
            # stats doc itself.
            stats["leads"] = len(load_leads())
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

            stats = load_stats_for_write()
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
         "condition": ""},
        {"from": "Tool_Executor", "to": "Human_Approval_Gate",
         "condition": "not tool_timeout and not execution_error"},
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
            except StorageError:
                raise  # storage outage -> 500 via dispatcher, never a silent 400
            except Exception as exc:
                return 400, {"error": str(exc)}

        if path == "/api/graph-audit":
            # Zero-friction browser trial: audit a workflow graph with the
            # same compiler + exact #k-SAT engine as the CLI/package path
            # (evaluate_custom_rules -> Autoformalizer trap encoding).
            # No signup, no install; verdicts are computed, never canned.
            graph, graph_error = _extract_graph(body)
            if graph_error is not None:
                return graph_error
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
            fallback = bool(body.get("fallback", False))
            if len(atoms) > 16 and not fallback:
                # Loud limit by default; opt-in structural-only fallback
                # for oversized graphs (productized "tiered audit").
                return 400, {
                    "ok": False,
                    "error": (
                        f"Graph uses {len(atoms)} distinct condition atoms; the browser trial "
                        "supports at most 16 exactly. Re-send with {\"fallback\": true} for "
                        "structural analysis only (no exact count or estimate is computed), "
                        "or install the full package for exact CNF counting: "
                        "curl -fsSL https://sharplogic.vercel.app/install.py | python3 -"
                    ),
                }
            if len(atoms) > 16 and fallback:
                # Structural-only fallback: findings from the compiler's
                # structural layer.  No exact count and no sampled
                # estimate exists in this mode - trap_count stays null.
                return 200, {
                    "ok": True,
                    "trap_count": None,
                    "estimated_trap_rate": None,
                    "total_assignments": 1 << len(atoms) if len(atoms) < 63 else None,
                    "condition_variables": atoms,
                    "structural_issues": ga.get("findings", []),
                    "witnesses": [],
                    "solve_time_us": res["audit"].get("solve_time_us"),
                    "engine": "sharplogic-core (structural fallback): exact counting unavailable beyond 16 atoms; install the full package for exact CNF counts.",
                    "verdict": "structural_fallback",
                    "note": "Oversized graph: returning structural analysis only. Use the full package for exact counts.",
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

        if path == "/api/report":
            # Email capture at the value-exchange moment: the visitor just
            # ran the browser trial and saw their trap count. The server
            # re-runs the SAME graph itself (client-supplied counts are
            # never trusted), emails the full report via Resend, and
            # stores the lead. Send-then-store: a failed send is recorded
            # as send_failed and answered 502; a stored lead marked
            # "sent" always means Resend accepted the message. If the
            # lead write itself fails in DB mode, StorageError surfaces
            # as a loud 500 via the dispatcher (never a silent success).
            email = str(body.get("email", "")).strip()[:254]
            if not _valid_email(email):
                return 400, {"ok": False, "error": "Please enter a valid email address."}
            graph, graph_error = _extract_graph(body)
            if graph_error is not None:
                return graph_error
            res, atoms, audit_error = _run_exact_graph_audit(graph)
            if audit_error is not None:
                return audit_error
            cap_hit = _report_cap_hit(load_leads(), email, client_ip)
            if cap_hit == "email":
                return 429, {"ok": False, "error": "This email address has already received 3 reports today. Please try again tomorrow."}
            if cap_hit == "ip":
                return 429, {"ok": False, "error": "Too many report emails have been sent from this network today. Please try again tomorrow."}
            subject, text_body, html_body = _build_report(res, atoms)
            message_id, send_error = _send_report_email(email, subject, text_body, html_body)
            entry = {
                "email": email,
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "exact_count": int(res["audit"]["exact_count"]),
                "total_space": 1 << len(atoms),
                "source": "browser-trial",
                "ip": client_ip,
                "status": "sent" if message_id else "send_failed",
            }
            append_lead(entry)
            if not message_id:
                return 502, {
                    "ok": False,
                    "error": (
                        f"The report email could not be sent: {send_error}. "
                        "Your audit result above still stands - please try again in a moment."
                    ),
                }
            return 200, {
                "ok": True,
                "sent": True,
                "email": email,
                "message_id": message_id,
                "exact_count": entry["exact_count"],
                "total_space": entry["total_space"],
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
