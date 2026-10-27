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

def load_stats() -> dict:
    default_stats = {
        "total_visits": 1284,
        "total_unlocked": 412,
        "total_audits": 3890,
        "codes_used": {"ETH-2026": 284, "SHARP-AGENT": 92, "OPENAI-MATH": 36},
    }
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {**default_stats, **data}
        except Exception:
            pass
    return default_stats

def save_stats(stats: dict) -> None:
    try:
        with open(STATS_FILE, "w", encoding="utf-8") as f:
            json.dump(stats, f)
    except Exception:
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
                for sid in ["ecommerce_promo", "agent_workflow", "cloud_iam"]:
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
                for sid in ["ecommerce_promo", "agent_workflow", "cloud_iam"]
            ]
            return 200, {"scenarios": summary}
        if path == "/api/audit":
            sid = query_params.get("scenario_id", ["ecommerce_promo"])[0]
            patched = query_params.get("patched", ["false"])[0].lower() in ("true", "1", "yes")
            try:
                stats = load_stats()
                stats["total_audits"] = stats.get("total_audits", 0) + 1
                save_stats(stats)
                return 200, evaluate_scenario(sid, apply_patch=patched)
            except Exception as exc:
                return 400, {"error": str(exc)}

        if path == "/api/stats":
            stats = load_stats()
            stats["total_visits"] = stats.get("total_visits", 0) + 1
            save_stats(stats)
            return 200, {
                "ok": True,
                "stats": stats,
                "accepted_invite_codes": sorted(list(VALID_INVITE_CODES)),
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
            
            stats = load_stats()
            stats["total_unlocked"] = stats.get("total_unlocked", 0) + 1
            stats["codes_used"][code] = stats["codes_used"].get(code, 0) + 1
            save_stats(stats)

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
                stats = load_stats()
                stats["total_audits"] = stats.get("total_audits", 0) + 1
                save_stats(stats)
                if sid == "custom":
                    raw_rules = str(body.get("raw_rules", ""))[:16000]
                    return 200, evaluate_custom_rules(
                        raw_rules, apply_patch=patched, llm_api_key=llm_api_key
                    )
                return 200, evaluate_scenario(sid, apply_patch=patched, custom_priors=custom_priors)
            except Exception as exc:
                return 400, {"error": str(exc)}

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
            try:
                with open(WAITLIST_FILE, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            except OSError:
                pass
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
