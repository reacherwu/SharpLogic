"""
Vercel Python Serverless Function Entrypoint (api/index.py).
Routes all /api/* requests and fallback UI requests through SharpLogic's production dispatcher.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PYTHON_DIR = os.path.join(ROOT_DIR, "python")
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if PYTHON_DIR not in sys.path:
    sys.path.insert(0, PYTHON_DIR)

from server import MAX_PAYLOAD_BYTES, WEB_DIR, dispatch_api_request  # noqa: E402


class handler(BaseHTTPRequestHandler):
    """Vercel Serverless Python Handler."""

    def _resolve_api_path(self) -> tuple[str, dict]:
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if "__path" in qs and qs["__path"]:
            real_path = qs["__path"][0]
            if not real_path.startswith("/"):
                real_path = "/" + real_path
            return real_path, qs
        return parsed.path, qs

    def _send_json(self, payload: dict, status: int = 200) -> None:
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
        real_path, qs = self._resolve_api_path()
        if real_path in ("/", "/index.html"):
            index_file = os.path.join(WEB_DIR, "index.html")
            if os.path.exists(index_file):
                with open(index_file, "rb") as f:
                    html = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return

        client_ip = self.headers.get("x-forwarded-for", "127.0.0.1").split(",")[0].strip()
        status, payload = dispatch_api_request("GET", real_path, qs, None, client_ip)
        self._send_json(payload, status=status)

    def do_POST(self) -> None:
        real_path, qs = self._resolve_api_path()
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_PAYLOAD_BYTES:
            self._send_json({"error": "Payload too large (max 64KB)"}, status=413)
            return
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
        try:
            body = json.loads(raw_body) if raw_body else {}
        except Exception:
            body = {}

        client_ip = self.headers.get("x-forwarded-for", "127.0.0.1").split(",")[0].strip()
        status, payload = dispatch_api_request("POST", real_path, qs, body, client_ip)
        self._send_json(payload, status=status)
