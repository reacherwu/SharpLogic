"""Helpers to convert common agent framework exports into SharpLogic graphs."""

from __future__ import annotations

from typing import Any, Dict, List


def from_langgraph(nodes: List[str], edges: List[Dict[str, Any]], terminals=None) -> Dict[str, Any]:
    return {
        "nodes": nodes,
        "terminals": terminals or [],
        "edges": [
            {
                "from": e.get("source") or e.get("from"),
                "to": e.get("target") or e.get("to"),
                "condition": e.get("condition") or e.get("guard") or "",
            }
            for e in edges
        ],
    }
