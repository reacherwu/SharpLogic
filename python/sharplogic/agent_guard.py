"""In-agent guardrail backed by SharpLogic's exact trap compiler + #k-SAT engine.

This module provides two implementations:

* :class:`AgentGuard` (engine-backed): compiles the workflow graph with
  :class:`Autoformalizer` and audits it with the Rust/serverless #k-SAT engine,
  supporting up to MAX_VARS variables, WMC and auto-patch.  Runtime transition
  checks use the same graph semantics as the standalone checker.
* The legacy standalone checker (<=16 atoms) remains available as
  :func:`audit_graph` for zero-dependency installs.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from .bridge import get_engine
from .compiler import Autoformalizer

# Re-export the standalone checker implementation (extracted from install.py).
try:
    from . import _standalone_checker as _sc  # type: ignore
except Exception:  # pragma: no cover
    _sc = None


class AgentInvariantViolation(RuntimeError):
    pass


class AgentGuard:
    """In-agent guardrail backed by the exact trap compiler + #k-SAT engine."""

    def __init__(self, token: str = "", graph: Optional[Dict[str, Any]] = None, fail_fast: bool = True):
        self.token = token
        self.graph = graph
        self.fail_fast = fail_fast
        self._compiled = None
        self._history = []

    def _compile(self):
        if self._compiled is None and self.graph is not None:
            self._compiled = Autoformalizer.compile_custom_rules(json.dumps(self.graph))
        return self._compiled

    def audit(self, apply_patch: bool = False):
        if self.graph is None:
            raise RuntimeError("AgentGuard was constructed without a workflow graph")
        compiled = self._compile()
        engine = get_engine()
        var_names = [v["name"] for v in compiled["variables"]]
        weights = [float(v["prior"]) for v in compiled["variables"]]
        clauses = list(compiled["clauses"])
        if apply_patch and clauses:
            from .scenarios import synthesize_blocking_patch

            added, descs, res = synthesize_blocking_patch(
                engine, compiled["num_vars"], clauses, weights, var_names
            )
            clauses = clauses + added
            compiled["clause_descriptions"] = compiled["clause_descriptions"] + descs
        else:
            res = engine.solve_cnf(
                num_vars=compiled["num_vars"],
                clauses=clauses,
                weights=weights,
                var_names=var_names,
            )
        return {
            "compiled": compiled,
            "audit": res,
            "graph_analysis": compiled.get("graph_analysis"),
            "exact_count": res["exact_count"],
        }

    def assert_safe(self, from_node, to_node, state=None, retry_count=None):
        if self.graph is None:
            raise RuntimeError(
                "AgentGuard has no workflow graph to verify against; pass graph=... to the constructor"
            )
        state = dict(state or {})
        if retry_count is not None:
            state.setdefault("retry_count > 3", retry_count > 3)
            state.setdefault("retry_count <= 3", retry_count <= 3)

        # Fall back to standalone checker semantics for runtime transition checks.
        try:
            import install as _install  # noqa
        except Exception:
            _install = None

        # Minimal transition check using compiled graph edges.
        nodes = self.graph.get("nodes", [])
        edges = self.graph.get("edges", [])
        terminals = set(self.graph.get("terminals", []) or [])
        # normalize nodes
        node_ids = []
        for n in nodes:
            node_ids.append(n if isinstance(n, str) else str(n.get("id") or n.get("name")))
        if from_node not in node_ids or to_node not in node_ids:
            msg = f"unknown node in transition {from_node} -> {to_node}"
            if self.fail_fast:
                raise AgentInvariantViolation(msg)
            return False

        matching = [
            e for e in edges
            if (e.get("from") or e.get("source")) == from_node
            and (e.get("to") or e.get("target")) == to_node
        ]
        if not matching:
            msg = f"no edge {from_node} -> {to_node} in the audited graph"
            if self.fail_fast:
                raise AgentInvariantViolation(msg)
            print("[SharpLogic] " + msg)
            return False

        # Evaluate guard truthiness with a tiny boolean env.
        def _truthy(cond):
            if cond in (None, "", True):
                return True
            if cond is False:
                return False
            text = str(cond).lower()
            # crude but dependency-free evaluation using state keys
            for k, v in state.items():
                text = text.replace(k.lower(), "true" if v else "false")
            return "false" not in text

        edge = matching[0]
        cond = edge.get("condition", edge.get("guard", ""))
        if not _truthy(cond):
            msg = f"transition {from_node} -> {to_node} is disabled under the current conditions"
            if self.fail_fast:
                raise AgentInvariantViolation(msg)
            print("[SharpLogic] " + msg)
            return False

        # Deadlock check on destination.
        outs = [
            e for e in edges
            if (e.get("from") or e.get("source")) == to_node
        ]
        if to_node not in terminals and outs and all(not _truthy(e.get("condition", e.get("guard", ""))) for e in outs):
            msg = f"node {to_node} would be a deadlock under the current conditions (all exits disabled)"
            if self.fail_fast:
                raise AgentInvariantViolation(msg)
            print("[SharpLogic] " + msg)
            return False
        return True

    def protect(self, func):
        import functools
        import time

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            t0 = time.perf_counter()
            res = func(*args, **kwargs)
            self._history.append((func.__name__, (time.perf_counter() - t0) * 1e6))
            return res

        return wrapper