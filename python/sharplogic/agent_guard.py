"""In-agent guardrail backed by SharpLogic's exact trap compiler + #k-SAT engine.

* :class:`AgentGuard` (engine-backed): compiles the workflow graph with
  :class:`Autoformalizer` and audits it with the Rust/serverless #k-SAT engine,
  supporting up to MAX_VARS variables, WMC and auto-patch.  Runtime transition
  checks (:meth:`AgentGuard.assert_safe`) evaluate edge guards with the same
  canonical-atom semantics as the standalone checker: guards are parsed into
  DNF over canonical atoms, state keys address those atoms, and atoms missing
  from the state default to False.
* :func:`audit_graph` audits a graph dict and returns the standalone
  checker's result shape, backed by this package's compiler + engine.  The
  zero-dependency standalone checker itself ships separately as install.py
  and implements identical trap semantics.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from .bridge import get_engine
from .compiler import Autoformalizer


def _state_env(state: Dict[str, Any], atoms) -> Dict[str, bool]:
    """Builds the atom environment for runtime transition checks.

    Every graph atom defaults to False (the standalone checker's rule).
    Each state entry names one atom - raw text (``"retry_count > 3"``),
    canonical text (``"retry_count <= 3"``), or a plain predicate name,
    optionally negated (``"not flag_a"``) - and sets it.  Keys are
    canonicalized with the same comparison algebra as edge guards, so
    complementary texts address the same atom with opposite polarity.
    Evaluation is by exact atom identity, never by substring matching.
    """
    env = {a: False for a in atoms}
    for key, val in state.items():
        text = re.sub(r"\s+", " ", str(key).strip().lower())
        pos = True
        m_not = re.match(r"^(not|!|~)\s+", text)
        if m_not:
            pos = False
            text = text[m_not.end():].strip()
        atom, atom_pos = Autoformalizer._canonical_atom(text, pos)
        if atom in env:
            env[atom] = bool(val) == atom_pos
    return env


def audit_graph(graph: Dict[str, Any]) -> Dict[str, Any]:
    """Trap-audit a workflow graph dict with the package compiler + engine.

    Returns the standalone checker's result shape: ``atoms``,
    ``condition_variables``, ``total_assignments``, ``exact_count``,
    ``entries``, ``terminals``, ``findings`` and ``witness`` (the first
    trap witness text, or None when the graph is clean).
    """
    from .scenarios import evaluate_custom_rules

    res = evaluate_custom_rules(json.dumps(graph))
    ga = res.get("graph_analysis") or {}
    atoms = ga.get("condition_variables") or []
    witnesses = res.get("trap_witness") or []
    return {
        "atoms": atoms,
        "condition_variables": len(atoms),
        "total_assignments": 1 << len(atoms),
        "exact_count": res["audit"]["exact_count"],
        "entries": ga.get("entries", []),
        "terminals": ga.get("terminals", []),
        "findings": ga.get("findings", []),
        "witness": witnesses[0] if witnesses else None,
    }


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
        self._protect_audit: Optional[Dict[str, Any]] = None

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

    def _parsed_edges(self) -> List[Tuple[str, str, list]]:
        """Graph edges as (source, target, guard DNF) using the compiler's
        canonical guard parsing - the same DNFs the audit compiles."""
        parsed: List[Tuple[str, str, list]] = []
        for e in self.graph.get("edges", []) or []:
            if isinstance(e, (list, tuple)) and len(e) >= 2:
                src, dst = str(e[0]), str(e[1])
                cond = e[2] if len(e) > 2 else None
            elif isinstance(e, dict):
                src = str(e.get("from") or e.get("source") or e.get("src") or "")
                dst = str(e.get("to") or e.get("target") or e.get("dst") or "")
                cond = e.get("condition", e.get("guard", e.get("when")))
            else:
                continue
            if src and dst:
                parsed.append((src, dst, Autoformalizer._guard_dnf(cond)))
        return parsed

    def _terminal_ids(self, node_ids: List[str]) -> set:
        terminals = {str(t) for t in self.graph.get("terminals", []) or []}
        terminals |= {
            str(t) for t in self.graph.get("terminal_nodes", []) or []
        }
        for n in self.graph.get("nodes", []) or []:
            if isinstance(n, dict):
                nid = str(n.get("id") or n.get("name") or n.get("key") or "")
                if n.get("terminal") is True or n.get("is_terminal") is True:
                    terminals.add(nid)
                if str(n.get("type", "")).lower() in {"end", "terminal", "final"}:
                    terminals.add(nid)
            else:
                nid = str(n)
            if nid.lower() in {"end", "__end__", "finish", "done", "final"}:
                terminals.add(nid)
        return terminals

    def assert_safe(self, from_node, to_node, state=None, retry_count=None):
        """Checks one proposed transition against a concrete condition state.

        ``state`` maps atom texts (e.g. ``"retry_count > 3"``) to booleans;
        atoms missing from the state default to False.  Guards are evaluated
        exactly - parsed to canonical DNF and evaluated over the atom
        environment - with the same semantics as the standalone checker.
        Raises :class:`AgentInvariantViolation` (or returns False when
        ``fail_fast=False``) when the edge does not exist, its guard is
        disabled under the state, or the destination would be a deadlock.
        """
        if self.graph is None:
            raise RuntimeError(
                "AgentGuard has no workflow graph to verify against; pass graph=... to the constructor"
            )
        state = dict(state or {})
        if retry_count is not None:
            state.setdefault("retry_count > 3", retry_count > 3)
            state.setdefault("retry_count <= 3", retry_count <= 3)

        nodes = self.graph.get("nodes", []) or []
        node_ids = [
            n if isinstance(n, str) else str(n.get("id") or n.get("name") or n.get("key") or "")
            for n in nodes
        ]
        if from_node not in node_ids or to_node not in node_ids:
            msg = f"unknown node in transition {from_node} -> {to_node}"
            if self.fail_fast:
                raise AgentInvariantViolation(msg)
            return False

        parsed = self._parsed_edges()
        atoms = {a for _, _, dnf in parsed for conj in dnf for a, _ in conj}
        env = _state_env(state, atoms)

        matching = [dnf for s, d, dnf in parsed if s == from_node and d == to_node]
        if not matching:
            msg = f"no edge {from_node} -> {to_node} in the audited graph"
            if self.fail_fast:
                raise AgentInvariantViolation(msg)
            print("[SharpLogic] " + msg)
            return False

        if not any(Autoformalizer._dnf_eval(dnf, env) for dnf in matching):
            msg = f"transition {from_node} -> {to_node} is disabled under the current conditions"
            if self.fail_fast:
                raise AgentInvariantViolation(msg)
            print("[SharpLogic] " + msg)
            return False

        # Deadlock check on destination (terminals are absorbing).
        terminals = self._terminal_ids(node_ids)
        outs = [dnf for s, _, dnf in parsed if s == to_node]
        if to_node not in terminals and outs and all(
            not Autoformalizer._dnf_eval(dnf, env) for dnf in outs
        ):
            msg = f"node {to_node} would be a deadlock under the current conditions (all exits disabled)"
            if self.fail_fast:
                raise AgentInvariantViolation(msg)
            print("[SharpLogic] " + msg)
            return False
        return True

    def protect(self, func):
        """Decorator for router/edge functions, backed by a real check.

        The first time the wrapped function is called, this guard's
        workflow graph is audited with the exact engine (the result is
        cached on the guard).  If the audit finds trap assignments
        (#F > 0), the call is blocked with :class:`AgentInvariantViolation`
        - or, with ``fail_fast=False``, a warning is printed and the call
        proceeds.  Call durations are recorded in the guard's history.
        A guard constructed without a graph has nothing to audit and
        only records timings.
        """
        import functools
        import time

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if self.graph is not None:
                if self._protect_audit is None:
                    self._protect_audit = self.audit()
                traps = self._protect_audit["exact_count"]
                if traps > 0:
                    msg = (
                        f"SharpLogic audit found {traps} trap assignment(s) in the guarded "
                        f"workflow; blocking protected call {func.__name__}()"
                    )
                    if self.fail_fast:
                        raise AgentInvariantViolation(msg)
                    print("[SharpLogic] " + msg + " (fail_fast=False: proceeding)")
            t0 = time.perf_counter()
            res = func(*args, **kwargs)
            self._history.append((func.__name__, (time.perf_counter() - t0) * 1e6))
            return res

        return wrapper