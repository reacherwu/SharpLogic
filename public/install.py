#!/usr/bin/env python3
"""
SharpLogic Standalone Agent Workflow Verifier (offline, zero dependencies).

Runs an exact trap-state audit of an agent workflow graph: it counts the
condition assignments ("trap assignments", #F) under which the workflow
can deadlock (a reachable node with every exit disabled) or livelock
(a reachable cycle/region whose exits are all disabled).  All numbers
printed by this script are computed live from the graph you give it -
nothing is pre-baked.  Graphs whose guard conditions use more than 16
distinct atomic predicates are rejected with an explicit error (the
full SharpLogic package compiles such graphs to an exact CNF counter
instead of enumerating assignments).

Usage:
    python3 install.py [--demo] [--graph workflow.json] [--install]
    python3 install.py --install   # writes the in-agent `sharplogic`
                                   # module (AgentGuard) into ./sharplogic
"""
import argparse
import json
import os
import sys
import time

BANNER = """
\033[1;32m   #\u2227 SharpLogic Agent Sentinel (v1.2)\033[0m
   \033[90mExact deadlock / livelock analysis for LangGraph & multi-agent graphs\033[0m
   \033[90mOffline - zero cloud calls - zero dependencies\033[0m
"""

# ---------------------------------------------------------------------------
# Sample workflow (deliberately flawed).  "Human_Approval_Gate" is declared
# a terminal explicitly: terminals are absorbing end states, so any edges
# out of them would be ignored by the analysis.
# ---------------------------------------------------------------------------
SAMPLE_LANGGRAPH = {
    "name": "CustomerSupport_MultiAgent_Workflow",
    "terminals": ["Human_Approval_Gate"],
    "nodes": [
        "User_Goal",
        "Planner_Agent",
        "Tool_Executor",
        "Critic_Fallback",
        "Human_Approval_Gate"
    ],
    "edges": [
        {"from": "User_Goal", "to": "Planner_Agent"},
        {"from": "Planner_Agent", "to": "Tool_Executor"},
        {"from": "Tool_Executor", "to": "Critic_Fallback", "condition": "tool_timeout or execution_error"},
        {"from": "Critic_Fallback", "to": "Tool_Executor", "condition": "retry_prompt_generated"},
        {"from": "Critic_Fallback", "to": "Human_Approval_Gate", "condition": "retry_count > 3"}
    ]
}

# The same workflow with the traps removed by three visible graph edits:
#   1. Tool_Executor gains a success exit and always reports back to the
#      critic (its only exit was error-only, so a successful tool call
#      stalled the workflow).
#   2. The retry edge is bounded (retry_count <= 3).
#   3. The escalation exit is the exact logical complement of the retry
#      loop's guard conjunction (bounded-retry pattern), so the loop can
#      never be entered without a way out.
SAMPLE_LANGGRAPH_PATCHED = {
    "name": "CustomerSupport_MultiAgent_Workflow (patched)",
    "terminals": ["Human_Approval_Gate"],
    "nodes": [
        "User_Goal",
        "Planner_Agent",
        "Tool_Executor",
        "Critic_Fallback",
        "Human_Approval_Gate"
    ],
    "edges": [
        {"from": "User_Goal", "to": "Planner_Agent"},
        {"from": "Planner_Agent", "to": "Tool_Executor"},
        {"from": "Tool_Executor", "to": "Critic_Fallback"},
        {"from": "Tool_Executor", "to": "Human_Approval_Gate", "condition": "not tool_timeout and not execution_error"},
        {"from": "Critic_Fallback", "to": "Tool_Executor", "condition": "retry_prompt_generated and retry_count <= 3"},
        {"from": "Critic_Fallback", "to": "Human_Approval_Gate", "condition": "not retry_prompt_generated or retry_count > 3"}
    ]
}

# ---------------------------------------------------------------------------
# Compact exact trap checker.  This source is shared verbatim between this
# installer (which execs it) and the generated in-agent module, so the
# standalone audit and the runtime guard implement identical semantics:
#
#   * edge guards are Boolean expressions over atomic predicates;
#     comparisons are canonicalized (x >= c is the negation of x < c,
#     x > c of x <= c, x != c of x == c);
#   * a trap assignment is a valuation of the atoms under which some
#     reachable non-terminal node has every outgoing edge disabled
#     (deadlock), or a reachable directed cycle / strongly connected
#     region has all of its exit edges disabled (livelock);
#   * a cycle whose exit guard is the exact logical complement of the
#     cycle's own guard conjunction (bounded retry) is guarded, not a
#     trap; the same exemption applies at region level;
#   * terminal nodes are absorbing: their outgoing edges are ignored.
#
# The checker enumerates atom valuations, so it refuses graphs with
# more than MAX_ATOMS distinct atoms instead of guessing.
# ---------------------------------------------------------------------------
CHECKER_SRC = '''
import itertools as _itertools
import re as _re

MAX_ATOMS = 16

_CMP_RE = _re.compile(r"^([a-z0-9_\\.\\[\\]]+)\\s*(<=|>=|==|!=|<|>)\\s*([^\\s]+)$")
_TERMINAL_WORDS = ("end", "finish", "complete", "done", "success", "output", "final")


def _canonical_atom(atom, pos):
    m = _CMP_RE.match(atom)
    if not m:
        return atom, pos
    lhs, op, rhs = m.group(1), m.group(2), m.group(3)
    base_op, negated = {
        "<": ("<", False), ">=": ("<", True),
        "<=": ("<=", False), ">": ("<=", True),
        "==": ("==", False), "!=": ("==", True),
    }[op]
    return "%s %s %s" % (lhs, base_op, rhs), (pos != negated)


def _guard_dnf(raw):
    """Condition -> DNF over atoms.  [] = never, [[]] = unconditional."""
    if raw is None or raw is True:
        return [[]]
    if raw is False:
        return []
    if isinstance(raw, (int, float)):
        return [[]] if raw else []
    text = str(raw).strip()
    if not text:
        return [[]]
    dnf = []
    for part in _re.split(r"\\s*\\|\\|\\s*|\\s+\\bor\\b\\s+", text, flags=_re.IGNORECASE):
        conj = []
        ok = True
        for tok in _re.split(r"\\s*&&\\s*|\\s+\\band\\b\\s+", part, flags=_re.IGNORECASE):
            tok = tok.strip()
            while tok.startswith("(") and tok.endswith(")"):
                tok = tok[1:-1].strip()
            if not tok:
                continue
            pos = True
            m_not = _re.match(r"^(not|!|~)\\s+", tok, flags=_re.IGNORECASE)
            if m_not:
                pos = False
                tok = tok[m_not.end():].strip()
            atom = _re.sub(r"\\s+", " ", tok.strip().lower())
            if atom in {"true", "1"}:
                continue
            if atom in {"false", "0"}:
                ok = False
                break
            if atom:
                conj.append(_canonical_atom(atom, pos))
        if ok:
            dnf.append(conj)
    return dnf


def _dnf_eval(dnf, env):
    return any(all(env[a] == p for a, p in conj) for conj in dnf)


def _parse_graph(graph):
    nodes = []
    for n in graph.get("nodes", []):
        if isinstance(n, dict):
            nid = str(n.get("id") or n.get("name"))
            nodes.append((nid, bool(n.get("terminal")) or n.get("type") == "end"))
        else:
            nodes.append((str(n), False))
    declared = {str(t) for t in graph.get("terminals", [])}
    terminals = set()
    for nid, flagged in nodes:
        low = nid.lower()
        if flagged or nid in declared or nid == "__end__" or any(w in low for w in _TERMINAL_WORDS):
            terminals.add(nid)
    edges = []
    for e in graph.get("edges", []):
        src = str(e.get("from") or e.get("source"))
        dst = str(e.get("to") or e.get("target"))
        edges.append((src, dst, _guard_dnf(e.get("condition", ""))))
    ids = [n for n, _ in nodes]
    live = [(s, d, g) for (s, d, g) in edges if s not in terminals]
    indeg = {n: 0 for n in ids}
    for s, d, _ in live:
        indeg[d] = indeg.get(d, 0) + 1
    entry = graph.get("entry") or graph.get("start")
    if entry:
        entries = [str(entry)]
    else:
        entries = [n for n in ids if indeg.get(n, 0) == 0] or ids[:1]
    return ids, terminals, live, entries


def _tarjan(nodes, adj):
    index, low, onstk, stk, out = {}, {}, set(), [], []
    cnt = [0]

    def strong(v):
        index[v] = low[v] = cnt[0]
        cnt[0] += 1
        stk.append(v)
        onstk.add(v)
        for w in adj.get(v, []):
            if w not in index:
                strong(w)
                low[v] = min(low[v], low[w])
            elif w in onstk:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp = []
            while True:
                w = stk.pop()
                onstk.discard(w)
                comp.append(w)
                if w == v:
                    break
            out.append(comp)

    for v in nodes:
        if v not in index:
            strong(v)
    return out


def _simple_cycles(nodes, adj):
    cycles = set()

    def dfs(start, cur, path, seen):
        for nxt in adj.get(cur, []):
            if nxt == start and len(path) >= 1:
                cyc = tuple(path)
                i = cyc.index(min(cyc))
                cycles.add(cyc[i:] + cyc[:i])
            elif nxt not in seen and nxt >= start:
                seen.add(nxt)
                path.append(nxt)
                dfs(start, nxt, path, seen)
                path.pop()
                seen.remove(nxt)

    for s in nodes:
        dfs(s, s, [s], {s})
    return [list(c) for c in cycles]


def _is_negation(fn_a, fn_b, atoms):
    return all(
        fn_a(dict(zip(atoms, vals))) == (not fn_b(dict(zip(atoms, vals))))
        for vals in _itertools.product([False, True], repeat=len(atoms))
    )


def audit_graph(graph):
    """Exact trap audit.  Returns a dict with the trap count #F, the
    atom list, structural findings and the first trap witness.
    Raises ValueError when the graph exceeds MAX_ATOMS atoms."""
    ids, terminals, edges, entries = _parse_graph(graph)
    atoms = sorted({a for _, _, dnf in edges for conj in dnf for a, _ in conj})
    if len(atoms) > MAX_ATOMS:
        raise ValueError(
            "graph uses %d distinct condition atoms; the standalone checker "
            "supports at most %d (use the full SharpLogic package, which "
            "compiles the graph to an exact CNF counter)" % (len(atoms), MAX_ATOMS)
        )
    out = {n: [] for n in ids}
    for i, (s, _, _) in enumerate(edges):
        out[s].append(i)
    adj = {n: sorted({edges[i][1] for i in out[n]}) for n in ids}
    cycles = _simple_cycles(ids, adj)
    sccs = _tarjan(ids, adj)
    findings = []
    for n in ids:
        if n not in terminals and not out[n] and len(ids) > 1:
            findings.append({"type": "dead_end", "nodes": [n]})
    reach_any = set(entries)
    stack = list(entries)
    while stack:
        cur = stack.pop()
        for i in out[cur]:
            if edges[i][1] not in reach_any:
                reach_any.add(edges[i][1])
                stack.append(edges[i][1])
    for n in ids:
        if n not in reach_any:
            findings.append({"type": "unreachable_node", "nodes": [n]})

    degenerate = len(ids) == 1 and not edges
    trap_count = 0
    witness = None
    guarded = 0
    for vals in _itertools.product([False, True], repeat=len(atoms)):
        env = dict(zip(atoms, vals))
        en = [_dnf_eval(d, env) for _, _, d in edges]
        reach = set(entries)
        stack = list(entries)
        while stack:
            cur = stack.pop()
            for i in out[cur]:
                if en[i] and edges[i][1] not in reach:
                    reach.add(edges[i][1])
                    stack.append(edges[i][1])
        trap = None
        if not degenerate:
            for n in ids:
                if n in reach and n not in terminals and all(not en[i] for i in out[n]):
                    trap = ("deadlock", n)
                    break
        if trap is None:
            for cyc in cycles:
                cset = set(cyc)
                cyc_edges = [
                    i for i, (s, d, _) in enumerate(edges)
                    if s in cset and d in cset
                    and any(cyc[k] == s and cyc[(k + 1) % len(cyc)] == d for k in range(len(cyc)))
                ]
                if not all(en[i] for i in cyc_edges):
                    continue
                if not all(n in reach for n in cyc):
                    continue
                exits = [i for i, (s, d, _) in enumerate(edges) if s in cset and d not in cset]
                if any(en[i] for i in exits):
                    continue

                def cyc_fn(e2, ce=tuple(cyc_edges)):
                    return all(_dnf_eval(edges[i][2], e2) for i in ce)
                if any(_is_negation(lambda e2, i=i: _dnf_eval(edges[i][2], e2), cyc_fn, atoms) for i in exits):
                    guarded += 1
                    continue
                trap = ("livelock", " -> ".join(cyc))
                break
        if trap is None:
            for comp in sccs:
                cset = set(comp)
                cyclic = len(comp) > 1 or any(edges[i][1] == comp[0] for i in out[comp[0]])
                if not cyclic:
                    continue
                comp_cycles = [c for c in cycles if set(c) == cset]
                if len(comp_cycles) == 1 and len([c for c in cycles if set(c) <= cset]) == 1:
                    continue  # covered precisely by the cycle rule above
                exits = [i for i, (s, d, _) in enumerate(edges) if s in cset and d not in cset]
                if any(en[i] for i in exits):
                    continue
                if not any(n in reach for n in comp):
                    continue
                internal = [i for i, (s, d, _) in enumerate(edges) if s in cset and d in cset]

                def internal_fn(e2, ii=tuple(internal)):
                    return all(_dnf_eval(edges[i][2], e2) for i in ii)
                if any(_is_negation(lambda e2, i=i: _dnf_eval(edges[i][2], e2), internal_fn, atoms) for i in exits):
                    continue  # bounded-retry exemption at region level
                ok = True
                for n in comp:
                    if n not in reach:
                        continue
                    internal_out = [i for i in out[n] if edges[i][1] in cset]
                    if internal_out and not any(en[i] for i in internal_out):
                        ok = False
                if ok:
                    trap = ("livelock_region", ", ".join(sorted(cset)))
                    break
        if trap is not None:
            trap_count += 1
            if witness is None:
                witness = {"kind": trap[0], "at": trap[1], "assignment": dict(env)}
    if guarded:
        findings.append({"type": "guarded_cycle", "count": guarded})
    return {
        "atoms": atoms,
        "condition_variables": len(atoms),
        "total_assignments": 1 << len(atoms),
        "exact_count": trap_count,
        "entries": entries,
        "terminals": sorted(terminals),
        "findings": findings,
        "witness": witness,
    }
'''

_ns = {}
exec(CHECKER_SRC, _ns)
audit_graph = _ns["audit_graph"]

GUARD_SRC = '''

class AgentInvariantViolation(RuntimeError):
    pass


class AgentGuard:
    """In-agent guardrail backed by the exact trap checker above.

    Construct with the workflow graph you want enforced.  `audit()` runs
    the full trap analysis; `assert_safe()` checks one proposed
    transition against a concrete condition state (a dict mapping
    normalized atom texts - e.g. "retry_count > 3" - to booleans).
    Without a graph, assert_safe raises instead of guessing.
    """

    def __init__(self, token="", graph=None, fail_fast=True):
        self.token = token
        self.graph = graph
        self.fail_fast = fail_fast
        self._history = []

    def audit(self):
        if self.graph is None:
            raise RuntimeError("AgentGuard was constructed without a workflow graph")
        return audit_graph(self.graph)

    def assert_safe(self, from_node, to_node, state=None, retry_count=None):
        if self.graph is None:
            raise RuntimeError(
                "AgentGuard has no workflow graph to verify against; "
                "pass graph=... to the constructor"
            )
        state = dict(state or {})
        if retry_count is not None:
            state.setdefault("retry_count > 3", retry_count > 3)
            state.setdefault("retry_count <= 3", retry_count <= 3)
        ids, terminals, edges, _entries = _parse_graph(self.graph)
        env = {}
        for atom in {a for _, _, dnf in edges for conj in dnf for a, _ in conj}:
            env[atom] = bool(state.get(atom, False))
        edge = next((g for (s, d, g) in edges if s == from_node and d == to_node), None)
        if edge is None:
            msg = "no edge %s -> %s in the audited graph" % (from_node, to_node)
            if self.fail_fast:
                raise AgentInvariantViolation(msg)
            print("[SharpLogic] " + msg)
            return False
        if not _dnf_eval(edge, env):
            msg = "transition %s -> %s is disabled under the current conditions" % (from_node, to_node)
            if self.fail_fast:
                raise AgentInvariantViolation(msg)
            print("[SharpLogic] " + msg)
            return False
        outs = [g for (s, _, g) in edges if s == to_node]
        if to_node not in terminals and outs and all(not _dnf_eval(g, env) for g in outs):
            msg = "node %s would be a deadlock under the current conditions (all exits disabled)" % to_node
            if self.fail_fast:
                raise AgentInvariantViolation(msg)
            print("[SharpLogic] " + msg)
            return False
        return True

    def protect(self, func):
        """Decorator: times the wrapped router/edge function and keeps a
        local history of call durations (introspection only)."""
        import functools
        import time

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            t0 = time.perf_counter()
            res = func(*args, **kwargs)
            self._history.append((func.__name__, (time.perf_counter() - t0) * 1e6))
            return res

        return wrapper
'''


def install_python_guard(token=""):
    """Installs the zero-dependency in-agent Python module in the current workspace."""
    pkg_dir = os.path.join(os.getcwd(), "sharplogic")
    os.makedirs(pkg_dir, exist_ok=True)
    init_code = (
        "# SharpLogic In-Agent Runtime Sentinel (generated by install.py)\n"
        "# Exact trap checker + AgentGuard. Semantics are documented in install.py.\n"
        + CHECKER_SRC
        + GUARD_SRC
    )
    init_path = os.path.join(pkg_dir, "__init__.py")
    with open(init_path, "w", encoding="utf-8") as f:
        f.write(init_code)
    print(f"\033[1;32m✓ In-Agent Python Module Installed:\033[0m {init_path}")
    print("  Use `from sharplogic import AgentGuard` with your workflow graph to audit it")
    print("  and to check transitions at runtime.\n")


def verify_agent_graph(graph_data, token=""):
    print(BANNER)
    if token and token != "sl_offline":
        print(f"\033[1;34m[✓] Active Sentinel Token:\033[0m {token}")
    print(f"\033[1m[*] Auditing workflow:\033[0m {graph_data.get('name', 'Agent Workflow')}")
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])
    print(f"    - Nodes: {len(nodes)} agents / gates")
    print(f"    - Edges: {len(edges)} conditional transitions")
    t0 = time.perf_counter()
    try:
        res = audit_graph(graph_data)
    except ValueError as exc:
        print(f"\033[31mCannot audit: {exc}\033[0m")
        sys.exit(2)
    elapsed_us = (time.perf_counter() - t0) * 1e6
    print(f"    - Condition variables: {res['condition_variables']} "
          f"({res['total_assignments']:,} assignments in the full state space)")
    print(f"    - Analysis time (standalone checker, measured): {elapsed_us:.1f} µs\n")
    for f in res["findings"]:
        if f["type"] == "dead_end":
            print(f"    \033[93m[structure] dead end:\033[0m node {f['nodes']} has no outgoing edges and is not a terminal")
        elif f["type"] == "unreachable_node":
            print(f"    \033[93m[structure] unreachable:\033[0m node {f['nodes']} cannot be reached from any entry")
        elif f["type"] == "guarded_cycle":
            print(f"    \033[92m[structure] guarded cycle:\033[0m a retry loop whose exit guard is the exact "
                  f"complement of its loop guard (bounded retry) is excluded from trap counting")
    if res["exact_count"]:
        w = res["witness"] or {}
        print(f"\033[1;31m[!] TRAPS FOUND: #F = {res['exact_count']} of {res['total_assignments']:,} "
              f"assignments leave the workflow stuck\033[0m")
        print(f"    First witness: {w.get('kind')} at {w.get('at')}")
        print(f"    Conditions: {json.dumps(w.get('assignment', {}), sort_keys=True)}")
        print("    Any assignment counted here reaches a node (or cycle) whose exits are")
        print("    all disabled by those conditions - the workflow cannot proceed.\n")
    else:
        print(f"\033[1;32m[✓] #F = 0: no assignment of the {res['condition_variables']} condition "
              f"variables traps this workflow\033[0m (deadlock/livelock analysis, exact enumeration).\n")
    return res


def main():
    parser = argparse.ArgumentParser(description="SharpLogic Standalone Agent Verifier")
    parser.add_argument("--token", type=str, help="User Sentinel Access Token", default="sl_offline")
    parser.add_argument("--graph", type=str, help="Path to LangGraph/Dify workflow JSON export", default=None)
    parser.add_argument("--demo", action="store_true", help="Run with flagship multi-agent workflow demo")
    parser.add_argument("--install", action="store_true", help="Install local in-agent Python module", default=False)
    args = parser.parse_args()

    if args.install:
        install_python_guard(args.token)

    if args.graph:
        try:
            with open(args.graph, "r", encoding="utf-8") as f:
                data = json.load(f)
            verify_agent_graph(data, args.token)
        except Exception as e:
            print(f"\033[31mError reading graph file:\033[0m {e}")
            sys.exit(1)
    else:
        verify_agent_graph(SAMPLE_LANGGRAPH, args.token)
        print("\033[1m[*] Applying a remediation and re-auditing:\033[0m")
        print("    1. success exit added for Tool_Executor (was error-exit only)")
        print("    2. retry edge bounded to retry_count <= 3")
        print("    3. escalation exit made the exact complement of the retry-loop guard\n")
        verify_agent_graph(SAMPLE_LANGGRAPH_PATCHED, args.token)


if __name__ == "__main__":
    main()
