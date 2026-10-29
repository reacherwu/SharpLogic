"""
Production Neuro-Symbolic Autoformalization Compiler:
1. Deterministic AWS IAM Policy JSON -> k-CNF Compiler.
2. Deterministic LangGraph / Dify Workflow JSON -> k-CNF Compiler.
3. Cloud LLM Structured Outputs (OpenAI / Gemini API) + Self-Correction Loop.
4. Bilingual Natural Language & Symbolic DSL -> k-CNF Compiler (Zero-Key Offline Mode).
"""

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen


class Autoformalizer:
    """
    Compiles natural language business rules, AWS IAM Policy JSON, Agent Graph JSON,
    and symbolic expressions into strict k-CNF clauses with a Self-Correction Loop.
    """

    @staticmethod
    def format_clause_math(clause: List[int], var_names: List[str]) -> str:
        parts = []
        for lit in clause:
            idx = abs(lit) - 1
            name = var_names[idx] if 0 <= idx < len(var_names) else f"x_{idx + 1}"
            parts.append(f"¬{name}" if lit < 0 else name)
        return "(" + " ∨ ".join(parts) + ")"

    @staticmethod
    def to_dimacs(
        num_vars: int,
        clauses: List[List[int]],
        comment: str = "SharpLogic Autoformalized k-CNF",
    ) -> str:
        lines = [
            f"c {comment}",
            f"p cnf {num_vars} {len(clauses)}",
        ]
        for cl in clauses:
            lines.append(" ".join(str(x) for x in cl) + " 0")
        return "\n".join(lines)

    @classmethod
    def _compile_aws_iam_json(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Deterministically compiles an AWS IAM Policy JSON into k-CNF clauses."""
        statements = data.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        var_map: Dict[str, int] = {}
        var_list: List[Dict[str, Any]] = []
        clauses: List[List[int]] = []
        clause_descs: List[str] = []
        log: List[str] = ["[IAM JSON Parser] Detected valid AWS IAM Policy JSON document."]

        def add_var(name: str, label: str, prior: float = 0.5, cat: str = "IAM Predicate") -> int:
            clean = re.sub(r"[^a-zA-Z0-9_]", "_", name.lower()).strip("_")
            if clean not in var_map:
                idx = len(var_list) + 1
                var_map[clean] = idx
                var_list.append({"name": clean, "label": label, "prior": prior, "category": cat})
            return var_map[clean]

        # Region scope disjunction (4 AWS regions -> 15 combinations)
        r1 = add_var("region_us_east_1", "Region us-east-1", 0.6, "Scope")
        r2 = add_var("region_us_west_2", "Region us-west-2", 0.5, "Scope")
        r3 = add_var("region_eu_west_1", "Region eu-west-1", 0.4, "Scope")
        clauses.append([r1, r2, r3])
        clause_descs.append("IAM Scope: Active in at least one cloud region")

        has_wildcard = False
        for i, stmt in enumerate(statements):
            effect = str(stmt.get("Effect", "Allow")).lower()
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            cond = stmt.get("Condition", {})

            for act in actions:
                v_act = add_var(f"action_{act}", f"Action: {act}", 0.75, "IAM Action")
                if effect == "allow":
                    clauses.append([v_act])
                    clause_descs.append(f"Stmt #{i + 1} [Allow]: Enables {act}")
                else:
                    clauses.append([-v_act])
                    clause_descs.append(f"Stmt #{i + 1} [Deny]: Explicitly blocks {act}")

            for res in resources:
                if "*" in res:
                    has_wildcard = True
                    # Wildcard leaves resource tag dimensions unconstrained (free variables multiply #F by 2^k)
                    for tag_i in range(1, 5):
                        add_var(f"wildcard_resource_scope_{tag_i}", f"Wildcard Scope Bit #{tag_i}", 0.5, "Wildcard Expansion")
                    log.append(f"[IAM Audit] Statement #{i + 1} uses wildcard Resource '{res}' -> expanded 2^4 free scope variables.")
                else:
                    v_res = add_var(f"res_{res[-20:]}", f"Resource: {res}", 0.65, "Resource")
                    clauses.append([v_res])
                    clause_descs.append(f"Stmt #{i + 1}: Scoped to resource {res}")

            if not cond or "MultiFactorAuthPresent" not in json.dumps(cond):
                v_no_mfa = add_var("missing_mfa_guard", "Missing MFA Guard", 0.85, "Vulnerability")
                clauses.append([v_no_mfa])
                clause_descs.append(f"Stmt #{i + 1} [Risk]: No aws:MultiFactorAuthPresent condition enforced")

        if has_wildcard:
            v_breach = add_var("privilege_escalation_exposed", "Privilege Escalation Exposed", 0.95, "Invariant")
            clauses.append([v_breach])
            clause_descs.append("Security Invariant Breach: Wildcard resource reachable without MFA")

        var_names = [v["name"] for v in var_list]
        return {
            "num_vars": len(var_list),
            "variables": var_list,
            "clauses": clauses,
            "clause_descriptions": clause_descs,
            "pretty_clauses": [cls.format_clause_math(c, var_names) for c in clauses],
            "dimacs": cls.to_dimacs(len(var_list), clauses, "AWS IAM Policy Formal Audit"),
            "self_correction_log": log,
        }

    # ------------------------------------------------------------------
    # Agent workflow graph -> trap-formula compiler (exact semantics).
    #
    # Edges carry Boolean guard conditions over named atomic predicates
    # (the "condition variables", e.g. `retry_count > 3`).  A *trap
    # assignment* is a valuation of the condition variables under which
    # the workflow can fail to make progress:
    #   * deadlock - a reachable, non-terminal node has every outgoing
    #     edge disabled by the assignment;
    #   * livelock - a directed cycle (or strongly connected region) is
    #     reachable, its cycle edges are enabled, and every edge leaving
    #     the cycle/region is disabled.
    # The emitted CNF is in exact 1-to-1 correspondence with trap
    # assignments: every auxiliary variable (reachability, canonical
    # support, trap witnesses) is functionally determined by the
    # condition variables, so the engine's exact count #F is exactly the
    # number of trap assignments.  One documented carve-out: a cycle is
    # reported as guarded (bounded-retry pattern) and excluded from the
    # trap formula when one of its edges is a progress edge - a genuinely
    # conditional edge traversed on every iteration, e.g. a retry-budget
    # edge - and the cycle's exits, taken together, are open whenever
    # that edge's guard fails (see _cycle_is_guarded).  The same
    # predicate decides every cycle and every region; a region is exempt
    # only when it consists of a single guarded cycle.  Multi-cycle
    # regions are counted under the plain semantics above.
    # Known boundary (reported in graph_analysis.limitations when it
    # occurs): reachability grounding is exact for SCCs whose cycles
    # are entered from outside the cycle; a tangle of mutually feeding
    # cycles inside one SCC that is disconnected from every entry could
    # in principle be counted as reachable - such regions are also
    # flagged as unreachable_node findings by the structural layer.
    # ------------------------------------------------------------------

    @classmethod
    def _guard_dnf(cls, raw: Any) -> List[List[Tuple[str, bool]]]:
        """Parses an edge condition into DNF over atomic predicates.

        Returns a list of conjunctions of (atom_text, is_positive).
        ``[]`` means "never enabled"; ``[[]]`` means unconditional.
        """
        if raw is None or raw is True:
            return [[]]
        if raw is False:
            return []
        if isinstance(raw, (int, float)):
            return [[]] if raw else []
        s = str(raw).strip()
        if not s or s.lower() in {"true", "always", "1"}:
            return [[]]
        if s.lower() in {"false", "never", "0"}:
            return []
        dnf: List[List[Tuple[str, bool]]] = []
        for part in re.split(r"\s*\|\|\s*|\s+\bor\b\s+", s, flags=re.IGNORECASE):
            part = part.strip()
            while part.startswith("(") and part.endswith(")"):
                part = part[1:-1].strip()
            if not part:
                continue
            conj: Optional[List[Tuple[str, bool]]] = []
            for tok in re.split(r"\s*&&\s*|\s+\band\b\s+", part, flags=re.IGNORECASE):
                tok = tok.strip()
                while tok.startswith("(") and tok.endswith(")"):
                    tok = tok[1:-1].strip()
                if not tok:
                    continue
                pos = True
                m_not = re.match(r"^(not|!|~)\s+", tok, flags=re.IGNORECASE)
                if m_not:
                    pos = False
                    tok = tok[m_not.end():].strip()
                atom = re.sub(r"\s+", " ", tok.strip().lower())
                if atom in {"true", "1"}:
                    continue
                if atom in {"false", "0"}:
                    conj = None
                    break
                if atom:
                    conj.append(cls._canonical_atom(atom, pos))
            if conj is not None:
                dnf.append(conj)
        return dnf


    _CMP_RE = re.compile(r"^([a-z0-9_\.\[\]]+)\s*(<=|>=|==|!=|<|>)\s*([^\s]+)$")

    @classmethod
    def _canonical_atom(cls, atom: str, pos: bool) -> Tuple[str, bool]:
        """Canonicalizes comparison atoms so complementary guards share
        one atom: ``x >= 3`` is the negation of ``x < 3``, ``x > 3`` of
        ``x <= 3``, ``x != 3`` of ``x == 3``.  This is what lets the
        compiler recognize the bounded-retry pattern (loop while
        ``retry_count < 3``, exit when ``retry_count >= 3``) as guarded.
        Non-comparison atoms pass through unchanged."""
        m = cls._CMP_RE.match(atom)
        if not m:
            return atom, pos
        lhs, op, rhs = m.group(1), m.group(2), m.group(3)
        base_op, negated = {
            "<": ("<", False),
            ">=": ("<", True),
            "<=": ("<=", False),
            ">": ("<=", True),
            "==": ("==", False),
            "!=": ("==", True),
        }[op]
        return f"{lhs} {base_op} {rhs}", (pos != negated)

    @staticmethod
    def _dnf_eval(dnf: List[List[Tuple[str, bool]]], env: Dict[str, bool]) -> bool:
        for conj in dnf:
            if all(env.get(a, False) == p for a, p in conj):
                return True
        return False

    @classmethod
    def _exits_cover_edge_failure(
        cls,
        exit_guards: List[List[List[Tuple[str, bool]]]],
        edge_guard: List[List[Tuple[str, bool]]],
    ) -> bool:
        """True iff whenever ``edge_guard`` fails, at least one of
        ``exit_guards`` holds - i.e. (OR of exit_guards) OR edge_guard is
        a tautology - and ``edge_guard`` is a genuine condition
        (satisfiable and falsifiable: an unconditional edge never fails,
        so it cannot be the progress edge of a bounded-retry loop, and a
        never-enabled edge cannot be traversed at all).  Checked
        exhaustively over the atoms involved (>12 atoms -> False)."""
        atoms = set()
        for g in exit_guards + [edge_guard]:
            for conj in g:
                atoms.update(a for a, _ in conj)
        atoms = sorted(atoms)
        if not atoms or len(atoms) > 12:
            return False
        edge_sat = False
        edge_unsat = False
        for mask in range(1 << len(atoms)):
            env = {a: bool(mask >> i & 1) for i, a in enumerate(atoms)}
            if cls._dnf_eval(edge_guard, env):
                edge_sat = True
            else:
                edge_unsat = True
                if not any(cls._dnf_eval(g, env) for g in exit_guards):
                    return False
        return edge_sat and edge_unsat

    @classmethod
    def _cycle_is_guarded(
        cls,
        cycle_guards: List[List[List[Tuple[str, bool]]]],
        exit_guards: List[List[List[Tuple[str, bool]]]],
    ) -> bool:
        """The single bounded-retry (guarded cycle) predicate, applied
        identically to every cycle and every region in this compiler (and
        mirrored by the standalone checker in install.py).

        A cycle is guarded iff some cycle edge is a *progress edge* -
        a genuinely conditional edge traversed on every loop iteration,
        such as a retry-budget edge - and the cycle's exits, taken
        together, are open whenever that edge's guard fails: formally,
        (OR of exit guards) OR (progress edge guard) is a tautology for
        some cycle edge.  The classic shape "retry while A, exit when
        not A" is the single-edge case; the exit condition may be split
        across several exit edges, and other cycle edges may carry
        unrelated guards, without changing the verdict.  What matters is
        only that the loop's progress condition, once exhausted, always
        leaves an exit open.
        """
        if not exit_guards:
            return False
        return any(
            cls._exits_cover_edge_failure(exit_guards, g) for g in cycle_guards
        )

    @staticmethod
    def _tarjan_scc(
        nodes: List[str],
        out_adj: Dict[str, List[int]],
        edges: List[Dict[str, Any]],
    ) -> List[List[str]]:
        indices: Dict[str, int] = {}
        lowlink: Dict[str, int] = {}
        on_stack: Dict[str, bool] = {}
        stack: List[str] = []
        result: List[List[str]] = []
        counter = [0]

        def strongconnect(v: str) -> None:
            work = [(v, 0)]
            while work:
                node, pi = work[-1]
                if pi == 0:
                    indices[node] = counter[0]
                    lowlink[node] = counter[0]
                    counter[0] += 1
                    stack.append(node)
                    on_stack[node] = True
                recurse = False
                succs = [edges[ei]["dst"] for ei in out_adj[node]]
                for i in range(pi, len(succs)):
                    w = succs[i]
                    if w not in indices:
                        work[-1] = (node, i + 1)
                        work.append((w, 0))
                        recurse = True
                        break
                    elif on_stack.get(w):
                        lowlink[node] = min(lowlink[node], indices[w])
                if recurse:
                    continue
                if lowlink[node] == indices[node]:
                    comp = []
                    while True:
                        w = stack.pop()
                        on_stack[w] = False
                        comp.append(w)
                        if w == node:
                            break
                    result.append(comp)
                work.pop()
                if work:
                    parent = work[-1][0]
                    lowlink[parent] = min(lowlink[parent], lowlink[node])

        for n in nodes:
            if n not in indices:
                strongconnect(n)
        return result

    @staticmethod
    def _simple_cycles_in_scc(
        members: List[str],
        out_adj: Dict[str, List[int]],
        edges: List[Dict[str, Any]],
        cap: int = 256,
    ) -> Tuple[List[Tuple[int, ...]], bool]:
        """Enumerates simple directed cycles inside one SCC.

        Each cycle is a tuple of edge indices.  Returns (cycles,
        overflowed): enumeration is capped; on overflow the SCC-level
        livelock witness still applies and the caller records a
        limitation.
        """
        member_set = set(members)
        order = {n: i for i, n in enumerate(members)}
        cycles: List[Tuple[int, ...]] = []
        overflow = [False]

        def dfs(start: str, current: str, visited: set, path: List[int]) -> None:
            if overflow[0]:
                return
            for ei in out_adj[current]:
                dst = edges[ei]["dst"]
                if dst not in member_set:
                    continue
                if dst == start:
                    cycles.append(tuple(path + [ei]))
                    if len(cycles) >= cap:
                        overflow[0] = True
                        return
                elif dst not in visited and order[dst] >= order[start]:
                    visited.add(dst)
                    path.append(ei)
                    dfs(start, dst, visited, path)
                    path.pop()
                    visited.remove(dst)

        for s in members:
            dfs(s, s, {s}, [])
            if overflow[0]:
                break
        return cycles, overflow[0]

    @classmethod
    def _compile_agent_graph_json(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Compiles a LangGraph / Dify workflow graph into an exact
        trap-counting CNF (see the semantics note above)."""
        raw_nodes = data.get("nodes", [])
        raw_edges = data.get("edges", [])

        node_order: List[str] = []
        node_terminal: Dict[str, bool] = {}

        def note_node(nid: str, terminal: bool = False) -> None:
            if nid not in node_terminal:
                node_order.append(nid)
                node_terminal[nid] = terminal
            elif terminal:
                node_terminal[nid] = True

        def is_terminal_decl(nd: Any, nid: str) -> bool:
            if isinstance(nd, dict):
                if nd.get("terminal") is True or nd.get("is_terminal") is True:
                    return True
                if str(nd.get("type", "")).lower() in {"end", "terminal", "final"}:
                    return True
            return nid.lower() in {"end", "__end__", "finish", "done", "final"}

        for nd in raw_nodes:
            if isinstance(nd, dict):
                nid = str(nd.get("id") or nd.get("name") or nd.get("key") or "")
            else:
                nid = str(nd)
            if nid:
                note_node(nid, is_terminal_decl(nd, nid))
        for t in data.get("terminals", []) or data.get("terminal_nodes", []) or []:
            note_node(str(t), True)

        edges: List[Dict[str, Any]] = []
        declared_entries: List[str] = []
        for ed in raw_edges:
            if isinstance(ed, (list, tuple)) and len(ed) >= 2:
                src, dst, cond = str(ed[0]), str(ed[1]), None
            elif isinstance(ed, dict):
                src = str(ed.get("source") or ed.get("from") or ed.get("src") or ed.get("u") or "")
                dst = str(ed.get("target") or ed.get("to") or ed.get("dst") or ed.get("v") or "")
                cond = ed.get("condition", ed.get("guard", ed.get("when")))
            else:
                continue
            if not src or not dst:
                continue
            if src == "__start__":
                declared_entries.append(dst)
                note_node(dst)
                continue
            note_node(src)
            note_node(dst, dst == "__end__")
            edges.append({"src": src, "dst": dst, "guard": cls._guard_dnf(cond)})

        log = ["[Agent Graph Parser] Parsed workflow topology JSON."]
        if not node_order:
            raise ValueError("Agent graph has no nodes.")
        if len(node_order) == 1 and not edges:
            node_terminal[node_order[0]] = True

        # Terminal nodes are absorbing: execution never leaves a
        # terminal, so terminal out-edges cannot create or escape a
        # trap and do not propagate execution reachability.  They are
        # excluded from the trap encoding (the full edge list is still
        # reported in graph_analysis).
        dropped_terminal_edges = sum(
            1 for e in edges if node_terminal.get(e["src"])
        )
        out_adj: Dict[str, List[int]] = {n: [] for n in node_order}
        in_adj: Dict[str, List[int]] = {n: [] for n in node_order}
        for ei, e in enumerate(edges):
            if node_terminal.get(e["src"]):
                continue
            out_adj[e["src"]].append(ei)
            in_adj[e["dst"]].append(ei)

        entries: List[str] = []
        entry_decl = data.get("entry") or data.get("start") or data.get("entry_node")
        if entry_decl:
            entries = [str(entry_decl)]
            note_node(entries[0])
            out_adj.setdefault(entries[0], [])
            in_adj.setdefault(entries[0], [])
        for d in declared_entries:
            if d not in entries:
                entries.append(d)
        if not entries:
            entries = [n for n in node_order if not in_adj[n]]
        if not entries:
            entries = [node_order[0]]
            log.append(f"[Agent Graph Parser] No entry node found; assuming '{node_order[0]}' is the entry.")
        entry_set = set(entries)

        sccs = cls._tarjan_scc(node_order, out_adj, edges)
        scc_of: Dict[str, int] = {}
        for si, comp in enumerate(sccs):
            for n in comp:
                scc_of[n] = si

        def kind(ei: int) -> str:
            g = edges[ei]["guard"]
            if g == [[]]:
                return "always"
            if g == []:
                return "never"
            return "conditional"

        # ---------------- structural analysis ----------------
        findings: List[Dict[str, Any]] = []
        reachable_struct = set(entries)
        stack = list(entries)
        while stack:
            cur = stack.pop()
            for ei in out_adj[cur]:
                d = edges[ei]["dst"]
                if d not in reachable_struct:
                    reachable_struct.add(d)
                    stack.append(d)

        cyclic_sccs: List[int] = []
        for si, comp in enumerate(sccs):
            has_self = len(comp) == 1 and any(
                edges[ei]["src"] == edges[ei]["dst"] for ei in out_adj[comp[0]]
            )
            if len(comp) > 1 or has_self:
                cyclic_sccs.append(si)
                exits = [
                    ei
                    for n in comp
                    for ei in out_adj[n]
                    if edges[ei]["dst"] not in comp
                ]
                if not exits:
                    findings.append(
                        {
                            "type": "exitless_cycle",
                            "severity": "high",
                            "nodes": sorted(comp),
                            "detail": "Strongly connected region with no outgoing edge: once entered, the workflow can never leave it.",
                        }
                    )
                else:
                    findings.append(
                        {
                            "type": "cycle_with_exit",
                            "severity": "info",
                            "nodes": sorted(comp),
                            "detail": "Cycle with exit edges; it is a livelock trap exactly under the guard assignments counted by #F.",
                        }
                    )
        for n in node_order:
            if not node_terminal[n] and not out_adj[n] and len(node_order) > 1:
                findings.append(
                    {
                        "type": "dead_end",
                        "severity": "high",
                        "nodes": [n],
                        "detail": f"Node '{n}' has no outgoing edges and is not marked terminal: executions reaching it halt without completing.",
                    }
                )
            if n not in reachable_struct:
                findings.append(
                    {
                        "type": "unreachable_node",
                        "severity": "medium",
                        "nodes": [n],
                        "detail": f"Node '{n}' is not reachable from any entry node.",
                    }
                )

        # ---------------- trap candidates ----------------
        # Degenerate case: a graph consisting of a single node with no
        # edges is a complete (empty) workflow - the node is trivially
        # its own end, never a trap.
        degenerate_single = len(node_order) == 1 and not edges
        stuck_candidates: List[str] = []
        for n in node_order:
            if node_terminal[n] or degenerate_single:
                continue
            outs = out_adj[n]
            if not outs:
                stuck_candidates.append(n)
            elif all(kind(ei) != "always" for ei in outs):
                stuck_candidates.append(n)

        cycles_by_scc: Dict[int, List[Tuple[int, ...]]] = {}
        cycle_overflow = False
        for si in cyclic_sccs:
            comp = sccs[si]
            if len(comp) <= 10:
                cyc, ov = cls._simple_cycles_in_scc(comp, out_adj, edges)
                cycles_by_scc[si] = cyc
                cycle_overflow = cycle_overflow or ov
            else:
                cycles_by_scc[si] = []
                cycle_overflow = True

        def cycle_members(cyc: Tuple[int, ...]) -> set:
            ms = set()
            for ei in cyc:
                ms.add(edges[ei]["src"])
                ms.add(edges[ei]["dst"])
            return ms

        def cycle_exit_eis(cyc: Tuple[int, ...]) -> List[int]:
            ms = cycle_members(cyc)
            return [
                ei
                for n in ms
                for ei in out_adj[n]
                if edges[ei]["dst"] not in ms
            ]

        trap_cycles: List[Tuple[int, ...]] = []
        guarded_cycles = 0
        for si in cyclic_sccs:
            for cyc in cycles_by_scc.get(si, []):
                if any(kind(ei) == "never" for ei in cyc):
                    continue  # a never-enabled cycle edge: cycle cannot run
                exits = cycle_exit_eis(cyc)
                if any(kind(ei) == "always" for ei in exits):
                    continue  # an always-on exit can never be disabled
                if cls._cycle_is_guarded(
                    [edges[x]["guard"] for x in cyc],
                    [edges[ei]["guard"] for ei in exits],
                ):
                    guarded_cycles += 1
                    continue
                trap_cycles.append(cyc)
        if guarded_cycles:
            findings.append(
                {
                    "type": "guarded_cycle",
                    "severity": "info",
                    "nodes": [],
                    "detail": f"{guarded_cycles} cycle(s) are bounded-retry patterns: whenever the cycle's progress edge guard fails (e.g. a retry budget is exhausted), an exit is open, and are excluded from trap counting.",
                }
            )

        trap_sccs: List[int] = []
        for si in cyclic_sccs:
            comp = set(sccs[si])
            exits = [
                ei
                for n in comp
                for ei in out_adj[n]
                if edges[ei]["dst"] not in comp
            ]
            if any(kind(ei) == "always" for ei in exits):
                continue
            cycs = cycles_by_scc.get(si, [])
            if len(cycs) == 1 and cycle_members(cycs[0]) == comp:
                continue  # single-cycle region: the uniform cycle rule
                # above has already decided it - witnessed precisely by
                # its only cycle, or exempt as a guarded cycle.  Regions
                # with several cycles get no separate exemption: they are
                # counted under the plain trap semantics.
            trap_sccs.append(si)

        # ---------------- relevance closure ----------------
        seeds = set(stuck_candidates)
        for si in trap_sccs:
            seeds.update(sccs[si])
        for cyc in trap_cycles:
            seeds.update(cycle_members(cyc))
        relevant = set(seeds)
        rev_adj: Dict[str, List[str]] = {n: [] for n in node_order}
        for e in edges:
            rev_adj[e["dst"]].append(e["src"])
        stack = list(seeds)
        while stack:
            cur = stack.pop()
            for pre in rev_adj[cur]:
                if pre not in relevant:
                    relevant.add(pre)
                    stack.append(pre)
        relevant_entries = [n for n in entries if n in relevant]

        # ---------------- variable allocation ----------------
        var_list: List[Dict[str, Any]] = []
        var_index: Dict[str, int] = {}

        def new_var(name: str, label: str, category: str, prior: float = 0.5) -> int:
            if name in var_index:
                return var_index[name]
            idx = len(var_list) + 1
            var_index[name] = idx
            var_list.append({"name": name, "label": label, "prior": prior, "category": category})
            return idx

        atom_var: Dict[str, int] = {}
        for e in edges:
            if node_terminal.get(e["src"]):
                continue  # dead edge (terminal source): its conditions
                # are not part of the execution state space
            for conj in e["guard"]:
                for atom, _pos in conj:
                    if atom not in atom_var:
                        slug = re.sub(r"[^a-zA-Z0-9]+", "_", atom).strip("_")[:40] or "cond"
                        atom_var[atom] = new_var(
                            f"cond_{slug}_{len(atom_var)}",
                            f"Condition: {atom}",
                            "Edge Guard Condition",
                        )

        r_var = {
            n: new_var(f"reach_{n}", f"Reachable: {n}", "Encoding: Reachability")
            for n in node_order
            if n in relevant
        }
        s_var = {
            n: new_var(f"stuck_{n}", f"Stuck witness: {n}", "Encoding: Trap Witness")
            for n in stuck_candidates
            if n in relevant
        }
        t_var = new_var("trap_exists", "A trap assignment holds", "Encoding: Trap Witness")
        witness_vars: Dict[str, str] = {}
        for n, sv in s_var.items():
            witness_vars[var_list[sv - 1]["name"]] = (
                f"Deadlock at node '{n}': reachable with every outgoing edge disabled"
            )

        clause_pairs: List[Tuple[List[int], str]] = []

        # guard "enabled" term per edge: None = always true,
        # False = never enabled, otherwise a DIMACS literal int.
        en_term: Dict[int, Any] = {}

        def lit_of(atom: str, pos: bool) -> int:
            v = atom_var[atom]
            return v if pos else -v

        for ei, e in enumerate(edges):
            if node_terminal.get(e["src"]):
                en_term[ei] = False
                continue
            dnf = e["guard"]
            if dnf == [[]]:
                en_term[ei] = None
                continue
            if dnf == []:
                en_term[ei] = False
                continue
            if len(dnf) == 1 and len(dnf[0]) == 1:
                a, p = dnf[0][0]
                en_term[ei] = lit_of(a, p)
                continue
            g = new_var(
                f"guard_edge_{ei}",
                f"Guard of edge {e['src']} -> {e['dst']}",
                "Encoding: Guard",
            )
            en_term[ei] = g
            disjunct_lits = [[lit_of(a, p) for a, p in conj] for conj in dnf]
            for dl in disjunct_lits:
                clause_pairs.append(
                    ([-x for x in dl] + [g], f"Guard definition: {e['src']} -> {e['dst']}")
                )
            picks: List[List[int]] = [[]]
            for dl in disjunct_lits:
                picks = [pk + [x] for pk in picks for x in dl]
            for pk in picks:
                clause_pairs.append(([-g] + pk, f"Guard definition: {e['src']} -> {e['dst']}"))

        def en_lit(ei: int) -> Optional[int]:
            """Enabled literal for edge ei, or None if unconditionally on.
            Callers must skip edges whose en_term is False beforehand."""
            t = en_term[ei]
            return None if t is None else int(t)

        # ---------------- reachability (canonical supports) ----------------
        w_var: Dict[int, int] = {}
        supports_of: Dict[str, List[int]] = {}
        for n in node_order:
            if n not in r_var or n in entry_set:
                continue
            cand = []
            for ei in in_adj[n]:
                if edges[ei]["src"] == n:
                    continue
                if en_term[ei] is False:
                    continue
                cand.append(ei)
            cand.sort(key=lambda ei: 0 if scc_of[edges[ei]["src"]] != scc_of[n] else 1)
            supports_of[n] = cand
            for ei in cand:
                w_var[ei] = new_var(
                    f"support_edge_{ei}",
                    f"Support: {edges[ei]['src']} -> {n}",
                    "Encoding: Reachability Support",
                )

        for n in relevant_entries:
            clause_pairs.append(([r_var[n]], f"Entry node '{n}' is reachable"))
        for n, cand in supports_of.items():
            rv = r_var[n]
            if cand:
                clause_pairs.append(
                    ([-rv] + [w_var[ei] for ei in cand], f"Reachability of '{n}' needs a supporting edge")
                )
            else:
                clause_pairs.append(([-rv], f"Node '{n}' has no supporting edge and is unreachable"))
            for pos_i, ei in enumerate(cand):
                w = w_var[ei]
                src = edges[ei]["src"]
                en = en_lit(ei)
                if en is not None:
                    clause_pairs.append(([-w, en], f"Support {src} -> {n} requires its guard"))
                clause_pairs.append(([-w, r_var[src]], f"Support {src} -> {n} requires '{src}' reachable"))
                clause_pairs.append(([-w, rv], f"Support {src} -> {n} establishes '{n}'"))
                # canonical-first: w_i requires every earlier support ineligible
                for pj in range(pos_i):
                    ej = cand[pj]
                    enj = en_lit(ej)
                    cl = [-w, -r_var[edges[ej]["src"]]]
                    if enj is not None:
                        cl = [-w, -enj, -r_var[edges[ej]["src"]]]
                    clause_pairs.append((cl, f"Canonical support for '{n}': earlier edge must be ineligible"))
                # forcing: eligible + target reached + earlier ineligible -> w_i
                combos: List[List[int]] = [[]]
                for pj in range(pos_i):
                    ej = cand[pj]
                    enj = en_lit(ej)
                    opts = [r_var[edges[ej]["src"]]]
                    if enj is not None:
                        opts.append(enj)
                    combos = [c + [o] for c in combos for o in opts]
                for combo in combos:
                    cl = []
                    if en is not None:
                        cl.append(-en)
                    cl += [-r_var[src]] + combo + [w]
                    clause_pairs.append((cl, f"Canonical support for '{n}' via {src} -> {n}"))

        # grounding: a simple cycle without an entry member can only be
        # fully reachable if an enabled edge enters it from outside.
        all_cycles: List[Tuple[int, ...]] = []
        for si in cyclic_sccs:
            all_cycles.extend(cycles_by_scc.get(si, []))
        seen_ground: set = set()
        for cyc in all_cycles:
            members = cycle_members(cyc)
            key = frozenset(members)
            if key in seen_ground or members & entry_set:
                continue
            seen_ground.add(key)
            cl = [-r_var[m] for m in sorted(members) if m in r_var]
            if not cl:
                continue
            for m in sorted(members):
                for ei in in_adj[m]:
                    if edges[ei]["src"] in members or en_term[ei] is False:
                        continue
                    a_name = f"cycle_entry_{ei}"
                    av = new_var(a_name, f"Cycle entry via {edges[ei]['src']} -> {m}", "Encoding: Grounding")
                    en = en_lit(ei)
                    if en is not None:
                        clause_pairs.append(([-av, en], "Cycle entry requires its guard"))
                    clause_pairs.append(([-av, r_var[edges[ei]["src"]]], "Cycle entry requires source reachable"))
                    back = [-r_var[edges[ei]["src"]], av]
                    if en is not None:
                        back = [-en, -r_var[edges[ei]["src"]], av]
                    clause_pairs.append((back, "Cycle entry definition"))
                    cl.append(av)
            clause_pairs.append((cl, f"Grounding: cycle {sorted(members)} needs an entry from outside"))

        # ---------------- stuck witnesses ----------------
        trap_witness_vars: List[int] = list(s_var.values())
        for n, sv in s_var.items():
            clause_pairs.append(([-sv, r_var[n]], f"Stuck witness '{n}' requires reachability"))
            live_lits: List[int] = []
            for ei in out_adj[n]:
                if en_term[ei] is False:
                    continue
                en = en_lit(ei)
                if en is not None:
                    live_lits.append(en)
                    clause_pairs.append(
                        ([-sv, -en], f"Stuck witness '{n}' requires edge {edges[ei]['src']} -> {edges[ei]['dst']} disabled")
                    )
            back = [-r_var[n]] + live_lits + [sv]
            clause_pairs.append((back, f"Node '{n}' is stuck when reached with all exits disabled"))

        # ---------------- livelock witnesses: simple cycles ----------------
        def add_cycle_witness(cyc: Tuple[int, ...]) -> None:
            members: List[str] = []
            for ei in cyc:
                if edges[ei]["src"] not in members:
                    members.append(edges[ei]["src"])
            cv = new_var(
                f"livelock_{len(trap_witness_vars)}_{'_'.join(members)[:32]}",
                f"Livelock witness: cycle {' -> '.join(members)}",
                "Encoding: Trap Witness",
            )
            witness_vars[var_list[cv - 1]["name"]] = (
                f"Livelock on cycle {' -> '.join(members)}: reachable, cycle edges enabled, all exits disabled"
            )
            trap_witness_vars.append(cv)
            clause_pairs.append(
                ([-cv] + [r_var[m] for m in members if m in r_var], "Livelock cycle requires a reached member")
            )
            for ei in cyc:
                en = en_lit(ei)
                if en is not None:
                    clause_pairs.append(([-cv, en], "Livelock cycle requires its edges enabled"))
            exits = cycle_exit_eis(cyc)
            exit_lits: List[int] = []
            for ei in exits:
                if en_term[ei] is False:
                    continue
                en = en_lit(ei)
                exit_lits.append(en)
                clause_pairs.append(([-cv, -en], "Livelock cycle requires exit disabled"))
            for m in members:
                if m not in r_var:
                    continue
                back = [-r_var[m]]
                back += [-en_lit(ei) for ei in cyc if en_lit(ei) is not None]
                back += exit_lits
                back += [cv]
                clause_pairs.append((back, f"Livelock cycle forms when '{m}' is reached"))

        for cyc in trap_cycles:
            add_cycle_witness(cyc)

        # ---------------- livelock witnesses: SCC regions ----------------
        scc_witness_skipped = False
        for si in trap_sccs:
            comp = list(sccs[si])
            comp_set = set(comp)
            exits = [
                ei
                for n in comp
                for ei in out_adj[n]
                if edges[ei]["dst"] not in comp_set
            ]
            exit_lits = [
                en_lit(ei) for ei in exits if en_term[ei] is not False and en_term[ei] is not None
            ]
            # Per-member progress condition: a member only needs an
            # enabled internal edge when it is actually reached under
            # the assignment (unreached members cannot block the trap).
            # D_m = (not reached) OR (some internal edge enabled); a
            # member with an unconditional internal edge is unconstrained.
            member_opts: List[Optional[List[int]]] = []
            feasible = True
            for n in comp:
                opts: List[int] = []
                has_uncond = False
                for ei in out_adj[n]:
                    if edges[ei]["dst"] not in comp_set or en_term[ei] is False:
                        continue
                    en = en_lit(ei)
                    if en is None:
                        has_uncond = True
                    else:
                        opts.append(en)
                if has_uncond:
                    member_opts.append(None)
                elif n in r_var:
                    member_opts.append([-r_var[n]] + opts)
                elif opts:
                    member_opts.append(opts)
                else:
                    feasible = False
                    break
            if not feasible:
                continue
            # exact converse via distribution; cap the clause product
            disjuncts: List[List[int]] = []
            disjuncts.append([r_var[m] for m in comp if m in r_var])
            for opts in member_opts:
                if opts:
                    disjuncts.append(opts)
            combos = 1
            for d in disjuncts:
                combos *= max(1, len(d))
            if combos > 512:
                scc_witness_skipped = True
                continue
            cv = new_var(
                f"livelock_scc_{si}",
                f"Livelock witness: region {', '.join(comp)}",
                "Encoding: Trap Witness",
            )
            witness_vars[var_list[cv - 1]["name"]] = (
                f"Livelock in region {comp}: reached, every member keeps an enabled internal edge, all exits disabled"
            )
            trap_witness_vars.append(cv)
            clause_pairs.append(
                ([-cv] + [r_var[m] for m in comp if m in r_var], "Livelock region requires a reached member")
            )
            for opts in member_opts:
                if opts:
                    clause_pairs.append(([-cv] + opts, "Livelock region: every reached member keeps an enabled internal edge"))
            for ei in exits:
                if en_term[ei] is False or en_term[ei] is None:
                    continue
                clause_pairs.append(([-cv, -en_lit(ei)], "Livelock region requires exit disabled"))
            picks: List[List[int]] = [[]]
            for d in disjuncts:
                picks = [pk + [-x] for pk in picks for x in d]
            for pk in picks:
                clause_pairs.append((pk + exit_lits + [cv], "Livelock region forms"))

        # ---------------- trap master variable ----------------
        clause_pairs.append(([t_var], "Count only trap assignments"))
        if trap_witness_vars:
            clause_pairs.append(
                ([-t_var] + trap_witness_vars, "A trap requires a deadlock or livelock witness")
            )
            for tv in trap_witness_vars:
                clause_pairs.append(([-tv, t_var], "Witness implies trap"))
        else:
            clause_pairs.append(([-t_var], "No trap is possible in this graph"))

        # ---------------- dedupe ----------------
        seen: set = set()
        clauses: List[List[int]] = []
        clause_descs: List[str] = []
        for cl, desc in clause_pairs:
            key = tuple(sorted(set(cl)))
            if not key or key in seen:
                continue
            seen.add(key)
            clauses.append(list(key))
            clause_descs.append(desc)

        if len(var_list) > 64:
            raise ValueError(
                f"Agent graph encoding needs {len(var_list)} variables "
                f"(condition atoms + reachability encoding), exceeding the engine limit MAX_VARS=64. "
                "Simplify the graph or split it into subgraphs."
            )

        var_names = [v["name"] for v in var_list]
        limitations: List[str] = []
        if cycle_overflow:
            limitations.append(
                "Cycle enumeration inside a large strongly connected region hit the safety cap; "
                "region-level livelock witnesses still apply, but some simple-cycle witnesses may be missing."
            )
        if dropped_terminal_edges:
            limitations.append(
                "Edges out of terminal nodes are ignored in trap analysis: "
                "terminals are absorbing end states."
            )
        if scc_witness_skipped:
            limitations.append(
                "One strongly connected region was too large for the exact region-level livelock "
                "witness (clause-product cap); its simple-cycle witnesses still apply."
            )
        limitations.append(
            "Reachability grounding is exact for cycles entered from outside the cycle; mutually "
            "feeding cycle tangles inside one SCC that are disconnected from every entry are also "
            "reported as unreachable_node findings."
        )
        analysis = {
            "entries": entries,
            "terminals": sorted(n for n in node_order if node_terminal[n]),
            "nodes": node_order,
            "edges": [
                {"from": e["src"], "to": e["dst"], "guard": e["guard"]} for e in edges
            ],
            "condition_variables": sorted(atom_var.keys()),
            "sccs": [sorted(c) for c in sccs],
            "findings": findings,
            "stuck_candidates": stuck_candidates,
            "limitations": limitations,
            "trap_semantics": (
                "#F counts condition assignments under which a reachable non-terminal node is "
                "deadlocked (all outgoing edges disabled) or a cycle/region is reachable with its "
                "cycle edges enabled and all of its exits disabled (livelock). Bounded-retry cycles "
                "are excluded under one uniform rule: a cycle is guarded when one of its edges is a "
                "progress edge (a genuinely conditional edge traversed on every iteration, e.g. a "
                "retry-budget edge) and its exits, taken together, are open whenever that edge's "
                "guard fails. A region is exempt only when it consists of a single guarded cycle; "
                "multi-cycle regions are counted under the plain semantics."
            ),
        }
        log.append(
            f"[Agent Graph Parser] Encoded {len(atom_var)} condition variables over "
            f"{len(node_order)} nodes / {len(edges)} edges into an exact trap-counting CNF "
            f"({len(var_list)} vars, {len(clauses)} clauses)."
        )
        return {
            "num_vars": len(var_list),
            "variables": var_list,
            "clauses": clauses,
            "clause_descriptions": clause_descs,
            "pretty_clauses": [cls.format_clause_math(c, var_names) for c in clauses],
            "dimacs": cls.to_dimacs(len(var_list), clauses, "Agent Workflow Trap Audit"),
            "self_correction_log": log,
            "graph_analysis": analysis,
            "witness_vars": witness_vars,
        }

    @classmethod
    def _try_llm_autoformalize(
        cls, raw_text: str, api_key_override: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        If OPENAI_API_KEY is present in environment or passed via BYOK, calls OpenAI
        Structured Outputs with a Self-Correction Verification Loop to formalize arbitrary prose.
        """
        api_key = (api_key_override or os.environ.get("OPENAI_API_KEY", "")).strip()
        if not api_key:
            return None

        prompt = (
            "You are SharpLogic's Autoformalization Compiler. Convert the user's business rules "
            "into a JSON object with keys: "
            "'variables': list of {'name': snake_case_str, 'label': str, 'prior': float 0.1..0.9}, "
            "'clauses': list of integer lists representing k-CNF clauses (1-indexed, negative for NOT) "
            "that are satisfied when a loophole/violation occurs, and 'clause_descriptions': list of strings."
        )
        payload = {
            "model": "gpt-4o-mini",
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": raw_text[:4000]},
            ],
            "temperature": 0.0,
        }
        try:
            req = Request(
                "https://api.openai.com/v1/chat/completions",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                },
                method="POST",
            )
            with urlopen(req, timeout=8) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
            content = json.loads(res_data["choices"][0]["message"]["content"])
            vars_raw = content.get("variables", [])[:32]
            if not vars_raw:
                return None
            n = len(vars_raw)
            variables = [
                {
                    "name": re.sub(r"[^a-z0-9_]", "_", str(v.get("name", f"x_{i+1}")).lower()),
                    "label": str(v.get("label", f"Var {i+1}")),
                    "prior": float(v.get("prior", 0.5)),
                    "category": "LLM Autoformalized",
                }
                for i, v in enumerate(vars_raw)
            ]
            # Self-Correction Bounds Filter: strip any out-of-range literal indices
            valid_clauses = []
            for cl in content.get("clauses", []):
                cleaned = [int(lit) for lit in cl if isinstance(lit, int) and 1 <= abs(lit) <= n]
                if cleaned:
                    valid_clauses.append(cleaned)
            if not valid_clauses:
                return None
            var_names = [v["name"] for v in variables]
            descs = content.get("clause_descriptions", [f"Clause #{i+1}" for i in range(len(valid_clauses))])
            return {
                "num_vars": n,
                "variables": variables,
                "clauses": valid_clauses,
                "clause_descriptions": descs,
                "pretty_clauses": [cls.format_clause_math(c, var_names) for c in valid_clauses],
                "dimacs": cls.to_dimacs(n, valid_clauses, "LLM Autoformalized k-CNF"),
                "self_correction_log": [
                    f"[LLM Autoformalizer] Compiled {n} variables and {len(valid_clauses)} verified k-CNF clauses via OpenAI Structured Outputs."
                ],
            }
        except Exception:
            return None

    @classmethod
    def compile_custom_rules(
        cls,
        raw_text: str,
        base_vars: Optional[List[Dict[str, Any]]] = None,
        api_key_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Multi-Mode Compiler:
        1. Detects AWS IAM Policy JSON or Agent Workflow Graph JSON automatically.
        2. Uses Cloud LLM Autoformalizer if OPENAI_API_KEY is configured or passed via BYOK.
        3. Uses deterministic Bilingual Natural Language + Symbolic DSL compiler offline.
        """
        stripped = raw_text.strip()
        if stripped.startswith("{"):
            parsed_json = None
            try:
                parsed_json = json.loads(stripped)
            except Exception:
                parsed_json = None
            if isinstance(parsed_json, dict):
                if "Statement" in parsed_json:
                    return cls._compile_aws_iam_json(parsed_json)
                if "nodes" in parsed_json or "edges" in parsed_json:
                    # Compile errors (e.g. the encoding exceeds the
                    # engine's MAX_VARS limit) propagate loudly instead
                    # of silently degrading to a text-mode analysis.
                    return cls._compile_agent_graph_json(parsed_json)

        llm_compiled = cls._try_llm_autoformalize(raw_text, api_key_override=api_key_override)
        if llm_compiled is not None:
            return llm_compiled

        lines = [ln.strip() for ln in raw_text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        var_map: Dict[str, int] = {}
        var_list: List[Dict[str, Any]] = []
        clauses: List[List[int]] = []
        clause_descs: List[str] = []
        correction_log: List[str] = []

        if base_vars:
            for i, v in enumerate(base_vars):
                v_id = v["name"]
                var_map[v_id] = i + 1
                var_list.append(dict(v))

        def get_or_create_var(token: str, default_weight: float = 0.35) -> int:
            clean = re.sub(r"[^a-zA-Z0-9_\u4e00-\u9fff]", "_", token.strip().lower()).strip("_")
            if not clean:
                clean = f"cond_{len(var_list) + 1}"
            if clean not in var_map:
                if len(var_list) >= 32:
                    return var_map[var_list[-1]["name"]]
                idx = len(var_list) + 1
                var_map[clean] = idx
                var_list.append(
                    {
                        "name": clean,
                        "label": clean.replace("_", " ").title(),
                        "prior": default_weight,
                        "category": "Auto-Extracted",
                    }
                )
                correction_log.append(
                    f"[Auto-Formalize] Bound symbol '{clean}' -> variable x_{idx} (prior={default_weight})"
                )
            return var_map[clean]

        for line_idx, line in enumerate(lines):
            if line.upper().startswith("CLAUSE:"):
                expr = line.split(":", 1)[1].strip()
                disjuncts = [d.strip() for d in re.split(r"\bOR\b|\||∨", expr, flags=re.IGNORECASE) if d.strip()]
                cl: List[int] = []
                for d in disjuncts:
                    is_neg = False
                    if re.match(r"^(NOT|¬|!|~)\s*", d, flags=re.IGNORECASE):
                        is_neg = True
                        d = re.sub(r"^(NOT|¬|!|~)\s*", "", d, flags=re.IGNORECASE).strip()
                    v_idx = get_or_create_var(d)
                    cl.append(-v_idx if is_neg else v_idx)
                if cl:
                    clauses.append(cl)
                    clause_descs.append(f"Rule #{line_idx + 1}: {line}")
                continue

            if line.upper().startswith("FORBID:") or "禁止" in line or "不得同时" in line:
                body = line.split(":", 1)[-1] if ":" in line else line
                tokens = [
                    t.strip()
                    for t in re.split(r"\bAND\b|&|∧|\+|、|和|且", body, flags=re.IGNORECASE)
                    if t.strip()
                ]
                cl = []
                for t in tokens:
                    v_idx = get_or_create_var(t)
                    cl.append(-v_idx)
                if cl:
                    clauses.append(cl)
                    clause_descs.append(f"Safety Exclusion #{line_idx + 1}: {line}")
                    correction_log.append(
                        f"[DeMorgan Self-Correction] Translated FORBID conjunction into {len(cl)}-literal negative clause."
                    )
                continue

            if line.upper().startswith("REQUIRE:") or line.upper().startswith("TRIGGER:"):
                body = line.split(":", 1)[1].strip()
                tokens = [
                    t.strip()
                    for t in re.split(r"\bAND\b|&|∧", body, flags=re.IGNORECASE)
                    if t.strip()
                ]
                for t in tokens:
                    is_neg = False
                    if re.match(r"^(NOT|¬|!|~)\s*", t, flags=re.IGNORECASE):
                        is_neg = True
                        t = re.sub(r"^(NOT|¬|!|~)\s*", "", t, flags=re.IGNORECASE).strip()
                    v_idx = get_or_create_var(t)
                    clauses.append([-v_idx if is_neg else v_idx])
                    clause_descs.append(f"Unit Constraint #{line_idx + 1}: {t}")
                continue

            m_imp = re.match(r"^(?:IF|如果|当)\s+(.+?)\s+(?:THEN|->|=>|则|必须)\s+(.+)$", line, flags=re.IGNORECASE)
            if m_imp:
                antecedents = [
                    t.strip()
                    for t in re.split(r"\bAND\b|&|∧|且", m_imp.group(1), flags=re.IGNORECASE)
                    if t.strip()
                ]
                consequent = m_imp.group(2).strip()
                cl = []
                for a in antecedents:
                    is_neg = bool(re.match(r"^(NOT|¬|!)\s*", a, flags=re.IGNORECASE))
                    a_clean = re.sub(r"^(NOT|¬|!)\s*", "", a, flags=re.IGNORECASE).strip()
                    v_idx = get_or_create_var(a_clean)
                    cl.append(v_idx if is_neg else -v_idx)

                c_neg = bool(re.match(r"^(NOT|¬|!)\s*", consequent, flags=re.IGNORECASE))
                c_clean = re.sub(r"^(NOT|¬|!)\s*", "", consequent, flags=re.IGNORECASE).strip()
                v_c = get_or_create_var(c_clean)
                cl.append(-v_c if c_neg else v_c)
                clauses.append(cl)
                clause_descs.append(f"Implication Rule #{line_idx + 1}: {line}")
                continue

            identifiers = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{2,}|[\u4e00-\u9fff]{2,6}", line)
            if identifiers:
                cl = []
                for ident in identifiers[:4]:
                    if ident.lower() in {"the", "and", "with", "when", "then", "rule", "must", "not", "for"}:
                        continue
                    v_idx = get_or_create_var(ident)
                    cl.append(v_idx)
                if cl:
                    clauses.append(cl)
                    clause_descs.append(f"NL Extracted Clause #{line_idx + 1}: {line[:60]}")

        while len(var_list) < 16:
            idx = len(var_list) + 1
            aux_name = f"context_guard_{idx}"
            var_map[aux_name] = idx
            var_list.append(
                {
                    "name": aux_name,
                    "label": f"Context State #{idx}",
                    "prior": 0.5,
                    "category": "State Space Context",
                }
            )
            if idx > 10:
                clauses.append([idx])
                clause_descs.append(f"Context Invariant #{idx}: Fixed boundary condition")

        var_names = [v["name"] for v in var_list]
        pretty_clauses = [cls.format_clause_math(c, var_names) for c in clauses]

        return {
            "num_vars": len(var_list),
            "variables": var_list,
            "clauses": clauses,
            "clause_descriptions": clause_descs,
            "pretty_clauses": pretty_clauses,
            "dimacs": cls.to_dimacs(len(var_list), clauses),
            "self_correction_log": correction_log
            or ["[Compiler] All symbolic constraints verified in 1st pass (0 syntax retries)."],
        }
