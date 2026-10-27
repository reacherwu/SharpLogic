"""
Zero-dependency C-ABI bridge to libsharplogic_core (Native Rust)
with Automatic High-Availability Serverless Fallback for Vercel Python Runtime.
"""

import ctypes
import math
import os
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

MAX_VARS = 64
K_HOT = 32
K_COLD = 96
K_TOTAL = 128
EMBED_DIM = 32
PAYLOAD_LEN = 256
MAGIC_HEADER = b"SLGC"
SNAPSHOT_VERSION = 1


class CnfAuditResultStruct(ctypes.Structure):
    _fields_ = [
        ("is_satisfiable", ctypes.c_uint8),
        ("num_vars", ctypes.c_uint32),
        ("num_clauses", ctypes.c_uint32),
        ("exact_count_lo", ctypes.c_uint64),
        ("exact_count_hi", ctypes.c_uint64),
        ("total_space_lo", ctypes.c_uint64),
        ("total_space_hi", ctypes.c_uint64),
        ("combinatorial_ratio", ctypes.c_double),
        ("weighted_probability", ctypes.c_double),
        ("ghost_path_probability", ctypes.c_double),
        ("sharp_score", ctypes.c_double),
        ("solve_time_us", ctypes.c_double),
        ("components_found", ctypes.c_uint32),
        ("conflict_clause_idx", ctypes.c_int32),
        ("ghost_assignment", ctypes.c_uint8 * MAX_VARS),
    ]


def _find_dylib_path() -> Optional[str]:
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    candidates = [
        os.path.join(root_dir, "target", "release", "libsharplogic_core.dylib"),
        os.path.join(root_dir, "target", "release", "libsharplogic_core.so"),
        os.path.join(root_dir, "target", "release", "sharplogic_core.dll"),
        os.path.join(root_dir, "target", "debug", "libsharplogic_core.dylib"),
        os.path.join(root_dir, "target", "debug", "libsharplogic_core.so"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


# ============================================================================
# BIT-EXACT SERVERLESS KERNEL (Used when deployed to Vercel Python Lambda)
# Implements the exact same Unit Propagation + Disjoint Component DPLL + O(K)
# Manifold + b"SLGC" binary snapshot protocol as src/lib.rs.
# ============================================================================


def _serverless_unit_propagate(
    clauses: List[Tuple[List[int], int]],
    assign: List[int],
    weights: List[float],
) -> Tuple[Optional[List[Tuple[List[int], int]]], float, float, int]:
    active = list(clauses)
    acc_wmc = 1.0
    acc_best_w = 1.0

    while True:
        unit_found = False
        next_active: List[Tuple[List[int], int]] = []

        for lits, orig_idx in active:
            satisfied = False
            rem: List[int] = []
            for lit in lits:
                v = abs(lit) - 1
                pol = 1 if lit > 0 else 0
                cur = assign[v]
                if cur == pol:
                    satisfied = True
                    break
                elif cur == -1:
                    if lit not in rem:
                        rem.append(lit)
            if satisfied:
                continue
            if not rem:
                return None, 0.0, 0.0, orig_idx
            if len(rem) == 1:
                unit_lit = rem[0]
                v = abs(unit_lit) - 1
                val = 1 if unit_lit > 0 else 0
                if assign[v] == -1:
                    assign[v] = val
                    w = weights[v] if val == 1 else (1.0 - weights[v])
                    acc_wmc *= w
                    acc_best_w *= w
                    unit_found = True
                elif assign[v] != val:
                    return None, 0.0, 0.0, orig_idx
            else:
                next_active.append((rem, orig_idx))

        active = next_active
        if not unit_found:
            break

    return active, acc_wmc, acc_best_w, -1


def _serverless_subproblem_key(clauses, comp_vars, assign):
    canon = sorted(idx for _, idx in clauses)
    relevant = set(comp_vars)
    for lits, _ in clauses:
        for lit in lits:
            relevant.add(abs(lit) - 1)
    return (
        tuple(canon),
        tuple(sorted(comp_vars)),
        tuple(assign[v] + 1 for v in sorted(relevant)),
    )


def _serverless_dpll_component(
    clauses: List[Tuple[List[int], int]],
    comp_vars: List[int],
    assign: List[int],
    weights: List[float],
    cache=None,
) -> Tuple[int, float, float, List[int], int]:
    """Memoized entry point; the counter is pure in (clauses, comp_vars,
    relevant assignment), so caching subproblem results is exact."""
    if cache is None:
        cache = {}
    key = None
    if len(clauses) >= 32:
        key = _serverless_subproblem_key(clauses, comp_vars, assign)
        if key in cache:
            return cache[key]
    result = _serverless_dpll_inner(clauses, comp_vars, assign, weights, cache)
    if key is not None:
        cache[key] = result
    return result


def _serverless_dpll_inner(
    clauses: List[Tuple[List[int], int]],
    comp_vars: List[int],
    assign: List[int],
    weights: List[float],
    cache,
) -> Tuple[int, float, float, List[int], int]:
    local_assign = list(assign)
    reduced, unit_wmc, unit_best_w, conflict_idx = _serverless_unit_propagate(
        clauses, local_assign, weights
    )
    if reduced is None:
        return 0, 0.0, 0.0, local_assign, conflict_idx

    var_in_clauses = set()
    for lits, _ in reduced:
        for lit in lits:
            var_in_clauses.add(abs(lit) - 1)

    remaining_vars: List[int] = []
    free_count = 0
    for v in comp_vars:
        if local_assign[v] == -1:
            if v in var_in_clauses:
                remaining_vars.append(v)
            else:
                free_count += 1
                p = weights[v]
                if p >= 0.5:
                    local_assign[v] = 1
                    unit_best_w *= p
                else:
                    local_assign[v] = 0
                    unit_best_w *= 1.0 - p

    if not reduced:
        return (1 << free_count), unit_wmc, unit_best_w, local_assign, -1

    # Dynamic component decomposition of the residual formula
    # (mirrors the Rust kernel exactly).
    if len(reduced) >= 6:
        parent = {v: v for v in remaining_vars}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for lits, _ in reduced:
            first = abs(lits[0]) - 1
            for lit in lits[1:]:
                ra, rb = find(first), find(abs(lit) - 1)
                if ra != rb:
                    parent[ra] = rb
        groups = {}
        for v in remaining_vars:
            groups.setdefault(find(v), []).append(v)
        if len(groups) > 1:
            total_count = 1 << free_count
            total_wmc = unit_wmc
            total_best = unit_best_w
            chosen = list(local_assign)
            for group in sorted(groups.values(), key=lambda g: g[0]):
                gset = set(group)
                gclauses = [
                    c for c in reduced
                    if all((abs(l) - 1) in gset for l in c[0])
                ]
                sub = _serverless_dpll_component(gclauses, group, local_assign, weights, cache)
                if sub[0] == 0:
                    return (0, 0.0, 0.0, local_assign, sub[4])
                total_count *= sub[0]
                total_wmc *= sub[1]
                total_best *= sub[2]
                for v in group:
                    if sub[3][v] != -1:
                        chosen[v] = sub[3][v]
            for v in comp_vars:
                if local_assign[v] != -1 and chosen[v] == -1:
                    chosen[v] = local_assign[v]
            return (total_count, total_wmc, total_best, chosen, -1)

    min_len = min(len(lits) for lits, _ in reduced)
    best_var = remaining_vars[0]
    best_score = -1
    for v in remaining_vars:
        score = 0
        for lits, _ in reduced:
            w = 8 if len(lits) == min_len else 1
            for lit in lits:
                if abs(lit) - 1 == v:
                    score += w
        if score > best_score:
            best_score = score
            best_var = v

    assign_t = list(local_assign)
    assign_t[best_var] = 1
    cnt_t, wmc_t, best_w_t, best_a_t, conf_t = _serverless_dpll_component(
        reduced, remaining_vars, assign_t, weights, cache
    )

    assign_f = list(local_assign)
    assign_f[best_var] = 0
    cnt_f, wmc_f, best_w_f, best_a_f, conf_f = _serverless_dpll_component(
        reduced, remaining_vars, assign_f, weights, cache
    )

    p_t = weights[best_var]
    p_f = 1.0 - p_t
    scaled_count = (cnt_t + cnt_f) * (1 << free_count)
    total_wmc = unit_wmc * ((p_t * wmc_t if cnt_t > 0 else 0.0) + (p_f * wmc_f if cnt_f > 0 else 0.0))

    cand_t = unit_best_w * p_t * best_w_t if cnt_t > 0 else -1.0
    cand_f = unit_best_w * p_f * best_w_f if cnt_f > 0 else -1.0

    if cand_t >= cand_f and cnt_t > 0:
        best_w, chosen = cand_t, list(best_a_t)
    elif cnt_f > 0:
        best_w, chosen = cand_f, list(best_a_f)
    else:
        best_w, chosen = 0.0, list(local_assign)

    for v in comp_vars:
        if local_assign[v] != -1 and chosen[v] == -1:
            chosen[v] = local_assign[v]

    conflict = -1
    if scaled_count == 0:
        conflict = conf_t if conf_t >= 0 else conf_f

    return scaled_count, total_wmc, best_w, chosen, conflict


def _serverless_solve_cnf(
    num_vars: int,
    clauses_raw: List[List[int]],
    prior_weights: List[float],
) -> Dict[str, Any]:
    t0 = time.perf_counter()
    if num_vars > MAX_VARS:
        raise ValueError(
            f"num_vars {num_vars} exceeds the engine limit MAX_VARS={MAX_VARS}"
        )
    n = num_vars
    weights = [
        min(0.9999, max(0.0001, float(prior_weights[i]))) if i < len(prior_weights) else 0.5
        for i in range(n)
    ]
    clauses: List[Tuple[List[int], int]] = []
    for idx, cl in enumerate(clauses_raw):
        valid = [int(lit) for lit in cl if lit != 0 and abs(int(lit)) <= n]
        clauses.append((valid, idx))

    total_space = 1 << n
    assign = [-1] * MAX_VARS
    active_clauses, global_wmc, global_best_w, conflict_idx = _serverless_unit_propagate(
        clauses, assign, weights
    )
    if active_clauses is None:
        elapsed_us = (time.perf_counter() - t0) * 1_000_000.0
        return {
            "is_satisfiable": False,
            "num_vars": n,
            "num_clauses": len(clauses_raw),
            "exact_count": 0,
            "total_space": total_space,
            "combinatorial_ratio": 0.0,
            "weighted_probability": 0.0,
            "ghost_path_probability": 0.0,
            "sharp_score": 100.0,
            "solve_time_us": round(elapsed_us, 2),
            "components_found": 0,
            "conflict_clause_idx": conflict_idx,
            "ghost_raw": [0] * n,
        }

    adj: Dict[int, set] = {v: set() for v in range(n)}
    var_active = [False] * n
    for lits, _ in active_clauses:
        for i in range(len(lits)):
            u = abs(lits[i]) - 1
            var_active[u] = True
            for j in range(i + 1, len(lits)):
                v = abs(lits[j]) - 1
                adj[u].add(v)
                adj[v].add(u)

    global_count = 1
    for v in range(n):
        if assign[v] == -1 and not var_active[v]:
            global_count *= 2
            p = weights[v]
            if p >= 0.5:
                assign[v] = 1
                global_best_w *= p
            else:
                assign[v] = 0
                global_best_w *= 1.0 - p

    visited = [False] * n
    components: List[List[int]] = []
    for v in range(n):
        if var_active[v] and not visited[v]:
            comp = []
            queue = [v]
            visited[v] = True
            while queue:
                curr = queue.pop(0)
                comp.append(curr)
                for nxt in adj[curr]:
                    if var_active[nxt] and not visited[nxt]:
                        visited[nxt] = True
                        queue.append(nxt)
            components.append(comp)

    num_components = max(1, len(components))
    first_conflict = -1

    for comp_vars in components:
        comp_set = set(comp_vars)
        comp_clauses = [
            (lits, oidx)
            for lits, oidx in active_clauses
            if any((abs(lit) - 1) in comp_set for lit in lits)
        ]
        c_cnt, c_wmc, c_best_w, c_assign, c_conf = _serverless_dpll_component(
            comp_clauses, comp_vars, assign, weights
        )
        if c_cnt == 0:
            global_count = 0
            global_wmc = 0.0
            global_best_w = 0.0
            first_conflict = c_conf
            break
        else:
            global_count *= c_cnt
            global_wmc *= c_wmc
            global_best_w *= c_best_w
            for v in comp_vars:
                if c_assign[v] != -1:
                    assign[v] = c_assign[v]

    elapsed_us = (time.perf_counter() - t0) * 1_000_000.0
    comb_ratio = 0.0 if global_count == 0 else (global_count / total_space)
    if global_count == 0:
        sharp_score = 100.0
    else:
        log_pen = min(48.0, 1.0 + math.log(global_count) * 6.5)
        wmc_pen = min(45.0, math.sqrt(max(0.0, global_wmc)) * 85.0)
        sharp_score = round(min(88.0, max(5.0, 100.0 - log_pen - wmc_pen)), 1)

    return {
        "is_satisfiable": global_count > 0,
        "num_vars": n,
        "num_clauses": len(clauses_raw),
        "exact_count": global_count,
        "total_space": total_space,
        "combinatorial_ratio": comb_ratio,
        "weighted_probability": min(1.0, max(0.0, global_wmc)),
        "ghost_path_probability": min(1.0, max(0.0, global_best_w)),
        "sharp_score": sharp_score,
        "solve_time_us": round(elapsed_us, 2),
        "components_found": num_components,
        "conflict_clause_idx": first_conflict,
        "ghost_raw": [1 if assign[v] == 1 else 0 for v in range(n)],
    }


def _causal_embed_py(text: str, is_query: bool) -> List[float]:
    vec = [0.0] * EMBED_DIM
    lower = text.lower()
    import re
    for token in re.split(r"[^a-z0-9_:]+", lower):
        if not token:
            continue
        h = 0xCBF29CE484222325
        for b in token.encode("utf-8"):
            h ^= b
            h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
        idx1 = h % EMBED_DIM
        idx2 = (h >> 16) % EMBED_DIM
        sign = 1.0 if ((h >> 32) & 1) == 0 else -1.0
        vec[idx1] += 1.0
        vec[idx2] += 0.5 * sign

    hyp = [0.0] * EMBED_DIM
    if any(k in lower for k in ("refund", "payout", "loss", "margin", "亏本", "薅羊毛", "discount", "vip", "coupon", "promo")):
        hyp[0] += 2.5
        hyp[1] += 2.0
        hyp[2] += 1.8
    if any(k in lower for k in ("cross_border", "cross-border", "跨境", "beauty", "美妆", "partial_return")):
        hyp[1] += 2.2
        hyp[3] += 2.0
    if any(k in lower for k in ("deadlock", "loop", "死锁", "agent", "langgraph", "dify", "retry", "escalate")):
        hyp[4] += 2.5
        hyp[5] += 2.2
        hyp[6] += 1.8
    if any(k in lower for k in ("wire_transfer", "mfa", "unauthorized", "越权")):
        hyp[6] += 2.2
        hyp[7] += 2.0
    if any(k in lower for k in ("iam", "assumerole", "blast", "privilege", "wildcard", "k8s", "rbac", "暴露面")):
        hyp[8] += 2.6
        hyp[9] += 2.2
        hyp[10] += 1.9
    if any(k in lower for k in ("patch", "invariant", "cap", "修复", "guardrail")):
        hyp[11] += 2.0
        hyp[12] += 1.5

    lam = 0.45 if is_query else 0.35
    for i in range(EMBED_DIM):
        vec[i] = (1.0 - lam) * vec[i] + lam * hyp[i]

    norm_sq = sum(x * x for x in vec)
    if norm_sq > 1e-12:
        inv = 1.0 / math.sqrt(norm_sq)
        vec = [x * inv for x in vec]
    return vec


class RustSharpLogicEngine:
    """
    High-speed Native Rust #k-SAT, WMC & Bounded O(K) Audit Manifold wrapper.
    Automatically loads Native Rust cdylib when available, and falls back to the
    bit-exact Serverless Kernel on Vercel Python Lambda containers.
    """

    def __init__(self, lib_path: Optional[str] = None, force_serverless: bool = False) -> None:
        self.lib_path = None if force_serverless else (lib_path or _find_dylib_path())
        self.lib = None
        self.manifold_ptr = None
        self.using_native_rust = False

        if self.lib_path and not force_serverless:
            try:
                self.lib = ctypes.CDLL(self.lib_path)
                self._configure_signatures()
                self.manifold_ptr = self.lib.sharplogic_manifold_new()
                self.using_native_rust = True
            except OSError:
                self.lib = None
                self.using_native_rust = False

        # Initialize Serverless O(K) Manifold state if Native Rust dylib is unavailable
        self._py_step = 0
        self._py_next_id = 1
        self._py_slots: List[Dict[str, Any]] = []

    def _configure_signatures(self) -> None:
        self.lib.sharplogic_solve_cnf.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_int32),
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_double),
            ctypes.POINTER(CnfAuditResultStruct),
        ]
        self.lib.sharplogic_solve_cnf.restype = ctypes.c_int32
        self.lib.sharplogic_manifold_new.argtypes = []
        self.lib.sharplogic_manifold_new.restype = ctypes.c_void_p
        self.lib.sharplogic_manifold_free.argtypes = [ctypes.c_void_p]
        self.lib.sharplogic_manifold_free.restype = None
        self.lib.sharplogic_manifold_ingest.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_uint8,
            ctypes.c_uint64,
            ctypes.c_float,
            ctypes.c_float,
        ]
        self.lib.sharplogic_manifold_ingest.restype = ctypes.c_uint64
        self.lib.sharplogic_manifold_active_count.argtypes = [ctypes.c_void_p]
        self.lib.sharplogic_manifold_active_count.restype = ctypes.c_uint32
        self.lib.sharplogic_manifold_recall_top1.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_float),
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_char_p,
            ctypes.c_uint32,
        ]
        self.lib.sharplogic_manifold_recall_top1.restype = ctypes.c_int32
        self.lib.sharplogic_manifold_save.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_uint32,
        ]
        self.lib.sharplogic_manifold_save.restype = ctypes.c_int32
        self.lib.sharplogic_manifold_load.argtypes = [
            ctypes.c_char_p,
            ctypes.c_uint32,
        ]
        self.lib.sharplogic_manifold_load.restype = ctypes.c_void_p

    def close(self) -> None:
        if self.using_native_rust and getattr(self, "manifold_ptr", None):
            self.lib.sharplogic_manifold_free(self.manifold_ptr)
            self.manifold_ptr = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def solve_cnf(
        self,
        num_vars: int,
        clauses: List[List[int]],
        weights: Optional[List[float]] = None,
        var_names: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Solves exact #k-SAT and Weighted Model Counting (#F & WMC).

        Raises ValueError when the formula exceeds MAX_VARS variables or
        references out-of-range literals; oversized formulas are never
        silently truncated.
        """
        if num_vars > MAX_VARS:
            raise ValueError(
                f"num_vars {num_vars} exceeds the engine limit MAX_VARS={MAX_VARS}; "
                "split the formula or reduce its variables"
            )
        for clause in clauses:
            for lit in clause:
                if lit == 0 or abs(lit) > num_vars:
                    raise ValueError(
                        f"clause literal {lit} is outside the variable range for num_vars={num_vars}"
                    )
        if weights is None:
            w_list = [0.5] * num_vars
        else:
            w_list = list(weights[:num_vars]) + [0.5] * max(0, num_vars - len(weights))

        names = var_names or [f"x_{i + 1}" for i in range(num_vars)]

        if self.using_native_rust:
            flat_list: List[int] = []
            for cl in clauses:
                flat_list.append(len(cl))
                flat_list.extend(cl)

            flat_arr = (ctypes.c_int32 * len(flat_list))(*flat_list) if flat_list else None
            w_arr = (ctypes.c_double * num_vars)(*w_list) if num_vars > 0 else None

            out = CnfAuditResultStruct()
            rc = self.lib.sharplogic_solve_cnf(
                ctypes.c_uint32(num_vars),
                ctypes.c_uint32(len(clauses)),
                flat_arr,
                ctypes.c_uint32(len(flat_list)),
                w_arr,
                ctypes.byref(out),
            )
            if rc != 0:
                raise RuntimeError(f"Rust sharplogic_solve_cnf failed with code {rc}")

            exact_count = (int(out.exact_count_hi) << 64) | int(out.exact_count_lo)
            total_space = (int(out.total_space_hi) << 64) | int(out.total_space_lo)
            ghost_dict = {
                (names[i] if i < len(names) else f"x_{i + 1}"): bool(out.ghost_assignment[i] == 1)
                for i in range(num_vars)
            }
            comb_ratio = float(out.combinatorial_ratio)
            w_prob = float(out.weighted_probability)
            ghost_prob = float(out.ghost_path_probability)
            sharp_score = float(out.sharp_score)
            solve_us = round(float(out.solve_time_us), 2)
            comps = int(out.components_found)
            conf_idx = int(out.conflict_clause_idx)
            is_sat = bool(out.is_satisfiable == 1)
        else:
            raw = _serverless_solve_cnf(num_vars, clauses, w_list)
            exact_count = raw["exact_count"]
            total_space = raw["total_space"]
            ghost_dict = {
                (names[i] if i < len(names) else f"x_{i + 1}"): bool(raw["ghost_raw"][i] == 1)
                for i in range(num_vars)
            }
            comb_ratio = raw["combinatorial_ratio"]
            w_prob = raw["weighted_probability"]
            ghost_prob = raw["ghost_path_probability"]
            sharp_score = raw["sharp_score"]
            solve_us = raw["solve_time_us"]
            comps = raw["components_found"]
            conf_idx = raw["conflict_clause_idx"]
            is_sat = raw["is_satisfiable"]

        comb_pct = comb_ratio * 100.0
        if comb_pct == 0.0:
            comb_pct_str = "0.000000%"
        elif comb_pct < 0.001:
            comb_pct_str = f"{comb_pct:.5f}%"
        else:
            comb_pct_str = f"{comb_pct:.4f}%"

        return {
            "is_satisfiable": is_sat,
            "num_vars": num_vars,
            "num_clauses": len(clauses),
            "exact_count": exact_count,
            "total_space": total_space,
            "combinatorial_ratio": comb_ratio,
            "combinatorial_percent": comb_pct_str,
            "weighted_probability": w_prob,
            "weighted_percent": f"{w_prob * 100.0:.3f}%",
            "ghost_path_probability": ghost_prob,
            "sharp_score": sharp_score,
            "solve_time_us": solve_us,
            "solve_time_ms": round(solve_us / 1000.0, 3),
            "components_found": comps,
            "conflict_clause_idx": conf_idx,
            "ghost_assignment": ghost_dict,
            "engine_backend": "Native Rust C-ABI" if self.using_native_rust else "Serverless Exact Kernel",
        }

    def ingest_event(
        self,
        payload: str,
        domain_tag: int = 1,
        loophole_count: int = 0,
        importance: float = 0.8,
        provenance: float = 0.9,
    ) -> int:
        if self.using_native_rust:
            raw = payload.encode("utf-8")
            return int(
                self.lib.sharplogic_manifold_ingest(
                    self.manifold_ptr,
                    raw,
                    len(raw),
                    domain_tag,
                    loophole_count,
                    importance,
                    provenance,
                )
            )
        self._py_step += 1
        rec_id = self._py_next_id
        self._py_next_id += 1
        emb = _causal_embed_py(payload, False)
        slot = {
            "record_id": rec_id,
            "step": self._py_step,
            "domain_tag": domain_tag,
            "loophole_count": loophole_count,
            "importance": importance,
            "provenance": provenance,
            "emb": emb,
            "payload": payload[:255],
        }
        # Deduplicate near-identical storm entries
        for existing in self._py_slots:
            sim = sum(a * b for a, b in zip(existing["emb"], emb))
            if sim >= 0.96 and existing["domain_tag"] == domain_tag:
                if importance >= existing["importance"]:
                    existing.update(slot)
                return rec_id
        if len(self._py_slots) < K_TOTAL:
            self._py_slots.append(slot)
        else:
            # Evict lowest importance/provenance slot
            self._py_slots.sort(key=lambda s: 0.65 * s["importance"] + 0.35 * s["provenance"])
            self._py_slots[0] = slot
        return rec_id

    def active_memory_slots(self) -> int:
        if self.using_native_rust:
            return int(self.lib.sharplogic_manifold_active_count(self.manifold_ptr))
        return len(self._py_slots)

    def recall_top1(self, query: str) -> Optional[Dict[str, Any]]:
        if self.using_native_rust:
            raw_q = query.encode("utf-8")
            score = ctypes.c_float(0.0)
            rec_id = ctypes.c_uint64(0)
            buf = ctypes.create_string_buffer(256)
            found = self.lib.sharplogic_manifold_recall_top1(
                self.manifold_ptr,
                raw_q,
                len(raw_q),
                ctypes.byref(score),
                ctypes.byref(rec_id),
                buf,
                256,
            )
            if found <= 0:
                return None
            return {
                "record_id": int(rec_id.value),
                "score": round(float(score.value), 4),
                "payload": buf.value.decode("utf-8", errors="replace"),
            }
        if not self._py_slots:
            return None
        q_emb = _causal_embed_py(query, True)
        best_score = -1.0
        best_slot = None
        for s in self._py_slots:
            sim = sum(a * b for a, b in zip(s["emb"], q_emb))
            temp = 1.0 if sim >= 0.50 else math.exp(-0.015 * max(0, self._py_step - s["step"]))
            prov = 0.5 * s["importance"] + 0.5 * s["provenance"]
            total = 0.50 * sim + 0.15 * 0.85 + 0.20 * temp + 0.15 * prov
            if total > best_score:
                best_score = total
                best_slot = s
        if not best_slot:
            return None
        return {
            "record_id": best_slot["record_id"],
            "score": round(best_score, 4),
            "payload": best_slot["payload"],
        }

    def save_snapshot(self, path: str) -> int:
        if self.using_native_rust:
            raw_p = path.encode("utf-8")
            res = int(self.lib.sharplogic_manifold_save(self.manifold_ptr, raw_p, len(raw_p)))
            if res < 0:
                raise RuntimeError(f"Failed to save snapshot to {path}")
            return res
        import json
        blob = MAGIC_HEADER + struct.pack("<IQQ", SNAPSHOT_VERSION, self._py_step, self._py_next_id)
        body = json.dumps(self._py_slots).encode("utf-8")
        data = blob + body
        with open(path, "wb") as f:
            f.write(data)
        return len(data)

    def load_snapshot(self, path: str) -> None:
        if self.using_native_rust:
            raw_p = path.encode("utf-8")
            new_ptr = self.lib.sharplogic_manifold_load(raw_p, len(raw_p))
            if not new_ptr:
                raise RuntimeError(f"Failed to load snapshot from {path}")
            if self.manifold_ptr:
                self.lib.sharplogic_manifold_free(self.manifold_ptr)
            self.manifold_ptr = new_ptr
            return
        import json
        with open(path, "rb") as f:
            data = f.read()
        if data[:4] != MAGIC_HEADER:
            raise ValueError("Invalid MAGIC header")
        _, self._py_step, self._py_next_id = struct.unpack("<IQQ", data[4:24])
        self._py_slots = json.loads(data[24:].decode("utf-8"))


_GLOBAL_ENGINE: Optional[RustSharpLogicEngine] = None


def get_engine() -> RustSharpLogicEngine:
    global _GLOBAL_ENGINE
    if _GLOBAL_ENGINE is None:
        _GLOBAL_ENGINE = RustSharpLogicEngine()
    return _GLOBAL_ENGINE
