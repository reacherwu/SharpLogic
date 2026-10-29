# SharpLogic (#∧) — Exact Trap-State Counting for AI Agent Workflows

> **"Don't Guess with Prompts. Count It with Math."**
> SharpLogic compiles your multi-agent routing graph into a CNF formula whose
> satisfying assignments are exactly the condition assignments that leave the
> workflow stuck — then counts them exactly (#F) with a native Rust engine.
>
> Inspired by the October 2026 research claim (*"The Exponential Time Hypothesis
> is False"*, expert review ongoing, not yet peer-reviewed) that exact `#k-SAT`
> counting can be done in subexponential time. **SharpLogic does not implement
> that claimed algorithm** — it uses a classical exact DPLL counter with
> component decomposition, subproblem caching, and safe clause preprocessing.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-sharplogic.vercel.app-03AA5C?style=flat-square)](https://sharplogic.vercel.app/?code=ETH-2026)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Zero-Cloud-API](https://img.shields.io/badge/Zero--API--Key-100%25%20Offline-emerald?style=flat-square)](https://sharplogic.vercel.app)

---

## ⚡ Why SharpLogic?

When you build multi-agent systems with **LangGraph**, **CrewAI**, or **Dify**, agents hand off tasks, execute tools, and retry on failure. With just 20 context & routing variables, the execution state space is **$2^{20} = 1,048,576$ assignments**.

- **The Problem with LLM Evals**: Running 1,000 or 10,000 prompt tests samples under 1% of those states. The rest can contain cyclic deadlocks (retry loops with no enabled exit), dead-end nodes, and stalled approval paths.
- **The Solution**: SharpLogic's compiler encodes your actual graph — topology plus edge guard conditions — into a trap-counting CNF. A **trap assignment** is a valuation of the guard conditions under which (a) a reachable, non-terminal node has every outgoing edge disabled (deadlock), or (b) a reachable cycle / strongly connected region has every exit edge disabled (livelock). A retry loop whose exit guard is the exact logical complement of its loop guard (the bounded-retry pattern) is reported as *guarded*, not as a trap. Terminal nodes are absorbing. The engine's exact count #F is the number of trap assignments — computed from your graph, never hard-coded.

```
   [User Goal] ──► [Planner Agent] ──► [Tool Executor]
                                             ▲   │
                                             │   ▼
                                       [Critic / Retry] 🚨 trap states counted exactly (#F)
                                             │
                                             ▼
                                    [Approval Gate]
```

**Auto-patch**: when #F > 0, the sandbox can synthesize real blocking clauses from the solver's own counterexample assignments (each clause is the negation of a trap assignment, greedily generalized literal-by-literal while the count strictly drops), re-counting #F exactly after every round until it reaches 0 or the round budget (64) ends.

**Benchmark scenarios**: the four flagship demos (#F = 63 / 42 / 192 / 1920) use *hand-authored benchmark CNF formulas* to exercise the counting engine across enterprise payments, fintech promo stacks, agent routing deadlocks, and cloud IAM blast radiuses. Their counts are real, brute-force-verifiable model counts of those formulas — they are **not** compiled from a user graph. User graphs always go through the trap compiler above.

---

## 🏛️ Enterprise Scenario: AP 3-Way Match Exception Clearance Gate

Enterprise deployments face a universal blocker: **"Something downstream becomes hard to reverse (paying wrong accounts, signing deviating contracts, failing compliance audits), any probability-driven LLM will be stopped at the gate."**

SharpLogic provides the deterministic symbolic clearance gate for non-standard enterprise payments:

```
[Vendor PDF Invoice / Email]  ──► [LLM Fact Tuple Extractor]
                                          │
                                          ▼  (Formal Tuples: PO #, Qty, Billed Price, Vendor TIN)
                                 [SharpLogic Symbolic Gate]
                                          │  • Cross-checks Purchase Order contracted baseline (+5% cap)
                                          │  • Verifies Goods Received Note (GRN) & QA Inspection
                                          │  • Validates Vendor Entity & Remittance Bank in ERP Master Table
                                          ▼
                      ┌───────────────────────────────────────┐
                      │  #F = 0 (UNSAT Core Verified)        │
                      │  ──► Generates SHA-256 Audit Seal    │
                      │  ──► Releases Treasury Wire Batch     │
                      └───────────────────────────────────────┘
                                          │  (If Variance > 5% without Director Signature)
                                          ▼
                      [#F = 63 Loophole States Detected] ──► HARD AUTOMATED HOLD
```

- **LLM Responsibility**: Extracts unstructured facts from invoices, packing slips, and email chains into structured fact tuples.
- **SharpLogic SMT Responsibility**: Enforces deterministic mathematical invariants with zero hallucination. If unit price discrepancy exceeds the +5% tolerance without a signed Procurement Director override or vendor credit memo, disbursement is physically blocked.

---

## 💼 Open-Core Model: Community vs. Enterprise Sentinel

To protect commercial viability while empowering developers, SharpLogic operates on an **Open-Core** architecture:

| Feature / Capability | Community Core (GitHub MIT) | Enterprise Sentinel (SaaS / Private) |
|---|---|---|
| **Native Rust `#k-SAT` / WMC Solver** | ✅ Full Local Offline Engine | ✅ High-Throughput Serverless Cloud |
| **Agent Graph Trap Compiler** | ✅ CLI & Python Library | ✅ Automated CI/CD Webhook Gate |
| **MPE Counterexample Witnessing** | ✅ Standalone Script | ✅ Visual Interactive Remediation Console |
| **AP 3-Way Match Exception Gate** | ⚠️ Hand-Authored Benchmark | ✅ Live SAP S/4HANA & NetSuite Connectors |
| **Audit Log Storage** | 128-Slot In-Memory Manifold | Multi-Tenant Postgres Encrypted Vault |
| **Compliance Proof Signatures** | Plaintext Witness Trace | Cryptographically Signed SOC 2 / ISO 27001 Proof |
| **Licensing** | Open Source (MIT) | Commercial B2B Subscription |

---

## 🚀 Quick Start (1-Line Standalone Agent Verifier)

Verify your agent workflow locally with zero cloud API keys and zero data leaving your machine:

```bash
# 1. Audit your own LangGraph/Agent JSON workflow export:
curl -fsSL https://sharplogic.vercel.app/install.py | python3 - --graph my_agent.json

# 2. Or run the built-in demo (a deliberately flawed support workflow,
#    then the same workflow with the traps removed and re-audited):
curl -fsSL https://sharplogic.vercel.app/install.py | python3 -
```

The standalone checker enumerates condition assignments exactly and supports
graphs with up to **16 distinct condition atoms**; larger graphs are rejected
with an explicit error and should be audited through the full package (the CNF
engine), which accepts encodings up to **MAX_VARS = 64 variables** and raises
a clear error beyond that — formulas are never silently truncated.

### Python SDK Integration (Pre-Deployment Guardrail Gate)

```python
import requests

# Run verification in your CI pipeline or pre-commit hook
resp = requests.post(
    "https://sharplogic.vercel.app/api/audit",
    json={"scenario_id": "agent_workflow", "patched": False}
).json()

assert resp["audit"]["exact_count"] == 0, (
    f"Blocked release! #F={resp['audit']['exact_count']} trap states detected: "
    f"{resp['ghost_path_summary']['headline']}"
)
```

---

## 🏗️ Architecture

1. **Zero-Dependency Native Rust Core (`src/lib.rs`)**:
   - **Exact `#k-SAT` & Weighted Model Counting (WMC)**:
     $$\#F = \left|\left\{ x \in \{0,1\}^n : F(x) = 1 \right\}\right|, \quad \text{WMC}(F) = \sum_{x \models F} \prod_{i=1}^n w(x_i)$$
   - DPLL with iterative unit propagation, top-level **and dynamic** disjoint component decomposition ($\#F(C_1 \land C_2) = \#F(C_1) \times \#F(C_2)$), subproblem memoization, safe preprocessing (literal dedupe, tautology/duplicate removal, subsumption), and the MOMS branching heuristic.
   - **MPE Ghost Path Extraction**: the highest-probability counterexample assignment, used as the auto-patch witness.
   - **$O(K)$ Bounded Manifold (128 slots)**: bounded alert/event store with `b"SLGC"` snapshot persistence.
   - Hard limit **MAX_VARS = 64**: oversized formulas and out-of-range literals return loud errors (FFI codes −2/−3), never truncated results.

2. **Graph Trap Compiler (`python/sharplogic/compiler.py`)**:
   - Parses LangGraph/Dify-style JSON (nodes, edges, guard conditions with `and`/`or`/`not` and comparisons; complementary comparisons are canonicalized, so `retry_count >= 3` is recognized as the negation of `retry_count < 3`).
   - Emits a CNF in exact 1-to-1 correspondence with trap assignments (functionally-determined reachability/support/witness variables), plus a structural layer (Tarjan SCCs, dead ends, unreachable nodes, guarded cycles).
   - Cross-validated against an independent brute-force implementation of the semantics on 200 random graphs (0 mismatches).

3. **Serverless Kernel Parity (`python/sharplogic/bridge.py`)**:
   - A pure-Python port mirrors the Rust kernel; a test enforces bit-exact parity (counts, WMC, scores, ghost assignments) between the two engines.

### Measured performance (medians, this repo's dev sandbox)

| Workload | Median solve time |
|---|---|
| Flagship benchmark formulas (20–24 vars) | 3.7–6.4 µs |
| Sample agent graph, trap-compiled (18 vars) | 33 µs |
| Router graphs, 10–15 guard atoms | 5–8 µs |
| Diamond pipeline, trap-compiled (50 vars) | 286 µs |
| Retry pipeline, trap-compiled (44 vars) | 261 µs |
| Dense random 3-SAT, 40 vars (r = 2.0) | 31 ms |
| Dense random 3-SAT, 50 vars (r = 2.0) | 0.46 s |
| Dense random 3-SAT, 64 vars (r = 2.0) | 6.7 s |

Exact counting is exponential in the worst case: sparse, structured workflow
formulas land in the microsecond range, dense random formulas hit the
exponential wall — the table reports both, as measured. (The 64-variable
dense case is ≈3× faster than the pre-optimization engine's 19.9 s on the
same machine and seeds.)

---

## 🧪 Local Build & Test

```bash
# 1. Run Rust test suite (3/3 passing)
cargo test

# 2. Run Python test suites (18/18 passing: 8 end-to-end + 10 graph-audit/limits)
python3 -m unittest discover -s tests -v

# 3. Start local development server on port 8765
python3 server.py
```

---

## 🔑 VIP Access & Live Demo

- **Production URL**: [https://sharplogic.vercel.app](https://sharplogic.vercel.app)
- **VIP Launch Invite Code**: `ETH-2026` (Pre-activated at `https://sharplogic.vercel.app/?code=ETH-2026`)
- Referral tiers: Tier 1 (offline engine + AgentGuard) and Tier 2 (auto-patch, live in the sandbox/API) are shipped. Tier 3 (GitHub Actions PR bot) and Tier 4 (Sentinel Hall of Fame) are **roadmap/waitlist** — unlocking them records a waitlist spot; they are not yet available.
