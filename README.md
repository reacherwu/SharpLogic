# SharpLogic (`#F`) — Neuro-Symbolic `#k-SAT` & WMC Audit Engine

> **"Don't Guess with Prompts. Prove It with Math."**  
> System 2 Mathematical Firewall for Enterprise Business Rules, AI Agent Workflows (LangGraph / Dify), and Cloud IAM Policies.

---

## Core Architecture

1. **Zero-Dependency Native Rust Core (`src/lib.rs` -> `libsharplogic_core.dylib`)**:
   - **Exact `#k-SAT` Model Counting (`#F`) & Weighted Model Counting (`WMC`)**:
     $$\#F = \left|\left\{ x \in \{0,1\}^n : F(x) = 1 \right\}\right|, \quad \text{WMC}(F) = \sum_{x \models F} \prod_{i=1}^n w(x_i)$$
   - Uses **Iterative Unit Propagation**, **Disjoint Connected-Component Decomposition** ($\#F(C_1 \land C_2) = \#F(C_1) \times \#F(C_2)$), and **MOMS DPLL** to exhaust $2^{24}$ ($16,777,216$) state spaces in **$< 100\ \mu\text{s}$**.
   - **MPE Ghost Path™ Extraction**: Automatically isolates the highest-prior-probability satisfying counterexample assignment and conflict clause (`UNSAT Core`).
   - **Physical $O(K)$ Bounded Two-Tier Audit Manifold (`K = 128` slots)**:
     - Hot working memory (`K_HOT = 32`) + Cold diversity memory (`K_COLD = 96`) with **Subspace Diversity Deduplication** ($\text{argmax}_i \max_{j \neq i} \cos(e_i, e_j) \ge \theta_{\text{sim}}$).
     - **Retrospective Causal Revision with Temporal Decay Exemption** ($\text{TempCompat} = 1.0$ when $\text{Sim} \ge \theta_{\text{exempt}}$) + **Lightweight Dual-Channel Semantic Causal Bridging** ($< 10\ \mu\text{s}$).
     - **Zero-Loss Microsecond Persistence (`b"SLGC"` binary snapshot)**: Save and restore in $< 1\ \text{ms}$ with 100% bit-exact recovery.

2. **Neuro-Symbolic Autoformalizer & Multi-Persona SaaS Workbench (`python/sharplogic/` & `web/index.html`)**:
   - **Entry 01**: E-Commerce Stacked Promo & Refund Radar (`24 Vars • 16.77M States • #F = 42 Loopholes -> 0`).
   - **Entry 02**: AI Agent Workflow Static Actuary (`20 Vars • 1.04M States • #F = 192 Deadlocks -> 0`).
   - **Entry 03**: Cloud IAM & K8s Blast Radius Quantifier (`22 Vars • 4.19M States • 120x Exposure -> 0`).
   - **Live Custom Rule Sandbox**: Real-time natural-language & symbolic rule compilation to $k$-CNF + DIMACS.

---

## Quick Start (1-Command Local Launch)

```bash
# 1. Build Native Rust Engine (0 external dependencies)
cargo build --release

# 2. Start the SharpLogic Interactive Sandbox Server
python3 server.py
```

Then open **`http://127.0.0.1:8765`** in your browser.

---

## Verification & Benchmarks

```bash
# Run Native Rust Unit & Persistence Tests
cargo test

# Run End-to-End Python + C-ABI + HTTP API & Adversarial Red-Team Tests
python3 -m unittest discover -s tests -v
```
