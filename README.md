<div align="center">

# SharpLogic (♯∧)

### The Deterministic Invariant & Payment Clearance Gate for AI Agents

**Never let probabilistic LLMs approve irreversible downstream actions.**  
Bring zero-hallucination mathematical verification to financial disbursements, contractual caps, and cloud permissions.

[![Live Demo](https://img.shields.io/badge/Live%20Console-sharplogic.vercel.app-00dc82?style=for-the-badge&logo=vercel&logoColor=black)](https://sharplogic.vercel.app/?code=ETH-2026)
[![License: MIT](https://img.shields.io/badge/License-MIT-0969da?style=for-the-badge)](LICENSE)
[![Zero-Cloud-API](https://img.shields.io/badge/Zero--Cloud--API-100%25%20Offline-1a7f37?style=for-the-badge)](https://sharplogic.vercel.app)
[![Rust Core](https://img.shields.io/badge/Rust-Zero--Dependency-DEA584?style=for-the-badge&logo=rust&logoColor=black)](src/lib.rs)
[![Tests Passing](https://img.shields.io/badge/Tests-28%2F28%20Passing-success?style=for-the-badge)](tests/)

<br />

<img src="public/media/sharplogic_demo.gif" alt="SharpLogic Enterprise Clearance Gate Demo" width="920" style="border-radius: 8px; border: 2px solid #30363d; box-shadow: 0 8px 24px rgba(0,0,0,0.5);" />

</div>

---

> [!IMPORTANT]
> **"Something downstream becomes hard to reverse — any probabilistic model gets blocked."**  
> Enterprises love AI demos, but CFOs and Legal Counsel will never grant probabilistic LLMs unconstrained authority to disburse funds, execute settlements, or relax security policies.  
> **SharpLogic bridges this chasm:** LLMs extract unstructured reality into formal tuples, while SharpLogic's native Rust SMT/`#k-SAT` engine enforces deterministic mathematical invariants in microseconds. If `#F > 0`, execution is physically blocked.

---

## ⚡ The Dual-Engine Architecture

Instead of trusting a 99.2% prompt evaluation to execute financial transactions, SharpLogic separates extraction from invariant verification:

```
[Unstructured Real World: Messy Invoices, Vendor Emails, Slack Chats]
                               │
                               ▼
        Layer 01: Probabilistic LLM Fact Extractor
        Extracts formal tuples: (PO #, Invoiced Qty, Unit Price, Vendor TIN)
                               │
                               ▼
     Layer 02: SharpLogic SMT Symbolic Clearance Gate (Rust Native)
        Evaluates 22+ boolean/linear invariants in < 10 µs:
        • Unit Price Discrepancy > 5% without Procurement Director physical signature?
        • Remittance bank routing matches ERP Master Profile?
        • OFAC/AML sanctions screening and 90-day duplicate hash cleared?
                               │
           ┌───────────────────┴───────────────────┐
           ▼                                       ▼
  [ #F = 63 Loophole Paths ]              [ #F = 0 (UNSAT Core) ]
  🚨 PHYSICAL DISBURSEMENT BLOCK          ✓ CRYPTOGRAPHIC SHA-256 SEAL
  • Halts unapproved wire batch           • Generates tamper-proof audit proof
  • Alerts human director queue           • Releases ERP / Treasury ACH batch
```

---

## 🏛️ Mission-Critical Enterprise Playbooks

| Playbook | The Downstream Catastrophe | SharpLogic SMT Invariant Gate | Commercial Value |
|---|---|---|---|
| **AP 3-Way Match Clearance** *(Live in Demo)* | 15%~25% non-standard invoices (price drift, unapproved freight). LLM hallucinates discount from supplier email, triggering irreversible $100k+ wire payouts. | Hard-gates +5% variance threshold. Enforces PO baseline, warehouse GRN, and director counter-signature. | **$1,000 ~ $3,500/mo** per AP Department |
| **Contract Fallback Matrix Review** | Sales needs to close, Legal has 2-week backlog. Generic AI flags "seems similar", but an ambiguous *"may"* vs *"shall"* triggers millions in uncapped liability. | Evaluates terms against corporate Fallback Matrix state machine. Auto-greenlights compliant clauses; blocks deviations. | **$20k ~ $40k/yr** in Legal Budget Saved |
| **SOC 2 / ISO 27001 Access Snaps** | Big 4 auditors reject black-box LLM summaries; they require unforgeable, timestamped mathematical proof of PR approvals and IAM boundaries. | Verifies access graphs before merge. Generates SHA-256 state snapshots and physical CI deployment blocks. | **Non-Negotiable** Compliance Gate |

---

## 💼 Open-Core Model: Community vs. Enterprise Sentinel

| Capability | Community Edition (GitHub MIT) | Enterprise Sentinel (Commercial SaaS / VPC) |
|---|---|---|
| **Rust `#k-SAT` / WMC Core** | ✅ Full Local Offline Engine | ✅ High-Throughput Serverless Fleet |
| **Workflow Trap Compiler** | ✅ CLI & Python Library | ✅ GitHub PR Automated Gate Bot |
| **AP 3-Way Match Gate** | ⚠️ Hand-Authored Benchmark | ✅ Live SAP S/4HANA & NetSuite Webhooks |
| **In-Agent Guardrail** | ✅ `AgentGuard` Runtime Hook | ✅ Multi-Agent Fleet Telemetry |
| **Audit Persistence** | 128-Slot In-Memory Ring Buffer | Multi-Tenant Postgres Encrypted Vault |
| **Compliance Signatures** | Plaintext Witness Trace | Cryptographic SHA-256 SOC 2 / Big 4 Proofs |
| **Licensing** | Open Source (MIT) | Commercial Enterprise License |

---

## 🚀 Quick Start

### 1. In-Agent Runtime Middleware (`AgentGuard`)

Install the local package and guard your multi-agent workflow with zero cloud dependencies:

```python
from sharplogic import AgentGuard

WORKFLOW = {
    "nodes": ["Tool_Executor", "Critic_Fallback", "Human_Approval_Gate"],
    "terminals": ["Human_Approval_Gate"],
    "edges": [
        {"from": "Tool_Executor", "to": "Critic_Fallback", "condition": "tool_timeout or execution_error"},
        {"from": "Critic_Fallback", "to": "Tool_Executor", "condition": "retry_prompt_generated and retry_count <= 3"},
        {"from": "Critic_Fallback", "to": "Human_Approval_Gate", "condition": "not retry_prompt_generated or retry_count > 3"},
    ],
}

guard = AgentGuard(graph=WORKFLOW)

# Audit graph: returns exact trap-state assignments (#F)
report = guard.audit()
assert report["exact_count"] == 0, f"Detected {report['exact_count']} deadlock states!"

# Runtime assert on edge transition before calling downstream tools
guard.assert_safe("Critic_Fallback", "Tool_Executor", state={"retry_prompt_generated": True}, retry_count=2)
```

### 2. LangGraph One-Line Adapter

```python
from sharplogic.langgraph_adapter import from_langgraph
from sharplogic import AgentGuard

# Convert existing LangGraph topology to SharpLogic formal specification
graph = from_langgraph(nodes=my_nodes, edges=my_edges, terminals=["END"])
guard = AgentGuard(graph=graph)
report = guard.audit()
```

### 3. One-Line Offline CLI Verifier

```bash
# Verify your agent JSON export locally (100% offline, zero data leaves machine):
curl -fsSL https://sharplogic.vercel.app/install.py | python3 - --graph my_agent.json
```

---

## 🔬 Benchmark Scenarios & Measured Performance

All counts are exact, brute-force-verifiable mathematical model counts evaluated dynamically by the native Rust solver:

| Workload | Variables | State Space | Trap States (#F) | Solve Time |
|---|---|---|---|---|
| **AP 3-Way Match Exception Gate** | 22 | 4,194,304 | **63** (Patched $\rightarrow$ **0**) | 4.8 µs |
| **E-Commerce Promo Stacking** | 24 | 16,777,216 | **42** (Patched $\rightarrow$ **0**) | 6.2 µs |
| **LangGraph Deadlock Routing** | 20 | 1,048,576 | **192** (Patched $\rightarrow$ **0**) | 3.7 µs |
| **AWS IAM / K8s Blast Radius** | 22 | 4,194,304 | **1,920** (120x expansion) | 5.1 µs |

---

## 🧪 Build & Test Verification

SharpLogic enforces a strict dual-track testing regime across Rust and Python boundaries:

```bash
# 1. Run Rust test suite (3/3 passing)
cargo test

# 2. Run Python test suite (28/28 passing: unit, integration & property tests)
python3 -m unittest discover -s tests -v

# 3. Start local development server
python3 server.py
```

---

## 🔑 VIP Access & Early Adopter Program

- **Live Production Platform**: [https://sharplogic.vercel.app](https://sharplogic.vercel.app)
- **VIP Launch Invite Code**: `ETH-2026` (Pre-activated at `https://sharplogic.vercel.app/?code=ETH-2026`)
- Claim your Sentinel token to unlock auto-patching and live sandbox formal verification.

<div align="center">
  <sub>Built with mathematical rigor for the next generation of mission-critical AI agents.</sub>
</div>
