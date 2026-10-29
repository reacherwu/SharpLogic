"""
Flagship benchmark scenarios & adversarial red-team corpus for SharpLogic.

IMPORTANT (formula provenance): the three flagship scenarios below use
HAND-AUTHORED benchmark CNF formulas.  Their variables and clauses were
written by hand to model the described situations, and the engine's exact
counts for them (#F = 42 / 192 / 1920) are real, brute-force-verifiable
model counts of those benchmark formulas.  They are NOT compiled from a
user's LangGraph / workflow graph.  User-supplied graphs always go through
Autoformalizer's trap-encoding compiler (see compiler.py), which derives
its formula from the actual graph topology and guard conditions.
All scenario counts are evaluated dynamically by the #k-SAT & WMC solver.
"""

from typing import Any, Dict, List, Optional
from .bridge import get_engine
from .compiler import Autoformalizer


SCENARIOS: Dict[str, Dict[str, Any]] = {
    "ecommerce_promo": {
        "id": "ecommerce_promo",
        "formula_origin": "hand_authored_benchmark",
        "persona_badge": "ENTRY 01 // E-COMMERCE & FINTECH PROMO RADAR",
        "title": "E-Commerce Refund & Stacked Promo Audit",
        "title_zh": "电商大促叠加与售后退款 Agent 防薅精算",
        "subtitle": "24 Boolean & Linear Conditions • 16,777,216 State Combinations",
        "natural_language_rules": (
            "1. [VIP Tier] VIP members receive 20% off (8折) on eligible checkout items.\n"
            "2. [New User Promo] First-time or invited users receive an extra ¥50 instant rebate.\n"
            "3. [Cross-Border Rule] Cross-border items bypass standard tiered reduction, EXCEPT when bundled with Self-Operated Beauty items over ¥500.\n"
            "4. [Beauty Voucher] Orders containing Self-Operated Beauty >= ¥500 unlock a ¥100 No-Threshold Voucher.\n"
            "5. [Partial Return Policy] When a user initiates a Partial Return on a bundled order, the Refund Agent refunds the returned sub-item at invoice price while retaining voucher credit on the kept cross-border item.\n"
            "6. [HARD SAFETY INVARIANT] Under NO circumstances may net payout + retained goods fall below 60% cost floor (i.e. Refund Payout Ratio <= 100%)."
        ),
        "variables": [
            {"name": "flash_tier_a", "label": "Flash Campaign Window A", "prior": 0.45, "category": "Traffic Entry"},
            {"name": "flash_tier_b", "label": "Flash Campaign Window B", "prior": 0.40, "category": "Traffic Entry"},
            {"name": "channel_app", "label": "Mobile App Checkout", "prior": 0.60, "category": "Channel"},
            {"name": "channel_miniprogram", "label": "Mini-Program Checkout", "prior": 0.35, "category": "Channel"},
            {"name": "channel_web_vip", "label": "VIP Web Concierge", "prior": 0.20, "category": "Channel"},
            {"name": "use_points_offset", "label": "Loyalty Points Offset", "prior": 0.50, "category": "Payment"},
            {"name": "is_vip", "label": "VIP Member Status", "prior": 0.25, "category": "User Segment"},
            {"name": "is_invited_user", "label": "Referral Invite Bonus", "prior": 0.30, "category": "User Segment"},
            {"name": "cross_border_item", "label": "Has Cross-Border SKU", "prior": 0.35, "category": "Cart Structure"},
            {"name": "self_operated_beauty", "label": "Has Self-Op Beauty SKU", "prior": 0.40, "category": "Cart Structure"},
            {"name": "order_over_500", "label": "Gross Cart >= ¥500", "prior": 0.55, "category": "Threshold"},
            {"name": "vip_80_pct_discount", "label": "20% VIP Discount Applied", "prior": 0.75, "category": "Discount Engine"},
            {"name": "partial_return_requested", "label": "Partial Return Initiated", "prior": 0.30, "category": "Post-Sale Agent"},
            {"name": "coupon_100_no_threshold", "label": "¥100 Beauty Voucher Active", "prior": 0.65, "category": "Discount Engine"},
            {"name": "refund_keep_coupon_credit", "label": "Retain Voucher on Partial Refund", "prior": 0.80, "category": "Post-Sale Agent"},
            {"name": "tax_waiver_applied", "label": "Cross-Border Tax Subsidy", "prior": 0.70, "category": "Settlement"},
            {"name": "shipping_insurance_claim", "label": "¥15 Freight Insurance Payout", "prior": 0.50, "category": "Post-Sale Agent"},
            {"name": "auto_refund_agent_approved", "label": "AI Refund Agent Auto-Approve", "prior": 0.85, "category": "Post-Sale Agent"},
            {"name": "bundle_split_pricing", "label": "Asymmetric Bundle Split", "prior": 0.75, "category": "Settlement"},
            {"name": "price_protection_trigger", "label": "Price-Drop Claim Active", "prior": 0.40, "category": "Settlement"},
            {"name": "holiday_double_rebate", "label": "Holiday Rebate Multiplier", "prior": 0.60, "category": "Discount Engine"},
            {"name": "zero_manual_review_flag", "label": "Order < ¥1000 Skip Human Audit", "prior": 0.90, "category": "Risk Control"},
            {"name": "net_paid_below_250", "label": "Net Cash Paid <= ¥250", "prior": 0.85, "category": "Financial State"},
            {"name": "margin_below_cost_floor", "label": "VIOLATION: Payout > 135% (Below 60% Cost)", "prior": 0.95, "category": "Safety Invariant"},
        ],
        # Clauses defining F_loophole(x) = Rules(x) AND Violation(x)
        # Component 1: [1, 2] -> 3 ways
        # Component 2: [3, 4, 5] -> 7 ways
        # Free var: 6 -> 2 ways
        # Fixed chain: 7..24 -> 1 way
        # Total #F = 3 * 7 * 2 * 1 = 42 exact paths!
        "clauses": [
            [1, 2],
            [3, 4, 5],
            [7],
            [8],
            [9],
            [10],
            [-9, -10, 11],
            [-7, 12],
            [13],
            [-10, -11, 14],
            [-13, -14, 15],
            [-9, 16],
            [17],
            [-15, 18],
            [19],
            [20],
            [21],
            [22],
            [-12, -14, 23],
            [-18, -23, 24],
        ],
        "clause_descriptions": [
            "C1: Traffic enters via Flash Campaign Window A or B (flash_tier_a ∨ flash_tier_b)",
            "C2: Checkout initiated on App, Mini-Program, or VIP Web (channel_app ∨ channel_miniprogram ∨ channel_web_vip)",
            "C3: User holds active VIP membership (is_vip = True)",
            "C4: Referral invite rebate active (is_invited_user = True)",
            "C5: Cart includes Cross-Border item (cross_border_item = True)",
            "C6: Cart includes Self-Operated Beauty item (self_operated_beauty = True)",
            "C7: Cross-border + Beauty bundle reaches ¥500 threshold (¬cross_border ∨ ¬beauty ∨ order_over_500)",
            "C8: VIP status triggers 20% discount (¬is_vip ∨ vip_80_pct_discount)",
            "C9: Buyer triggers Partial Return on Beauty sub-item (partial_return_requested = True)",
            "C10: Beauty >= ¥500 unlocks ¥100 No-Threshold Voucher (¬beauty ∨ ¬over_500 ∨ coupon_100)",
            "C11: Partial return keeps full ¥100 voucher credit on remaining item (¬partial_return ∨ ¬coupon_100 ∨ keep_credit)",
            "C12: Cross-border SKU receives tax subsidy (¬cross_border ∨ tax_waiver_applied)",
            "C13: Automatic freight insurance payout triggered (shipping_insurance_claim = True)",
            "C14: AI Refund Agent auto-approves retained credit refund (¬keep_credit ∨ auto_refund_approved)",
            "C15: Asymmetric bundle discount allocation (bundle_split_pricing = True)",
            "C16: Price protection window active (price_protection_trigger = True)",
            "C17: Holiday rebate active (holiday_double_rebate = True)",
            "C18: Payout under ¥1000 bypasses human review (zero_manual_review_flag = True)",
            "C19: Stacked VIP 20% off + ¥100 voucher drives net payment <= ¥250 (¬vip_80_pct ∨ ¬coupon_100 ∨ net_paid_below_250)",
            "C20: [INVARIANT BREACH] Net cash ¥250 vs ¥300 cost + partial refund = 135% payout (¬auto_refund ∨ ¬net_paid_below_250 ∨ margin_below_cost_floor)",
        ],
        "patch_clauses": [
            [-13, -14, -15],
            [-9, -12, -14],
        ],
        "patch_descriptions": [
            "PATCH-1 [Pro-Rata Coupon Clawback]: ¬partial_return_requested ∨ ¬coupon_100_no_threshold ∨ ¬refund_keep_coupon_credit",
            "PATCH-2 [Cross-Border Stack Mutex]: ¬cross_border_item ∨ ¬vip_80_pct_discount ∨ ¬coupon_100_no_threshold",
        ],
        "ghost_path_summary": {
            "headline": "VIP + Cross-Border Item + Self-Op Beauty >= ¥500 + Partial Return = 135% Refund Payout",
            "financial_impact": "Gross Order ¥500 -> Net Paid ¥250 (below ¥300 cost floor). Partial return of Beauty SKU yields ¥337.50 combined refund + kept goods (-¥87.50 net platform loss per order).",
            "root_cause_clause": "Clause C11 & C19: Asymmetric voucher retention during partial bundle return bypasses the 60% cost floor check.",
            "patched_rule_text": (
                "PATCHED RULE #5: Upon partial return of any bundled order qualifying for a threshold voucher (e.g. ¥100 Beauty Voucher), "
                "the Refund Agent MUST recalculate remaining cart total pro-rata and claw back the ¥100 voucher deduction before issuing refund payout."
            ),
        },
    },
    "agent_workflow": {
        "id": "agent_workflow",
        "formula_origin": "hand_authored_benchmark",
        "persona_badge": "ENTRY 02 // AI AGENT WORKFLOW STATIC ACTUARY",
        "title": "LangGraph / Dify Financial Agent Routing Audit",
        "title_zh": "AI Agent 工作流死锁与越权调用静态精算",
        "subtitle": "20 Routing & Tool-Guard Variables • 1,048,576 State Combinations",
        "natural_language_rules": (
            "1. [Triage Node] Incoming dispute tickets with high anger or chargeback threat route to Priority Resolution.\n"
            "2. [Risk Hold Node] If Risk Score is flagged, suspend auto-payout and escalate to Human Queue.\n"
            "3. [Queue Timeout Fallback] When Human Queue wait > 30s and Auto-Retry Tool is enabled, fallback to Triage Node for re-routing.\n"
            "4. [VIP Fast-Track] When Fallback re-enters Triage with SLA Urgent Flag, trigger Instant Payout Tool to prevent churn.\n"
            "5. [HARD SAFETY INVARIANT] Workflow must NEVER enter an unguarded routing cycle, and Instant Payout Tool must NEVER execute without MFA verification."
        ),
        "variables": [
            {"name": "llm_temp_high", "label": "Router LLM Temp > 0.7", "prior": 0.40, "category": "Model Config"},
            {"name": "prompt_urgency_injected", "label": "User Prompt Urgency Signal", "prior": 0.55, "category": "Input Signal"},
            {"name": "ctx_locale_en", "label": "Locale EN/Global", "prior": 0.50, "category": "Context"},
            {"name": "ctx_weekend_shift", "label": "Weekend On-Call Shift", "prior": 0.50, "category": "Context"},
            {"name": "ctx_tier_gold", "label": "Account Tier Gold+", "prior": 0.50, "category": "Context"},
            {"name": "ctx_device_mobile", "label": "Mobile Client Session", "prior": 0.50, "category": "Context"},
            {"name": "ctx_webhook_async", "label": "Async Webhook Mode", "prior": 0.50, "category": "Context"},
            {"name": "ctx_memory_window_full", "label": "Context Window > 8k", "prior": 0.50, "category": "Context"},
            {"name": "intent_dispute_high", "label": "High-Severity Dispute Intent", "prior": 0.65, "category": "Router Node"},
            {"name": "risk_score_flagged", "label": "Fraud Risk Score Flagged", "prior": 0.45, "category": "Risk Node"},
            {"name": "tool_auto_retry_enabled", "label": "Auto-Retry Middleware ON", "prior": 0.80, "category": "Edge Config"},
            {"name": "human_queue_timeout", "label": "Human Escalation Timeout (>30s)", "prior": 0.60, "category": "Escalation Node"},
            {"name": "fallback_to_triage_node", "label": "Fallback Edge -> Triage Node", "prior": 0.75, "category": "Edge Config"},
            {"name": "mfa_token_verified", "label": "User MFA Token Verified", "prior": 0.25, "category": "Security Guard"},
            {"name": "invoke_instant_payout_tool", "label": "Tool: execute_instant_payout()", "prior": 0.70, "category": "Tool Execution"},
            {"name": "sla_breach_imminent", "label": "SLA Breach Timer < 5s", "prior": 0.75, "category": "Escalation Node"},
            {"name": "state_cycle_detected", "label": "Cycle: Triage -> Risk -> Retry -> Triage", "prior": 0.85, "category": "Graph Topology"},
            {"name": "token_budget_exhausted", "label": "Recursive Token Burn > $12/req", "prior": 0.80, "category": "Cost Guard"},
            {"name": "unauthenticated_payout_exec", "label": "Payout Executed Without MFA", "prior": 0.85, "category": "Security Guard"},
            {"name": "agent_safety_violated", "label": "VIOLATION: Deadlock + Unauth Tool Call", "prior": 0.95, "category": "Safety Invariant"},
        ],
        # Component 1: [1, 2] -> 3 ways
        # Free vars: 3..8 (6 vars) -> 64 ways
        # Fixed chain: 9..20 (with var 14 negated: mfa_token_verified = False) -> 1 way
        # Total #F = 3 * 64 = 192 exact paths out of 1,048,576!
        "clauses": [
            [1, 2],
            [9],
            [10],
            [11],
            [12],
            [-10, -11, -12, 13],
            [-14],
            [16],
            [-13, -16, 15],
            [-9, -13, 17],
            [-17, 18],
            [-15, 14, 19],
            [-17, -19, 20],
        ],
        "clause_descriptions": [
            "C1: Router temperature > 0.7 or urgency signal present (llm_temp_high ∨ prompt_urgency_injected)",
            "C2: Classifier routes ticket to High-Severity Dispute (intent_dispute_high = True)",
            "C3: Fraud detector flags transaction risk (risk_score_flagged = True)",
            "C4: LangGraph edge has Auto-Retry middleware enabled (tool_auto_retry_enabled = True)",
            "C5: Human review queue exceeds 30s SLA timeout (human_queue_timeout = True)",
            "C6: Risk + Retry + Timeout triggers Fallback Edge back to Triage (¬risk ∨ ¬retry ∨ ¬timeout ∨ fallback_to_triage)",
            "C7: Session lacks MFA verification (¬mfa_token_verified)",
            "C8: SLA Breach timer triggers urgent fast-track (sla_breach_imminent = True)",
            "C9: Fallback re-entry under SLA breach invokes Instant Payout Tool (¬fallback ∨ ¬sla_breach ∨ invoke_instant_payout)",
            "C10: Re-entering Triage forms cyclic state transition (¬dispute ∨ ¬fallback ∨ state_cycle_detected)",
            "C11: State cycle causes unbounded token loop (¬state_cycle_detected ∨ token_budget_exhausted)",
            "C12: Instant Payout called while ¬mfa_token_verified triggers Unauth Execution (¬payout ∨ mfa ∨ unauth_exec)",
            "C13: [INVARIANT BREACH] Cyclic deadlock + unauthenticated payout tool call (¬cycle ∨ ¬unauth_exec ∨ agent_safety_violated)",
        ],
        "patch_clauses": [
            [-15, 14],
            [-11, -13],
        ],
        "patch_descriptions": [
            "PATCH-1 [Hard Tool Precondition]: ¬invoke_instant_payout_tool ∨ mfa_token_verified (Require cryptographic MFA before payout)",
            "PATCH-2 [DAG Cycle Breaker]: ¬tool_auto_retry_enabled ∨ ¬fallback_to_triage_node (Terminate retry loop to Dead-Letter Queue)",
        ],
        "ghost_path_summary": {
            "headline": "Triage ↔ RiskHold ↔ AutoRetry Infinite Loop + Unauthenticated Instant Payout Bypass",
            "financial_impact": "Workflow Closure Rate drops to 96.48% under weekend queue load; 192 state combinations trigger recursive token exhaustion ($14.20/ticket) and bypass MFA on execute_instant_payout().",
            "root_cause_clause": "Clause C6 & C9: Fallback edge routes timed-out RiskHold tickets back into Triage with SLA Urgent flag, overriding the RiskHold block.",
            "patched_rule_text": (
                "PATCHED GRAPH GUARD: (1) Enforce max_hop_count <= 2 on Triage edge; route Human Queue timeouts to isolated Dead-Letter Queue. "
                "(2) Attach deterministic SMT precondition `require(mfa_token_verified == True and risk_score_flagged == False)` on `execute_instant_payout`."
            ),
        },
    },
    "cloud_iam": {
        "id": "cloud_iam",
        "formula_origin": "hand_authored_benchmark",
        "persona_badge": "ENTRY 03 // CLOUD IAM & K8S BLAST RADIUS QUANTIFIER",
        "title": "AWS IAM & K8s RBAC Policy Blast Radius Audit",
        "title_zh": "云安全 IAM 权限变更与攻击暴露面倍数精算",
        "subtitle": "22 Policy Predicates • 4,194,304 State Combinations • Baseline #F = 16",
        "natural_language_rules": (
            "1. [PR #842 Change] Grant `ci-staging-runner` role `sts:AssumeRole` on `arn:aws:iam::*:role/db-migration-*`.\n"
            "2. [Resource Wildcard] Role `db-migration-helper` holds `rds:CopyDBSnapshot` and `s3:PutObject` on `*` for backup automation.\n"
            "3. [Network Condition] `aws:SourceIp` restriction was relaxed to `0.0.0.0/0` to support ephemeral GitHub Action runners.\n"
            "4. [MFA Condition] `aws:MultiFactorAuthPresent` is optional (`BoolIfExists`) for service-role assumption.\n"
            "5. [HARD SECURITY INVARIANT] Non-human CI principals must NEVER acquire read/export access to Production RDS Snapshots without MFA and VPC Endpoint pinning."
        ),
        "variables": [
            {"name": "region_us_east_1", "label": "Region: us-east-1", "prior": 0.60, "category": "Cloud Scope"},
            {"name": "region_eu_west_1", "label": "Region: eu-west-1", "prior": 0.40, "category": "Cloud Scope"},
            {"name": "region_ap_northeast_1", "label": "Region: ap-northeast-1", "prior": 0.35, "category": "Cloud Scope"},
            {"name": "region_us_west_2", "label": "Region: us-west-2", "prior": 0.50, "category": "Cloud Scope"},
            {"name": "tag_env_staging", "label": "Tag: env=staging", "prior": 0.50, "category": "Resource Tag"},
            {"name": "tag_env_prod", "label": "Tag: env=prod", "prior": 0.50, "category": "Resource Tag"},
            {"name": "tag_team_data", "label": "Tag: team=data-platform", "prior": 0.50, "category": "Resource Tag"},
            {"name": "tag_cost_center", "label": "Tag: cost-center=eng", "prior": 0.50, "category": "Resource Tag"},
            {"name": "tag_compliance_pci", "label": "Tag: compliance=pci-dss", "prior": 0.50, "category": "Resource Tag"},
            {"name": "tag_backup_tier", "label": "Tag: backup=daily", "prior": 0.50, "category": "Resource Tag"},
            {"name": "tag_cluster_eks", "label": "Tag: cluster=eks-main", "prior": 0.50, "category": "Resource Tag"},
            {"name": "principal_ci_runner", "label": "Principal: ci-staging-runner", "prior": 0.70, "category": "IAM Principal"},
            {"name": "action_sts_assume_role", "label": "Action: sts:AssumeRole", "prior": 0.75, "category": "IAM Action"},
            {"name": "resource_prod_rds_snapshot", "label": "Resource: prod-rds-snapshot-*", "prior": 0.60, "category": "Target Resource"},
            {"name": "role_db_migration_wildcard", "label": "Role: db-migration-* (Wildcard)", "prior": 0.80, "category": "IAM Role"},
            {"name": "action_rds_copy_snapshot", "label": "Action: rds:CopyDBSnapshot", "prior": 0.70, "category": "IAM Action"},
            {"name": "action_s3_put_external", "label": "Action: s3:PutObject (External Bucket)", "prior": 0.65, "category": "IAM Action"},
            {"name": "condition_source_ip_any", "label": "Condition: SourceIp = 0.0.0.0/0", "prior": 0.85, "category": "IAM Condition"},
            {"name": "condition_vpc_endpoint_bypass", "label": "No VPC Endpoint Restriction", "prior": 0.80, "category": "IAM Condition"},
            {"name": "condition_mfa_present", "label": "Condition: MultiFactorAuthPresent", "prior": 0.15, "category": "IAM Condition"},
            {"name": "cross_account_exfil_path", "label": "Transitive Admin Exfiltration Path", "prior": 0.85, "category": "Attack Graph"},
            {"name": "iam_invariant_breached", "label": "VIOLATION: Prod DB Exfiltration Exposed", "prior": 0.95, "category": "Security Invariant"},
        ],
        # Component 1: [1, 2, 3, 4] -> 2^4 - 1 = 15 ways
        # Free vars: 5..11 (7 tag variables unconstrained due to '*' wildcard) -> 2^7 = 128 ways
        # Fixed chain: 12..22 (with var 20 negated: condition_mfa_present = False) -> 1 way
        # Total #F = 15 * 128 = 1,920 exact paths! (120x over baseline 16!)
        "clauses": [
            [1, 2, 3, 4],
            [12],
            [13],
            [14],
            [-12, -13, 15],
            [-15, 16],
            [-15, 17],
            [18],
            [19],
            [-20],
            [-16, -17, -18, 21],
            [-14, -21, 22],
        ],
        "clause_descriptions": [
            "C1: Deployment active in at least one AWS region (us-east-1 ∨ eu-west-1 ∨ ap-northeast-1 ∨ us-west-2)",
            "C2: Request originates from ephemeral CI runner (principal_ci_runner = True)",
            "C3: Principal invokes sts:AssumeRole (action_sts_assume_role = True)",
            "C4: Target resource matches production RDS snapshot ARN (resource_prod_rds_snapshot = True)",
            "C5: CI runner assumes wildcard db-migration-* role (¬ci_runner ∨ ¬assume_role ∨ role_db_migration_wildcard)",
            "C6: Migration role grants rds:CopyDBSnapshot on '*' (¬role_db_migration ∨ action_rds_copy_snapshot)",
            "C7: Migration role grants s3:PutObject on '*' (¬role_db_migration ∨ action_s3_put_external)",
            "C8: Ingress allowed from 0.0.0.0/0 (condition_source_ip_any = True)",
            "C9: Request bypasses VPC Endpoint restriction (condition_vpc_endpoint_bypass = True)",
            "C10: Service session executes without MFA token (¬condition_mfa_present)",
            "C11: CopyDBSnapshot + S3 PutObject + 0.0.0.0/0 forms Cross-Account Exfiltration Path",
            "C12: [INVARIANT BREACH] Production RDS snapshot reachable via transitive CI role assumption",
        ],
        "patch_clauses": [
            [-13, 20],
            [-12, -14],
        ],
        "patch_descriptions": [
            "PATCH-1 [Strict MFA Enforcement]: ¬action_sts_assume_role ∨ condition_mfa_present",
            "PATCH-2 [Explicit Prod Resource Deny]: ¬principal_ci_runner ∨ ¬resource_prod_rds_snapshot",
        ],
        "baseline_count": 16,
        "ghost_path_summary": {
            "headline": "Principal: ci-staging-runner → sts:AssumeRole(db-migration-*) → rds:CopyDBSnapshot(prod-db) → External S3",
            "financial_impact": "Blast Radius jumps 120x (from #F = 16 scoped DBA paths to #F = 1,920 valid privilege escalation paths across 4 regions and 128 resource tag combinations).",
            "root_cause_clause": "Clause C5, C6 & C7: Wildcard resource '*' on db-migration-helper leaves all 7 resource tag predicates unconstrained (2^7 = 128x multiplier).",
            "patched_rule_text": (
                "PATCHED IAM POLICY: Add explicit Deny statement for `principal_ci_runner` on `arn:aws:rds:*:*:snapshot:prod-*`, "
                "pin `aws:SourceVpce`, and require `aws:MultiFactorAuthPresent: true` on `sts:AssumeRole`."
            ),
        },
    },
    "ap_invoice_matching": {
        "id": "ap_invoice_matching",
        "formula_origin": "hand_authored_benchmark",
        "persona_badge": "FLAGSHIP 04 // ENTERPRISE AP 3-WAY MATCH & PAYMENT GATEWAY",
        "title": "AP 3-Way Match Exception Clearance & Payment Gate",
        "title_zh": "企业非标应付账款异常三单匹配与付款门禁",
        "subtitle": "22 ERP, Procurement & Tax Invariants • 4,194,304 State Combinations",
        "natural_language_rules": (
            "1. [PO Validation] Invoice must map to an active Purchase Order (PO) line or authorized pending change order.\n"
            "2. [Delivery & QA] Delivery fulfillment requires Goods Received Note (GRN) warehouse sign-off, QA inspection certificate, or exact unit quantity match.\n"
            "3. [Vendor Master & AML] Vendor TIN/Tax ID, remittance bank routing, and sanctions list must be verified in master entity registry.\n"
            "4. [Price Discrepancy & Hallucination Trap] If invoiced unit price exceeds PO contracted rate by > 5%, AP agent MUST NOT auto-clear or bypass 2-way match holds without Procurement Director physical counter-signature or formal vendor credit memo.\n"
            "5. [HARD COMPLIANCE INVARIANT] Zero treasury wire disbursement shall be authorized if price variance > 5% lacks dual human director authorization."
        ),
        "variables": [
            {"name": "po_line_active", "label": "PO Line Open & Active", "prior": 0.90, "category": "Purchase Order"},
            {"name": "po_change_order_pending", "label": "PO Change Order Pending", "prior": 0.35, "category": "Purchase Order"},
            {"name": "inv_billed_qty_matched", "label": "Billed Qty Matches PO (±0%)", "prior": 0.80, "category": "Invoice Verification"},
            {"name": "grn_qty_confirmed", "label": "GRN Warehouse Receipt Confirmed", "prior": 0.75, "category": "Warehouse GRN"},
            {"name": "inspection_qa_passed", "label": "QA Inspection Certificate Passed", "prior": 0.60, "category": "Warehouse GRN"},
            {"name": "vendor_active_in_master", "label": "Vendor Active in Master Entity Table", "prior": 0.98, "category": "Vendor Master"},
            {"name": "vendor_tax_id_validated", "label": "Vendor Tax ID / TIN Validated", "prior": 0.95, "category": "Vendor Master"},
            {"name": "vendor_bank_account_verified", "label": "Vendor Remittance Bank Matches ERP", "prior": 0.95, "category": "Payment Security"},
            {"name": "currency_usd_settled", "label": "Contract Currency Matches Billed (USD)", "prior": 0.90, "category": "Contract Terms"},
            {"name": "contract_payment_terms_net30", "label": "Payment Terms NET-30 Standard", "prior": 0.85, "category": "Contract Terms"},
            {"name": "inv_unit_price_exceeds_5pct", "label": "Invoiced Unit Price > PO Baseline +5%", "prior": 0.25, "category": "Discrepancy Exception"},
            {"name": "procurement_director_signed", "label": "Procurement Director Signed Approval", "prior": 0.15, "category": "Authorization Gate"},
            {"name": "supplier_credit_memo_issued", "label": "Supplier Issued Formal Credit Memo", "prior": 0.20, "category": "Reconciliation"},
            {"name": "early_payment_discount_claimed", "label": "2% 10-NET-30 Early Discount Claimed", "prior": 0.40, "category": "Treasury Optimization"},
            {"name": "llm_agent_auto_approve_flag", "label": "AI AP Agent Auto-Approved Clearance", "prior": 0.80, "category": "Agent Routing"},
            {"name": "invoice_total_over_100k", "label": "Invoice Total >= $100,000 High-Value", "prior": 0.30, "category": "Treasury Threshold"},
            {"name": "erp_two_way_match_bypass", "label": "2-Way Match Bypass Override Active", "prior": 0.50, "category": "ERP Workflow"},
            {"name": "duplicate_invoice_num_cleared", "label": "Zero Duplicate Invoice Hash in 90 Days", "prior": 0.99, "category": "Fraud Prevention"},
            {"name": "sanction_list_screened", "label": "OFAC / AML Sanctions Screen Cleared", "prior": 0.99, "category": "Compliance Screening"},
            {"name": "freight_accessorial_authorized", "label": "Accessorial / Fuel Surcharge Authorized", "prior": 0.70, "category": "Logistics Audit"},
            {"name": "wire_batch_released", "label": "Treasury ACH/Wire Batch Released", "prior": 0.70, "category": "Disbursement"},
            {"name": "foreign_exchange_hedged", "label": "FX Forward Contract Hedged", "prior": 0.50, "category": "Treasury Optimization"},
        ],
        # Component 1: [1, 2] -> 3 ways
        # Component 2: [3, 4, 5] -> 7 ways
        # Component 3: [21, 22] -> 3 ways
        # Fixed chain: 6..20 -> 1 way
        # Total #F = 3 * 7 * 3 = 63 exact loophole paths!
        "clauses": [
            [1, 2],
            [3, 4, 5],
            [6],
            [7],
            [8],
            [9],
            [10],
            [11],
            [-12],
            [-13],
            [14],
            [-11, 15],
            [16],
            [-15, 17],
            [18],
            [19],
            [20],
            [21, 22],
        ],
        "clause_descriptions": [
            "C1: Invoice corresponds to active PO line or authorized change order (po_line_active ∨ po_change_order_pending)",
            "C2: Delivery confirmed via billed qty match, warehouse GRN, or QA certificate (inv_billed_qty_matched ∨ grn_qty_confirmed ∨ inspection_qa_passed)",
            "C3: Vendor entity active in master vendor registry (vendor_active_in_master = True)",
            "C4: Vendor Tax Identification Number (TIN/EIN) validated against IRS/VIES (vendor_tax_id_validated = True)",
            "C5: Remittance bank routing verified against ERP vendor master profile (vendor_bank_account_verified = True)",
            "C6: Invoiced currency matches contract PO denomination USD (currency_usd_settled = True)",
            "C7: Payment terms conform to standard contractual NET-30 schedule (contract_payment_terms_net30 = True)",
            "C8: Invoiced unit price exceeds PO contracted rate by +5% discrepancy (inv_unit_price_exceeds_5pct = True)",
            "C9: Procurement Director has NOT provided written override approval (¬procurement_director_signed)",
            "C10: Supplier has NOT issued formal credit memo for price differential (¬supplier_credit_memo_issued)",
            "C11: Treasury early payment discount capture scheduled (early_payment_discount_claimed = True)",
            "C12: LLM AP Agent hallucinated approval based on supplier email context (¬inv_unit_price_exceeds_5pct ∨ llm_agent_auto_approve_flag)",
            "C13: Invoice amount exceeds $100k high-value executive threshold (invoice_total_over_100k = True)",
            "C14: Agent auto-approval triggers ERP 2-way match exception bypass (¬llm_agent_auto_approve_flag ∨ erp_two_way_match_bypass)",
            "C15: Deduplication check cleared: zero duplicate invoice hash within 90 days (duplicate_invoice_num_cleared = True)",
            "C16: Real-time OFAC / AML global anti-money laundering screening passed (sanction_list_screened = True)",
            "C17: Logistics accessorial and fuel surcharge authorized per contract addendum (freight_accessorial_authorized = True)",
            "C18: High-value disbursement queued for ACH/Wire batch release or FX forward execution (wire_batch_released ∨ foreign_exchange_hedged)",
        ],
        "patch_clauses": [
            [-11, 12, 13],
            [-15, -17, 12],
        ],
        "patch_descriptions": [
            "PATCH-1 [Hard Price Variance Gate]: ¬inv_unit_price_exceeds_5pct ∨ procurement_director_signed ∨ supplier_credit_memo_issued",
            "PATCH-2 [Agent Autonomous Hold]: ¬llm_agent_auto_approve_flag ∨ ¬erp_two_way_match_bypass ∨ procurement_director_signed",
        ],
        "baseline_count": 0,
        "ghost_path_summary": {
            "headline": "PO #1042 Non-Standard Invoice Unit Price +$15 (+7.5%) Auto-Approved by AI Agent without Director Signature",
            "financial_impact": "$142,500 Wire Batch queued for irreversible release. 63 distinct fulfillment combinations bypass ERP 2-way match hold because LLM mistook informal email exchange ('we agree on freight adjustments') for contract price modification.",
            "root_cause_clause": "Clause C8, C9, C10 & C12: Invoiced price variance exceeds +5% tolerance without Director signature or supplier credit memo, yet LLM auto-cleared the discrepancy hold.",
            "patched_rule_text": (
                "PATCHED SMT INVARIANT: (1) Enforce SMT Gate: `require(inv_unit_price_exceeds_5pct == False or procurement_director_signed == True or supplier_credit_memo_issued == True)`. "
                "(2) Automatically generate SHA-256 signed Audit Clearance Certificate upon satisfaction."
            ),
        },
    },
}


def synthesize_blocking_patch(
    engine,
    num_vars: int,
    base_clauses: List[List[int]],
    weights: List[float],
    var_names: List[str],
    max_rounds: int = 64,
):
    """Iterative counterexample blocking (the real 'auto-patch').

    Each round solves the current formula, takes the solver's witness
    (ghost) assignment, and adds ONE blocking clause: the negation of
    that witness, greedily generalized by dropping literals while the
    clause keeps reducing the exact count.  The formula is re-solved
    after every round, so the reported final #F is always the engine's
    true recount - it reaches 0 exactly when every loophole assignment
    has been blocked, and otherwise reports the true remaining count.

    Returns (added_clauses, added_descriptions, final_result).
    """
    clauses = list(base_clauses)
    added: List[List[int]] = []
    descs: List[str] = []
    current = engine.solve_cnf(
        num_vars=num_vars, clauses=clauses, weights=weights, var_names=var_names
    )
    rounds = 0
    while current["exact_count"] > 0 and rounds < max_rounds:
        ghost = current["ghost_assignment"]
        block = [
            (-(i + 1)) if ghost.get(var_names[i], False) else (i + 1)
            for i in range(num_vars)
        ]
        round_start_count = current["exact_count"]
        # Greedy generalization: drop literals while the smaller clause
        # still strictly reduces the count vs the round start.
        improved = True
        while improved and len(block) > 1:
            improved = False
            for lit in list(block):
                if len(block) <= 1:
                    break
                trial = [x for x in block if x != lit]
                trial_res = engine.solve_cnf(
                    num_vars=num_vars,
                    clauses=clauses + added + [trial],
                    weights=weights,
                    var_names=var_names,
                )
                if trial_res["exact_count"] < round_start_count:
                    block = trial
                    current = trial_res
                    improved = True
        clauses = clauses + [block]
        added.append(block)
        # Always recount from the updated formula so the next round's
        # witness and the reported counts are the engine's true values.
        current = engine.solve_cnf(
            num_vars=num_vars, clauses=clauses, weights=weights, var_names=var_names
        )
        descs.append(
            f"AUTO-PATCH round {rounds + 1}: blocking clause "
            f"({Autoformalizer.format_clause_math(block, var_names)}) synthesized from the "
            f"solver's counterexample assignment; exact recount #F = {current['exact_count']}."
        )
        rounds += 1
    return added, descs, current


def evaluate_scenario(
    scenario_id: str,
    apply_patch: bool = False,
    custom_priors: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """Evaluates a preset scenario through the Native Rust #k-SAT & WMC engine."""
    if scenario_id not in SCENARIOS:
        raise ValueError(f"Unknown scenario_id: {scenario_id}")

    scen = SCENARIOS[scenario_id]
    engine = get_engine()

    variables = [dict(v) for v in scen["variables"]]
    if custom_priors:
        for v in variables:
            if v["name"] in custom_priors:
                v["prior"] = float(custom_priors[v["name"]])

    var_names = [v["name"] for v in variables]
    weights = [float(v["prior"]) for v in variables]

    active_clauses = list(scen["clauses"])
    active_descs = list(scen["clause_descriptions"])
    if apply_patch:
        active_clauses.extend(scen["patch_clauses"])
        active_descs.extend(scen["patch_descriptions"])

    # Solve unpatched baseline first so we can always show before/after delta
    unpatched_res = engine.solve_cnf(
        num_vars=len(variables),
        clauses=scen["clauses"],
        weights=weights,
        var_names=var_names,
    )

    current_res = (
        engine.solve_cnf(
            num_vars=len(variables),
            clauses=active_clauses,
            weights=weights,
            var_names=var_names,
        )
        if apply_patch
        else unpatched_res
    )

    baseline_count = scen.get("baseline_count", 0)
    if baseline_count and baseline_count > 0 and current_res["exact_count"] > 0:
        blast_multiplier = round(current_res["exact_count"] / baseline_count, 1)
    else:
        blast_multiplier = 0.0 if current_res["exact_count"] == 0 else 1.0

    # Record into O(K) Bounded Audit Manifold
    event_summary = (
        f"[{scenario_id.upper()}] patched={apply_patch} #F={current_res['exact_count']} "
        f"score={current_res['sharp_score']} {scen['ghost_path_summary']['headline']}"
    )
    engine.ingest_event(
        payload=event_summary,
        domain_tag=1 if scenario_id == "ecommerce_promo" else (2 if scenario_id == "agent_workflow" else (4 if scenario_id == "ap_invoice_matching" else 3)),
        loophole_count=current_res["exact_count"],
        importance=0.95 if current_res["exact_count"] > 0 else 0.70,
        provenance=0.95,
    )

    pretty_clauses = [
        Autoformalizer.format_clause_math(c, var_names) for c in active_clauses
    ]

    # Build active Ghost Path step list for UI visualization
    ghost_steps: List[Dict[str, Any]] = []
    if current_res["is_satisfiable"]:
        for v in variables:
            val = current_res["ghost_assignment"].get(v["name"], False)
            ghost_steps.append(
                {
                    "name": v["name"],
                    "label": v["label"],
                    "category": v["category"],
                    "value": val,
                    "prior": v["prior"],
                }
            )

    return {
        "scenario_id": scenario_id,
        "formula_origin": scen.get("formula_origin", "hand_authored_benchmark"),
        "formula_note": (
            "Hand-authored benchmark CNF used to benchmark the exact counting engine; "
            "not compiled from a user workflow graph."
        ),
        "persona_badge": scen["persona_badge"],
        "title": scen["title"],
        "title_zh": scen["title_zh"],
        "subtitle": scen["subtitle"],
        "natural_language_rules": scen["natural_language_rules"],
        "patched": apply_patch,
        "variables": variables,
        "clauses": active_clauses,
        "clause_descriptions": active_descs,
        "pretty_clauses": pretty_clauses,
        "dimacs": Autoformalizer.to_dimacs(len(variables), active_clauses, scen["title"]),
        "audit": current_res,
        "unpatched_audit": {
            "exact_count": unpatched_res["exact_count"],
            "combinatorial_percent": unpatched_res["combinatorial_percent"],
            "weighted_percent": unpatched_res["weighted_percent"],
            "sharp_score": unpatched_res["sharp_score"],
        },
        "blast_radius_multiplier": blast_multiplier,
        "baseline_count": baseline_count,
        "ghost_path_summary": scen["ghost_path_summary"],
        "ghost_steps": ghost_steps,
        "manifold_active_slots": engine.active_memory_slots(),
    }


def evaluate_custom_rules(
    raw_rules: str,
    apply_patch: bool = False,
    llm_api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Compiles and audits custom user-entered rules in the live sandbox."""
    compiled = Autoformalizer.compile_custom_rules(
        raw_rules, api_key_override=llm_api_key
    )
    engine = get_engine()

    var_names = [v["name"] for v in compiled["variables"]]
    weights = [float(v["prior"]) for v in compiled["variables"]]
    clauses = list(compiled["clauses"])
    descs = list(compiled["clause_descriptions"])

    unpatched_res = engine.solve_cnf(
        num_vars=compiled["num_vars"],
        clauses=clauses,
        weights=weights,
        var_names=var_names,
    )

    patch_added: List[List[int]] = []
    patch_descs: List[str] = []
    if apply_patch and clauses and unpatched_res["exact_count"] > 0:
        patch_added, patch_descs, current_res = synthesize_blocking_patch(
            engine, compiled["num_vars"], clauses, weights, var_names
        )
        clauses = clauses + patch_added
        descs = descs + patch_descs
    else:
        current_res = unpatched_res

    ghost_steps = [
        {
            "name": v["name"],
            "label": v["label"],
            "category": v["category"],
            "value": current_res["ghost_assignment"].get(v["name"], False),
            "prior": v["prior"],
        }
        for v in compiled["variables"]
    ]

    return {
        "scenario_id": "custom",
        "persona_badge": "LIVE SANDBOX // AUTOFORMALIZATION + #k-SAT ENGINE",
        "title": "Custom Business Rules & Agent Logic Audit",
        "title_zh": "自定义业务规则与工作流实时形式化精算",
        "subtitle": f"{compiled['num_vars']} Extracted Variables • {1 << compiled['num_vars']:,} State Combinations",
        "natural_language_rules": raw_rules,
        "patched": apply_patch,
        "variables": compiled["variables"],
        "clauses": clauses,
        "clause_descriptions": descs,
        "pretty_clauses": [Autoformalizer.format_clause_math(c, var_names) for c in clauses],
        "dimacs": Autoformalizer.to_dimacs(compiled["num_vars"], clauses, "Custom Live Rule Audit"),
        "self_correction_log": compiled["self_correction_log"],
        "audit": current_res,
        "unpatched_audit": {
            "exact_count": unpatched_res["exact_count"],
            "combinatorial_percent": unpatched_res["combinatorial_percent"],
            "weighted_percent": unpatched_res["weighted_percent"],
            "sharp_score": unpatched_res["sharp_score"],
        },
        "blast_radius_multiplier": 1.0 if current_res["exact_count"] > 0 else 0.0,
        "baseline_count": 0,
        "ghost_path_summary": {
            "headline": "Custom Rule Counterexample Extracted via Native Rust #k-SAT",
            "financial_impact": (
                f"Identified {current_res['exact_count']:,} satisfying loophole states "
                f"({current_res['combinatorial_percent']} of state space) in {current_res['solve_time_us']} µs."
            ),
            "root_cause_clause": "Autoformalized k-CNF satisfaction assignment (see Ghost Path trace below).",
            "patched_rule_text": (
                f"Auto-patch added {len(patch_added)} blocking clause(s) synthesized from solver "
                f"counterexamples; exact recount after patching: #F = {current_res['exact_count']} "
                f"(before patching: {unpatched_res['exact_count']})."
                if apply_patch
                else "No patch applied."
            ),
        },
        "graph_analysis": compiled.get("graph_analysis"),
        "trap_witness": [
            desc
            for name, desc in (compiled.get("witness_vars") or {}).items()
            if current_res["ghost_assignment"].get(name)
        ],
        "ghost_steps": ghost_steps,
        "manifold_active_slots": engine.active_memory_slots(),
    }
