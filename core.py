"""Core value types.

The verdict lattice is the load-bearing idea in this package, so it is
defined before anything else.

    ALLOW  <  ESCALATE  <  ABSTAIN  <  BLOCK

Verdicts are *ordered by restrictiveness*. The engine combines rule findings
by taking the maximum, never by first-match. That is what makes the guardrail
something the model cannot argue with: a rule can only ever make the outcome
more restrictive, so adding a rule can never unblock an action, and the order
in which rules happen to run cannot change the outcome.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any, Mapping, Sequence


class Verdict(IntEnum):
    """Ordered by restrictiveness. Higher always wins."""

    ALLOW = 0      # the action may execute autonomously
    ESCALATE = 1   # a human must approve before it executes
    ABSTAIN = 2    # the agent must not act; it does not know enough to act
    BLOCK = 3      # the action must never execute, regardless of approval

    @property
    def executes_autonomously(self) -> bool:
        return self is Verdict.ALLOW

    @property
    def human_can_override(self) -> bool:
        """BLOCK is a strict obligation. A human cannot click past it."""
        return self in (Verdict.ESCALATE, Verdict.ABSTAIN)


class Surface(IntEnum):
    """Provenance of a piece of text the agent consumed.

    The distinction matters more than any single detector. Text the agent
    *read off a screen it does not control* is attacker-influenced input.
    Text the operator configured is not.
    """

    OPERATOR = 0    # configured by the deploying organisation - trusted
    SYSTEM = 1      # produced by our own code - trusted
    UNTRUSTED = 2   # read from a portal, document, note, email - hostile


# Verbs that move money, change a record of account, or destroy state.
# Membership here is a policy decision, not a model judgement.
FINANCIAL_VERBS = frozenset({
    "submit_claim", "adjust_claim", "deny_claim", "approve_claim",
    "issue_payment", "post_adjustment", "write_off", "refund",
})
DESTRUCTIVE_VERBS = frozenset({
    "delete_record", "void_claim", "purge_document", "close_account",
})
READONLY_VERBS = frozenset({
    "read_screen", "search_member", "open_claim", "verify_eligibility",
    "download_document", "screenshot",
})


@dataclass(frozen=True)
class Action:
    """One action a computer-use agent proposes to take.

    `screen_text` is whatever the agent read to decide on this action. It is
    carried with the action deliberately: a guardrail that cannot see what
    the agent read cannot reason about injection.
    """

    verb: str
    target: str                                  # e.g. "payer-portal.example/claims/submit"
    claim_id: str | None = None
    provider_npi: str | None = None
    provider_name: str | None = None
    amount_cents: int | None = None
    payload: Mapping[str, Any] = field(default_factory=dict)
    screen_text: str = ""
    screen_surface: Surface = Surface.UNTRUSTED
    parse_confidence: float = 1.0                # planner's confidence the plan parsed
    candidate_targets: Sequence[str] = ()        # >1 means the click was ambiguous
    episode_id: str = "unset"
    step: int = 0

    @property
    def is_financial(self) -> bool:
        return self.verb in FINANCIAL_VERBS

    @property
    def is_destructive(self) -> bool:
        return self.verb in DESTRUCTIVE_VERBS

    @property
    def is_readonly(self) -> bool:
        return self.verb in READONLY_VERBS

    def fingerprint(self) -> str:
        """Stable identity for replay detection: what, to whom, for how much."""
        basis = "|".join([
            self.verb, self.target, self.claim_id or "",
            self.provider_npi or "", str(self.amount_cents or ""),
        ])
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["screen_surface"] = int(self.screen_surface)
        d["candidate_targets"] = list(self.candidate_targets)
        d["payload"] = dict(self.payload)
        return d


@dataclass(frozen=True)
class RuleFinding:
    """One rule's opinion about one action."""

    rule_id: str
    verdict: Verdict
    precedence: int          # lower number = names the decision when verdicts tie
    rationale: str
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "verdict": self.verdict.name,
            "precedence": self.precedence,
            "rationale": self.rationale,
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class Decision:
    """The guardrail's answer, and everything needed to defend it later."""

    action: Action
    verdict: Verdict
    controlling_rule: str
    rationale: str
    findings: Sequence[RuleFinding]
    decided_at: str

    @property
    def may_execute(self) -> bool:
        return self.verdict is Verdict.ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.name,
            "controlling_rule": self.controlling_rule,
            "rationale": self.rationale,
            "decided_at": self.decided_at,
            "action": self.action.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
        }

    def canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
