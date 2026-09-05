"""The precedence engine.

One design decision carries this file, and it is worth stating plainly
because it is the difference between a guardrail and a suggestion:

    The engine evaluates EVERY rule and takes the MOST RESTRICTIVE verdict.
    It does not stop at the first match.

First-match-wins would make rule ordering load-bearing: put a permissive
rule early and it hides a block that would have fired later. Taking the
maximum over the verdict lattice makes the outcome independent of order and
gives a property that can be tested rather than asserted -

    MONOTONICITY: for any action, adding a rule can never produce a less
    restrictive verdict than the same rule set without it.

That is what "a deterministic override the model cannot argue with" means
mechanically. `Guardrail.check_monotonicity` proves it over a corpus.
"""
from __future__ import annotations

from datetime import datetime, timezone
from itertools import combinations
from typing import Iterable, Sequence

from .rules import ALL_RULES, Context, Rule
from .ledger import TraceLedger
from .core import Action, Decision, RuleFinding, Verdict

DEFAULT_RULES: tuple[Rule, ...] = ALL_RULES

_DEFAULT_ALLOW = RuleFinding(
    rule_id="DEFAULT.ALLOW",
    verdict=Verdict.ALLOW,
    precedence=999,
    rationale="No rule restricted this action.",
)


class Guardrail:
    """Decides whether a proposed agent action may execute."""

    def __init__(
        self,
        context: Context,
        rules: Sequence[Rule] = DEFAULT_RULES,
        ledger: TraceLedger | None = None,
        clock=None,
    ) -> None:
        self.context = context
        self.rules = tuple(rules)
        self.ledger = ledger if ledger is not None else TraceLedger(clock=clock)
        self._clock = clock or (lambda: datetime.now(timezone.utc).isoformat())

    # -- core ---------------------------------------------------------------

    def _findings(self, action: Action) -> list[RuleFinding]:
        out: list[RuleFinding] = []
        for rule in self.rules:
            finding = rule(action, self.context)
            if finding is not None:
                out.append(finding)
        return out

    @staticmethod
    def _resolve(findings: Sequence[RuleFinding]) -> RuleFinding:
        """Most restrictive verdict wins; lowest precedence names it."""
        if not findings:
            return _DEFAULT_ALLOW
        worst = max(f.verdict for f in findings)
        if worst is Verdict.ALLOW:
            return _DEFAULT_ALLOW
        controlling = min(
            (f for f in findings if f.verdict == worst),
            key=lambda f: f.precedence,
        )
        return controlling

    def decide(self, action: Action, record: bool = True) -> Decision:
        findings = self._findings(action)
        controlling = self._resolve(findings)
        decision = Decision(
            action=action,
            verdict=controlling.verdict,
            controlling_rule=controlling.rule_id,
            rationale=controlling.rationale,
            findings=tuple(findings),
            decided_at=self._clock(),
        )
        if record:
            self.ledger.append({
                "kind": "action_decision",
                "episode_id": action.episode_id,
                "step": action.step,
                "verdict": decision.verdict.name,
                "controlling_rule": decision.controlling_rule,
                "rationale": decision.rationale,
                "action_fingerprint": action.fingerprint(),
                "verb": action.verb,
                "target": action.target,
                "claim_id": action.claim_id,
                "findings": [f.to_dict() for f in findings],
            })
            # Only executed writes count as "seen" for replay purposes. An
            # action that was blocked never happened, so it must not poison
            # a later legitimate retry.
            if decision.may_execute and (action.is_financial or action.is_destructive):
                self.context.seen_fingerprints.setdefault(action.fingerprint(), action.step)
        return decision

    def execute(self, action: Action, executor) -> tuple[Decision, object]:
        """Gate an executor behind the guardrail.

        The point of this method is that there is no code path to `executor`
        that skips `decide`. A guardrail the caller can forget to invoke is
        documentation, not a control.
        """
        decision = self.decide(action)
        if not decision.may_execute:
            return decision, None
        result = executor(action)
        self.ledger.append({
            "kind": "action_executed",
            "episode_id": action.episode_id,
            "step": action.step,
            "action_fingerprint": action.fingerprint(),
            "verb": action.verb,
        })
        return decision, result

    # -- the invariant, as an executable check ------------------------------

    def check_monotonicity(self, actions: Iterable[Action],
                           max_subset: int = 3) -> tuple[bool, list[dict]]:
        """Verify that no rule can loosen another's decision.

        For each action, compare the full rule set against every subset up to
        `max_subset` rules removed. If any smaller rule set ever yields a MORE
        restrictive verdict than the full set, the lattice has been violated.
        """
        violations: list[dict] = []
        full_rules = self.rules
        for action in actions:
            baseline = self._resolve(self._findings(action)).verdict
            for k in range(1, min(max_subset, len(full_rules)) + 1):
                for removed in combinations(range(len(full_rules)), k):
                    subset = tuple(r for i, r in enumerate(full_rules) if i not in removed)
                    sub_findings = [f for r in subset
                                    if (f := r(action, self.context)) is not None]
                    sub_verdict = self._resolve(sub_findings).verdict
                    if sub_verdict > baseline:
                        violations.append({
                            "action": f"{action.verb}@{action.target}",
                            "full_set_verdict": baseline.name,
                            "subset_verdict": sub_verdict.name,
                            "removed_rules": [full_rules[i].__name__ for i in removed],
                        })
        return (not violations), violations


def default_context(**overrides) -> Context:
    """A sane, closed-by-default deployment policy."""
    from .screening import load_exclusion_screener

    base = dict(
        exclusion_screener=load_exclusion_screener(),
        allowed_hosts=("payer-portal.example.com", "clearinghouse.example.net"),
        phi_allowed_hosts=("payer-portal.example.com",),
        autonomous_amount_cents=0,
    )
    base.update(overrides)
    return Context(**base)
