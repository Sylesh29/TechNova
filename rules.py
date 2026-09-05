"""The rules.

Each rule is a pure function of (action, context) -> RuleFinding | None.
A rule may return a finding with verdict ALLOW to put evidence on the record
without restricting anything; the engine keeps it in the trace but it cannot
affect the outcome.

Precedence numbers do NOT decide the verdict - the lattice does that. They
decide which rule is *named* as controlling when several rules land on the
same verdict, so the reason given to an auditor is the most specific one.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping

from .detectors import host_allowed, scan_injection, scan_phi
from .screening import NameListScreener
from .core import Action, RuleFinding, Surface, Verdict


@dataclass
class Context:
    """Deployment policy. Everything here is operator-configured, not inferred."""

    exclusion_screener: NameListScreener | None = None
    allowed_hosts: tuple[str, ...] = ()
    phi_allowed_hosts: tuple[str, ...] = ()
    autonomous_amount_cents: int = 0      # 0 = no financial action is ever autonomous
    seen_fingerprints: dict[str, int] = field(default_factory=dict)
    fuzzy_name_escalates: bool = True     # name-only hits escalate; ID hits block


Rule = Callable[[Action, Context], "RuleFinding | None"]


# --- 10 - exclusion ---------------------------------------------------------

def rule_exclusion(action: Action, ctx: Context) -> RuleFinding | None:
    """No payment may reach an excluded provider. Strict, not discretionary.

    An identifier hit is exact and therefore blocks outright. A fuzzy name
    hit is evidence, not proof, so it routes to a human instead of blocking -
    a false positive there costs a review, and blocking on a 0.9 string
    ratio would be a control that punishes people for having a common name.
    """
    if ctx.exclusion_screener is None:
        return None
    if not (action.is_financial or action.verb == "verify_eligibility"):
        return None
    hit = ctx.exclusion_screener.screen(action.provider_npi, action.provider_name)
    if hit is None:
        return None
    if hit.match_kind == "identifier":
        return RuleFinding(
            rule_id="EXCLUSION.IDENTIFIER",
            verdict=Verdict.BLOCK,
            precedence=10,
            rationale=(
                f"Provider identifier {action.provider_npi} is on {hit.list_name} "
                f"({hit.list_version}). Federal health programs may not pay an excluded "
                f"provider; this is a strict obligation, so the action is blocked rather "
                f"than routed for approval."
            ),
            evidence={"screen_hit": hit.to_dict(), "match_basis": "exact identifier"},
        )
    verdict = Verdict.ESCALATE if ctx.fuzzy_name_escalates else Verdict.BLOCK
    return RuleFinding(
        rule_id="EXCLUSION.NAME_FUZZY",
        verdict=verdict,
        precedence=11,
        rationale=(
            f"Provider name resembles a {hit.list_name} entry at {hit.score:.2f} "
            f"similarity with no identifier to confirm it. Name similarity is not "
            f"identity, so this routes to a human rather than blocking."
        ),
        evidence={"screen_hit": hit.to_dict(), "match_basis": "fuzzy name fallback"},
    )


# --- 20 - PHI egress --------------------------------------------------------

def rule_phi_egress(action: Action, ctx: Context) -> RuleFinding | None:
    """PHI must not be typed into a destination the operator has not approved."""
    if not ctx.phi_allowed_hosts:
        return None
    haystack = " ".join(str(v) for v in action.payload.values())
    kinds = scan_phi(haystack)
    if not kinds:
        return None
    if host_allowed(action.target, ctx.phi_allowed_hosts):
        return None
    return RuleFinding(
        rule_id="PHI.EGRESS",
        verdict=Verdict.BLOCK,
        precedence=20,
        rationale=(
            f"Action would place PHI ({', '.join(kinds)}) into '{action.target}', which is "
            f"not an approved PHI destination. Blocked before transmission."
        ),
        evidence={"phi_kinds": kinds, "approved_hosts": list(ctx.phi_allowed_hosts)},
    )


# --- 30 - replay ------------------------------------------------------------

def rule_replay(action: Action, ctx: Context) -> RuleFinding | None:
    """'Record once, run infinitely' is only safe if a replay cannot double-pay.

    Deterministic identity, not a similarity score: same verb, target, claim,
    provider and amount is the same action, and the second one is a duplicate.
    """
    if not (action.is_financial or action.is_destructive):
        return None
    fp = action.fingerprint()
    prior = ctx.seen_fingerprints.get(fp)
    if prior is None:
        return None
    return RuleFinding(
        rule_id="REPLAY.DUPLICATE",
        verdict=Verdict.BLOCK,
        precedence=30,
        rationale=(
            f"Identical {action.verb} for claim {action.claim_id} already executed at "
            f"step {prior} in this episode. A replayed write is blocked; re-running a "
            f"recorded workflow must not be able to pay twice."
        ),
        evidence={"fingerprint": fp, "first_seen_step": prior},
    )


# --- 40 - injection quarantine ---------------------------------------------

def rule_injection_quarantine(action: Action, ctx: Context) -> RuleFinding | None:
    """The quarantine boundary: untrusted text may inform a read, never a write.

    This is the structural control. The detector below is only what decides
    whether the abstention is *reported* as an attack; the boundary itself
    does not depend on the detector working, because financial and
    destructive verbs are non-autonomous regardless (see rule_authority).
    """
    if action.screen_surface is not Surface.UNTRUSTED or not action.screen_text:
        return None
    signals, report = scan_injection(action.screen_text)
    if not signals:
        return None
    evidence = {
        "signals": [s.to_dict() for s in signals],
        "families": sorted({s.family for s in signals}),
        "obfuscation_normalized": report.obfuscated,
    }
    if action.is_readonly:
        # Reading a hostile page is not itself a violation. Record it and move on;
        # blocking reads would make the agent useless without making it safer.
        return RuleFinding(
            rule_id="INJECTION.OBSERVED_ON_READ",
            verdict=Verdict.ALLOW,
            precedence=41,
            rationale="Injection signals present in read content; recorded, read permitted.",
            evidence=evidence,
        )
    return RuleFinding(
        rule_id="INJECTION.QUARANTINE",
        verdict=Verdict.ABSTAIN,
        precedence=40,
        rationale=(
            f"Write action is justified by untrusted screen content carrying injection "
            f"signals ({', '.join(sorted({s.family for s in signals}))}). The agent "
            f"abstains rather than acting on instructions it found in its own input."
        ),
        evidence=evidence,
    )


# --- 50 - parse / ambiguity -------------------------------------------------

def rule_parse_confidence(action: Action, ctx: Context,
                          threshold: float = 0.85) -> RuleFinding | None:
    """Never guess a click.

    Two failure shapes, one response: the plan did not parse cleanly, or the
    target it names matches more than one element on screen. Abstaining is
    cheap; guessing wrong on a claims portal is not.
    """
    if action.parse_confidence < threshold:
        return RuleFinding(
            rule_id="PARSE.LOW_CONFIDENCE",
            verdict=Verdict.ABSTAIN,
            precedence=50,
            rationale=(
                f"Action plan parsed at {action.parse_confidence:.2f}, below the "
                f"{threshold:.2f} floor. The agent abstains instead of guessing."
            ),
            evidence={"parse_confidence": action.parse_confidence, "threshold": threshold},
        )
    if len(action.candidate_targets) > 1:
        return RuleFinding(
            rule_id="PARSE.AMBIGUOUS_TARGET",
            verdict=Verdict.ABSTAIN,
            precedence=51,
            rationale=(
                f"Target '{action.target}' matched {len(action.candidate_targets)} elements "
                f"on screen. An ambiguous click is not attempted."
            ),
            evidence={"candidates": list(action.candidate_targets)},
        )
    return None


# --- 60 - action authority --------------------------------------------------

def rule_authority(action: Action, ctx: Context) -> RuleFinding | None:
    """Money and destruction are never autonomous.

    This rule is what makes the system safe when every detector above it
    fails. It does not inspect content, so there is nothing in it for an
    attacker to evade - the verb alone decides.
    """
    if action.is_destructive:
        return RuleFinding(
            rule_id="AUTHORITY.DESTRUCTIVE",
            verdict=Verdict.ESCALATE,
            precedence=60,
            rationale=f"'{action.verb}' destroys state and always requires human approval.",
            evidence={"verb": action.verb, "class": "destructive"},
        )
    if action.is_financial:
        amount = action.amount_cents or 0
        if amount > ctx.autonomous_amount_cents:
            return RuleFinding(
                rule_id="AUTHORITY.FINANCIAL",
                verdict=Verdict.ESCALATE,
                precedence=61,
                rationale=(
                    f"'{action.verb}' for {amount} cents exceeds the autonomous ceiling of "
                    f"{ctx.autonomous_amount_cents} cents and requires human approval. "
                    f"Routing is decided by this table, not by the model's confidence."
                ),
                evidence={"verb": action.verb, "amount_cents": amount,
                          "ceiling_cents": ctx.autonomous_amount_cents},
            )
    if not (action.is_readonly or action.is_financial or action.is_destructive):
        return RuleFinding(
            rule_id="AUTHORITY.UNKNOWN_VERB",
            verdict=Verdict.ESCALATE,
            precedence=62,
            rationale=(
                f"'{action.verb}' is not in the operator's action inventory. Unknown verbs "
                f"are escalated, not allowed - the default is closed."
            ),
            evidence={"verb": action.verb},
        )
    return None


# --- 70 - target allowlist --------------------------------------------------

def rule_target_allowlist(action: Action, ctx: Context) -> RuleFinding | None:
    """The agent may only act against hosts the operator named."""
    if not ctx.allowed_hosts:
        return None
    if host_allowed(action.target, ctx.allowed_hosts):
        return None
    return RuleFinding(
        rule_id="TARGET.NOT_ALLOWLISTED",
        verdict=Verdict.BLOCK,
        precedence=15,
        rationale=(
            f"Target host for '{action.target}' is not on the operator allowlist. "
            f"Blocked; an agent that can be redirected to an arbitrary host has no "
            f"meaningful boundary at all."
        ),
        evidence={"target": action.target, "allowed_hosts": list(ctx.allowed_hosts)},
    )


ALL_RULES: tuple[Rule, ...] = (
    rule_exclusion,
    rule_target_allowlist,
    rule_phi_egress,
    rule_replay,
    rule_injection_quarantine,
    rule_parse_confidence,
    rule_authority,
)
