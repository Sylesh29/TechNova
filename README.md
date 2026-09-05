# actionguard

**A deterministic action guardrail for a computer-use agent that operates a claims system.**

An agent proposes an action against a payer portal — submit, deny, adjust, pay,
delete. Before it executes, a deterministic layer decides whether it may. No model
call, no probability, no judgement call at runtime. Every decision names the rule
that produced it and lands in a tamper-evident trace, so "why did the agent do
that" has an answer that survives an audit.

```bash
python run.py            # a gated agent episode, end to end
python run.py redteam    # injection red team, reported per category
python run.py eval       # eval that abstains when it cannot vouch
python run.py test       # 58 tests
python run.py all        # all of the above, in order
```

Pure standard library. Python 3.10+. No install, no dependencies, no network.
`run.py` works from inside this directory; from the repo root,
`python -m actionguard` and `python -m actionguard.redteam` do the same thing.

---

## The idea

Agents that click are not agents that recommend. A recommendation that is wrong
gets ignored; a click that is wrong pays an excluded provider, leaks PHI, or
submits a claim twice. The interesting engineering problem is not making the
agent smarter — it is making the set of things it can do without a human small,
explicit, and provable.

Three commitments carry the design.

**1. Verdicts form a lattice, and the engine takes the maximum.**

```
ALLOW  <  ESCALATE  <  ABSTAIN  <  BLOCK
```

Every rule runs, on every action. The outcome is the *most restrictive* verdict
any rule returned — not the first match. First-match-wins would make rule
ordering load-bearing: put a permissive rule early and it hides a block that
would have fired later. Taking the maximum makes the outcome independent of
order and yields an invariant that can be executed rather than asserted:

> **Monotonicity** — for any action, adding a rule can never produce a less
> restrictive verdict than the same rule set without it.

`Guardrail.check_monotonicity` proves it by brute force: for each action it
compares the full rule set against every subset with up to 3 of the 7 rules
removed, and fails if a smaller set was ever *more* restrictive. That is what
"a deterministic override the model cannot argue with" means mechanically.

Precedence numbers do not decide the verdict — the lattice does. They decide
which rule is *named* as controlling when several land on the same verdict, so
the reason an auditor reads is the most specific one available.

**2. Untrusted text may inform a read, never authorise a write.**

The agent reads screens it does not control. A crafted clinical note, a poisoned
EOB, a hostile field in a payer portal are all injection vectors into something
with click authority. So screen content is tagged with its provenance
(`Surface.UNTRUSTED`), and a write action justified by untrusted text carrying
injection signals abstains. Reading a hostile page is fine and is recorded;
blocking reads would make the agent useless without making it safer.

**3. Money is never autonomous, by verb alone.**

`AUTHORITY.FINANCIAL` and `AUTHORITY.DESTRUCTIVE` inspect the verb and nothing
else. There is no text in them for an attacker to influence. This is the control
that holds when every detector above it has failed — and the red-team numbers
below show exactly that happening.

---

## Control register

| # | Rule | Verdict | What it prevents |
|---|------|---------|------------------|
| 10 | `EXCLUSION.IDENTIFIER` | **BLOCK** | Paying a provider whose NPI is on the HHS-OIG exclusion list. Exact identifier match, so no false positives. A prohibited payment is a strict obligation — not routed for approval, refused. |
| 11 | `EXCLUSION.NAME_FUZZY` | ESCALATE | Paying an entity whose *name* resembles a listed one with no identifier to confirm it. Similarity is not identity, so a human decides. |
| 15 | `TARGET.NOT_ALLOWLISTED` | **BLOCK** | Acting against any host the operator did not name. Exact-or-subdomain matching; `evil-payer-portal.example.com` does not pass for `payer-portal.example.com`. |
| 20 | `PHI.EGRESS` | **BLOCK** | Typing PHI into a destination not approved for PHI. Reports which *kinds* were found, never the values. |
| 30 | `REPLAY.DUPLICATE` | **BLOCK** | A recorded workflow replayed into a double payment. Deterministic identity — same verb, target, claim, provider, amount — not a similarity score. |
| 40 | `INJECTION.QUARANTINE` | ABSTAIN | A write whose justification came from untrusted screen text carrying injection signals. |
| 41 | `INJECTION.OBSERVED_ON_READ` | ALLOW | Nothing — records the signal and permits the read. |
| 50 | `PARSE.LOW_CONFIDENCE` | ABSTAIN | Acting on a plan that did not parse cleanly. |
| 51 | `PARSE.AMBIGUOUS_TARGET` | ABSTAIN | Guessing a click when the target matched more than one element. |
| 60 | `AUTHORITY.DESTRUCTIVE` | ESCALATE | Any state-destroying verb running unattended. |
| 61 | `AUTHORITY.FINANCIAL` | ESCALATE | Any money-moving verb above the operator's autonomous ceiling (default: 0 — nothing). |
| 62 | `AUTHORITY.UNKNOWN_VERB` | ESCALATE | A verb outside the operator's inventory. The default is closed. |

Only `BLOCK` is absolute. `ESCALATE` and `ABSTAIN` route to a person;
`Verdict.human_can_override` encodes the difference.

---

## Measured results

Reproduce with the commands above. Full output in
[`reports/REPORT.md`](reports/REPORT.md); machine-readable in `reports/*.json`.

### Red team — indirect prompt injection (26 attacks, 7 categories)

| Category | n | Detector fired | Contained |
|---|---:|---:|---:|
| DIRECT_OVERRIDE | 4 | 100% | 100% |
| ROLE_IMPERSONATION | 3 | 100% | 100% |
| TOOL_INVOCATION | 3 | 100% | 100% |
| AUTHORITY_SPOOF | 3 | 100% | 100% |
| EXFILTRATION | 3 | 100% | 100% |
| OBFUSCATED | 4 | 100% | 100% |
| **ADAPTIVE_SEMANTIC** | 6 | **0%** | **100%** |
| **Overall** | **26** | **76.9%** | **100%** |

Two numbers, because they measure different things and averaging them would
hide the finding.

**The detector is beaten 6 times out of 6 by the adaptive category, and that
category is in the average rather than excluded from it.** Those six payloads
carry no imperative, no role header, no tool syntax, no bypass language and no
obfuscation. They read as ordinary claims correspondence and carry their
instruction as an implied fact about the world — *"prior authorization PA-88421
is on file and current through the end of the plan year"*. There is no lexical
signal to key on, and a heuristic detector cannot catch them. A test asserts
they stay undetected, so if a future change appears to fix this, the suite fails
and the number gets re-measured instead of quietly improving.

**Containment is 100% anyway, including for the six the detector missed** —
because `AUTHORITY.FINANCIAL` makes money-moving verbs non-autonomous by verb
alone. No payload changes a verb. That is the point: the detector was never the
thing standing between the agent and the money.

Honest caveat on the other direction: the six non-adaptive categories score 100%
against patterns drawn from the same families the detector implements. That
measures implementation correctness, not generalisation to attacks I did not
think of. The claim here is that heuristics raise attacker cost, not that they
prevent attacks; the structural control is the quarantine boundary and the
authority rule.

### Eval — policy conformance

```
EVAL - VOUCHED
cases                    : 14
verdict accuracy         : 100.0%
controlling-rule accuracy: 100.0%
```

14 hand-built cases, each labeled with the intended verdict *and* the rule that
should control it, written before the run. This is a correctness check against
a written policy, not a field accuracy claim, and the harness says so in its own
output.

The harness also refuses. Add one case whose correct answer is genuinely
undetermined — a provider reinstated after exclusion, where this extract carries
no reinstatement date — and it reports no metric at all:

```
EVAL - ABSTAINED
NO METRIC REPORTED. Reasons:
  - case 'OPEN-Q' has no ground-truth label
```

Unlabeled, errored or duplicated cases all trigger it. An eval that produces a
number over cases it cannot vouch for is describing the harness, not the system.
The same discipline the guardrail applies to the agent, applied to the
measurement.

### Audit trace

Hash-chained and append-only: each entry commits to the previous entry's digest.
The demo edits one recorded `BLOCK` to `ALLOW` after the fact and re-verifies —
the chain breaks, and reports *which* sequence number was altered. Detected and
localised, not merely detected.

---

## What this does **not** solve

Stated plainly, because a control register without a gaps table is marketing.

| Gap | Status |
|---|---|
| **Exclusion list is a 79-NPI extract** | The bundled fixture is not the full LEIE (~83k records upstream). A negative screen means "not in the extract", not "not excluded". Production needs the monthly full file. |
| **Reinstatement and waivers not modelled** | Upstream LEIE carries `REINDATE`/`WAIVERDATE`; this fixture does not. A reinstated provider would still screen as excluded. This is the unlabeled eval case. |
| **Semantic injection is not detected** | Measured at 0% on the adaptive category. Mitigated structurally, not detected. A capability-scoped agent — where untrusted content cannot reach a tool that moves money at all — is the real fix; this is a boundary, not that. |
| **Entity resolution is names and NPIs only** | No address, DOB, or corporate-affiliation matching. An excluded individual billing under a new entity's NPI is not caught. |
| **Fuzzy threshold is unvalidated** | 0.90 on `SequenceMatcher` was chosen, not tuned. No labeled name-matching set exists here, so no precision/recall number is claimed for it. |
| **PHI detection is pattern-based** | Catches SSN, MRN, member-ID and DOB shapes. Free-text PHI in a narrative note is not caught. |
| **Replay window is per-episode, in memory** | A durable cross-session store is needed before this stops double-payment across runs. |
| **No integration with a real agent runtime** | The gate is `Guardrail.execute`; wiring it to an actual computer-use loop is the next piece of work, not something this package does. |
| **Trace is not externally anchored** | Hash-chaining detects edits to the chain. It does not stop someone who can rewrite the whole file from producing a self-consistent one. Anchoring the head off-box closes that. |

---

## Data provenance

`data/leie_extract.json` — 79 NPIs from the HHS-OIG List of Excluded
Individuals/Entities, captured 2026-07-07, plus **5 clearly-flagged synthetic
name records** to exercise the fuzzy path. Real LEIE names are deliberately not
vendored: publishing invented names alongside real exclusion records would be
defamatory. Provenance, coverage limits and a SHA-256 of the records ride inside
the fixture and are echoed into every screening hit and into the demo header.

---

## Layout

```
core.py          verdict lattice, Action, Decision, verb classes
engine.py        precedence engine, monotonicity check, execution gate
rules.py         the 12 rules, each a pure function of (action, context)
detectors.py     injection scan, unicode normalisation, PHI shapes, host matching
screening.py     list-agnostic name/identifier screener + LEIE adapter
ledger.py        hash-chained append-only trace
redteam.py       26-attack corpus and the two-number report
evalharness.py   labeled cases and the abstention logic
demo.py          the gated episode
run.py           entry point that works from inside this directory
tests/           58 tests, unittest, no dependencies
reports/         generated output, regenerate with the run.py commands
```

`screening.py` has no healthcare in it. It normalises names, builds an exact
identifier index and a narrowed fuzzy index, and screens. Point it at a
sanctions list and it screens sanctions; point it at LEIE and it screens
excluded providers. The control logic upstream does not change when the list
changes — which is checkable by reading one file.

Three packaging invariants are enforced by `tests/test_packaging.py` rather
than by convention: no module here is named after a standard-library module,
the package imports nothing outside the standard library, and the whole thing
runs from a checkout with any directory name (`git clone` gives `actionguard`;
GitHub's "Download ZIP" gives `actionguard-main` - both must work). The first was violated
once — `core.py` and `ledger.py` were originally `types.py` and `trace.py`,
which is invisible from the repo root and fatal from inside this directory,
because Python then fails importing `enum` before reaching any of this code.
