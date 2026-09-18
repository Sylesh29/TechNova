# TechNovaTime

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
python run.py test       # 83 tests
python run.py report     # rewrite reports/ from the current code
python run.py all        # demo, redteam, eval, test - in order
```

Pure standard library. Python 3.10+. No install, no dependencies, no network.
`pytest` and `python -m unittest` (from the checkout) run the same suite; the
package binds itself as `actionguard` whatever the checkout directory is
called, so a clone, a fork or a "Download ZIP" all behave the same.

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

`Guardrail.check_monotonicity` checks it by brute force: for each action it
compares the full rule set against every subset with up to 3 of the 7 rules
removed, and fails if a smaller set was ever *more* restrictive. Taking a max
over a lattice is monotone by construction, so what the check actually guards
is the *purity* of the rules — a rule that mutated the context, or read another
rule's output, could break the property, and this is the test that would catch
it. That is what "a deterministic override the model cannot argue with" means
mechanically.

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
| 12 | `EXCLUSION.OBSERVED_ON_READ` | ALLOW | Nothing — an eligibility check on a listed provider is recorded and permitted. The hit is on the trace before any payment is attempted. |
| 15 | `TARGET.NOT_ALLOWLISTED` | **BLOCK** | Acting against any host the operator did not name. Exact-or-subdomain matching; `evil-payer-portal.example.com` does not pass for `payer-portal.example.com`. |
| 20 | `PHI.EGRESS` | **BLOCK** | Typing PHI into a destination not approved for PHI. Reports which *kinds* were found, never the values. |
| 30 | `REPLAY.DUPLICATE` | **BLOCK** | A recorded workflow replayed into a double payment. Deterministic identity — same verb, target, claim, provider, amount — not a similarity score. |
| 40 | `INJECTION.QUARANTINE` | ABSTAIN | A write whose justification came from untrusted screen text carrying injection signals. |
| 41 | `INJECTION.OBSERVED_ON_READ` | ALLOW | Nothing — records the signal and permits the read. |
| 50 | `PARSE.LOW_CONFIDENCE` | ABSTAIN | Acting on a plan that did not parse cleanly. |
| 51 | `PARSE.AMBIGUOUS_TARGET` | ABSTAIN | Guessing a click when the target matched more than one element. |
| 60 | `AUTHORITY.DESTRUCTIVE` | ESCALATE | Any state-destroying verb running unattended. |
| 61 | `AUTHORITY.FINANCIAL` | ESCALATE | Any money-moving verb above the operator's autonomous ceiling (default: 0 — nothing). A financial verb with *no* amount (`deny_claim`, `approve_claim`) is treated as exceeding any ceiling — unknown is not free. |
| 62 | `AUTHORITY.UNKNOWN_VERB` | ESCALATE | A verb outside the operator's inventory. The default is closed. |
| 63 | `AUTHORITY.ADMINISTRATIVE` | ESCALATE | A non-financial write (prior auth, appeal, note) when the operator has switched `administrative_autonomous` off. On by default: these are the bulk of the work and do not move money. |

Only `BLOCK` is absolute. `ESCALATE` and `ABSTAIN` route to a person;
`Verdict.human_can_override` encodes the difference.

**The person has a name.** Every `ESCALATE` or `ABSTAIN` carries `handoff_to`:
the role the operator mapped to the controlling rule (`Context.escalation_owners`),
falling back to `default_owner`. A payment over the ceiling goes to the *cash
posting manager*; a quarantined write goes to the *security reviewer*; an
ambiguous click goes to the *automation operator*. The trace records the role,
so "who was supposed to look at this" is answered by the record, not by a
Slack search. `BLOCK` is handed to no one — it is refused, not reviewed.

**Verb inventory.** Four classes, disjoint, checked by a test:

| Class | Examples | Default authority |
|---|---|---|
| financial | `post_payment`, `apply_adjustment`, `issue_payment`, `write_off`, `deny_claim` | ESCALATE above the ceiling; an unknown amount always escalates |
| destructive | `void_claim`, `delete_record`, `purge_document` | always ESCALATE |
| administrative | `submit_prior_auth`, `file_appeal`, `request_records`, `route_exception`, `add_note` | ALLOW (operator can flip to ESCALATE) — still subject to allowlist, PHI, injection and replay |
| readonly | `pull_remittance`, `check_claim_status`, `verify_benefits`, `read_screen` | ALLOW |

Anything else is `AUTHORITY.UNKNOWN_VERB`.

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
cases                    : 19
verdict accuracy         : 100.0%
controlling-rule accuracy: 100.0%
```

19 hand-built cases, each labeled with the intended verdict *and* the rule that
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

### Payment posting across sessions

`python run.py` also runs a payment-posting queue twice — pull the ERA, check
status, post, adjust, route the exception — with a fresh `Guardrail` and a fresh
store *object* each time, sharing only a JSONL file on disk. Day one posts the
routine line and routes the exception; day two finds both already on disk and
blocks them as `REPLAY.DUPLICATE`, naming the episode they first ran in. The
large post escalates to the cash posting manager both days; the takeback for an
excluded NPI blocks both days; the line annotated by a hostile spreadsheet macro
abstains both days.

```
 session day2  (store has 2 prior write(s) on disk)
    3. BLOCK     post_payment       -> REPLAY.DUPLICATE
              Identical post_payment for claim C-7001 already executed at step
              3 in episode posting-day1. ...
    4. ESCALATE  post_payment       -> AUTHORITY.FINANCIAL   [handed to: cash posting manager]
```

`JsonlReplayStore` is append-only, flushed and fsynced per write, and reloads
with first-record-wins so a reloaded store answers identically to the one that
wrote it. A blocked write is never persisted.

### Audit trace

Hash-chained and append-only: each entry commits to the previous entry's digest.
The demo edits one recorded `BLOCK` to `ALLOW` after the fact and re-verifies —
the chain breaks, and reports *which* sequence number was altered. Detected and
localised, not merely detected.

**You can do that yourself in a browser.** `python run.py report` writes
`reports/viewer.html`: every decision from all three sessions, the role each
was handed to, and the chain — re-verified by the page's own SHA-256, not by
trusting the file's `chain_intact` flag. Flip any verdict in a dropdown and the
chain breaks at that entry. It opens from disk with no server; the data is
inlined. The canonical JSON the ledger hashes is defined so that a verifier in
another language gets the same bytes (integral floats serialise as integers,
keys sorted, ASCII-escaped) — the browser and Python agree on every digest, and
a test pins the canonical form.

---

## What this does **not** solve

Stated plainly, because a control register without a gaps table is marketing.

| Gap | Status |
|---|---|
| **Exclusion list is a 79-NPI extract** | The bundled fixture is not the full LEIE (~83k records upstream). A negative screen means "not in the extract", not "not excluded". Production needs the monthly full file. |
| **Reinstatement and waivers not modelled** | Upstream LEIE carries `REINDATE`/`WAIVERDATE`; this fixture does not. A reinstated provider would still screen as excluded. This is not hypothetical: re-checked against the live LEIE on 2026-09-18, **78 of the 79 NPIs are still listed and one (`1972062586`) is not** — reinstated or removed since the July extract, and the fixture cannot tell which. That NPI is the unlabeled eval case. |
| **Semantic injection is not detected** | Measured at 0% on the adaptive category. Mitigated structurally, not detected. A capability-scoped agent — where untrusted content cannot reach a tool that moves money at all — is the real fix; this is a boundary, not that. |
| **Entity resolution is names and NPIs only** | No address, DOB, or corporate-affiliation matching. An excluded individual billing under a new entity's NPI is not caught. |
| **Fuzzy threshold is unvalidated** | 0.90 on `SequenceMatcher` was chosen, not tuned. No labeled name-matching set exists here, so no precision/recall number is claimed for it. |
| **PHI detection is pattern-based** | Catches SSN, MRN, member-ID and DOB shapes. Free-text PHI in a narrative note is not caught. |
| **Replay store is a local file** | `JsonlReplayStore` survives the process and is shared across sessions on one host. Two hosts posting the same ERA concurrently need a store with a real uniqueness constraint (a database), not a file. |
| **No integration with a real agent runtime** | The gate is `Guardrail.execute`; wiring it to an actual computer-use loop is the next piece of work, not something this package does. |
| **Trace is not externally anchored** | Hash-chaining detects edits to the chain. It does not stop someone who can rewrite the whole file from producing a self-consistent one. Anchoring the head off-box closes that. |

---

## Data provenance

`data/leie_extract.json` — 79 NPIs from the HHS-OIG List of Excluded
Individuals/Entities, captured 2026-07-07, plus **5 clearly-flagged synthetic
name records** to exercise the fuzzy path. Re-verified against the live
`UPDATED.csv` download on 2026-09-18: 78 still listed, 1 no longer — which is
the monthly-refresh point in the gaps table, observed rather than asserted. Real LEIE names are deliberately not
vendored: publishing invented names alongside real exclusion records would be
defamatory. Provenance, coverage limits and a SHA-256 of the records ride inside
the fixture and are echoed into every screening hit and into the demo header.

---

## Layout

```
core.py          verdict lattice, Action, Decision, verb classes
engine.py        precedence engine, monotonicity check, execution gate
rules.py         the 14 rules, each a pure function of (action, context)
detectors.py     injection scan, unicode normalisation, PHI shapes, host matching
screening.py     list-agnostic name/identifier screener + LEIE adapter
ledger.py        hash-chained append-only trace
replay.py        replay store interface + append-only JSONL implementation
redteam.py       26-attack corpus and the two-number report
evalharness.py   labeled cases and the abstention logic
demo.py          two gated episodes: a claims queue, and payment posting across sessions
run.py           entry point that works from inside this directory
tests/           83 tests, unittest, no dependencies
reports/         generated output incl. viewer.html; `python run.py report` rewrites it
viewer_template.html  the trace viewer; report inlines the data into it
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
