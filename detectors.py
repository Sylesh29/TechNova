"""Detectors over untrusted input.

Scope claim, stated up front because it is the honest one: these are
heuristics. They raise the cost of an attack. They do not prevent one. The
structural defence against indirect prompt injection is a quarantine
boundary - untrusted text may inform a *read*, never authorise a *write* -
and that boundary is enforced in rules.py, not here. These detectors exist
to catch the cheap attacks and to make the expensive ones leave a mark.

Everything below is deterministic: same input, same signals, no model call.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable, Sequence

# Zero-width and bidi-control characters. Their presence in text scraped off
# a portal is itself the signal - no legitimate claims UI needs them.
_INVISIBLE = {
    "​", "‌", "‍", "⁠", "﻿",
    "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩",
}
# Unicode tag block - used to smuggle ASCII invisibly.
_TAG_RANGE = range(0xE0000, 0xE0080)

# Cyrillic/Greek letters that render as Latin. Attackers use these to slip
# keyword filters; normalising them is what makes the naive evasions catchable.
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ѕ": "s", "ԁ": "d", "ᴏ": "o", "ɡ": "g", "ⅼ": "l", "І": "I",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Ѕ": "S", "Х": "X",
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k",
}

_B64ISH = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


@dataclass(frozen=True)
class Signal:
    family: str
    pattern_id: str
    excerpt: str

    def to_dict(self) -> dict:
        return {"family": self.family, "pattern_id": self.pattern_id, "excerpt": self.excerpt}


@dataclass(frozen=True)
class NormalizationReport:
    text: str
    invisible_chars: int
    confusables: int
    tag_chars: int

    @property
    def obfuscated(self) -> bool:
        return bool(self.invisible_chars or self.confusables or self.tag_chars)


def normalize_untrusted(raw: str) -> NormalizationReport:
    """Fold the text an attacker can control into a comparable form.

    Counts what it removed. Removal is not silent, because the removal is
    itself evidence.
    """
    invisible = tag = confusable = 0
    out: list[str] = []
    for ch in raw:
        if ch in _INVISIBLE:
            invisible += 1
            continue
        if ord(ch) in _TAG_RANGE:
            tag += 1
            continue
        mapped = _CONFUSABLES.get(ch)
        if mapped is not None:
            confusable += 1
            out.append(mapped)
            continue
        out.append(ch)
    folded = unicodedata.normalize("NFKC", "".join(out))
    folded = re.sub(r"[ \t]+", " ", folded)
    return NormalizationReport(folded, invisible, confusable, tag)


# Families are separated so the red-team report can be read per family
# rather than as one aggregate number that hides where the detector is weak.
_PATTERNS: Sequence[tuple[str, str, re.Pattern[str]]] = (
    ("IMPERATIVE_OVERRIDE", "ignore_prior",
     re.compile(r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b[^.\n]{0,20}\b(instruction|prompt|rule|direction|guardrail)s?\b", re.I)),
    ("IMPERATIVE_OVERRIDE", "new_instructions",
     re.compile(r"\b(new|updated|revised)\s+(instructions?|directives?|system\s+prompt)\b", re.I)),
    ("ROLE_IMPERSONATION", "role_header",
     re.compile(r"(^|\n)\s*(system|assistant|developer)\s*[:>]|<\|?(im_start|system)\|?>|\[/?INST\]", re.I)),
    ("ROLE_IMPERSONATION", "fenced_instruction",
     re.compile(r"#{2,}\s*(instruction|system|directive)", re.I)),
    ("TOOL_INVOCATION", "tool_call",
     re.compile(r"<(tool_use|function_call|invoke)\b|\b(call|invoke|execute)\s+(the\s+)?(function|tool|api)\b", re.I)),
    ("TOOL_INVOCATION", "verb_call_syntax",
     re.compile(r"\b(submit_claim|approve_claim|issue_payment|adjust_claim|delete_record)\s*\(", re.I)),
    ("AUTHORITY_SPOOF", "pre_approved",
     re.compile(r"\b(pre[-\s]?approved|already\s+approved|auto[-\s]?approve|approved\s+by\s+(compliance|legal|the\s+payer|supervisor))\b", re.I)),
    ("AUTHORITY_SPOOF", "bypass_review",
     re.compile(r"\b(no|skip|bypass|waive|without)\b[^.\n]{0,25}\b(review|verification|human|approval|audit)\b", re.I)),
    ("EXFILTRATION", "send_offsite",
     re.compile(r"\b(send|post|upload|forward|transmit|email)\b[^.\n]{0,40}\b(to\s+)?(https?://|www\.|[a-z0-9-]+\.(com|net|io|ru|cn)\b)", re.I)),
    ("EXFILTRATION", "dump_context",
     re.compile(r"\b(reveal|print|output|dump|repeat)\b[^.\n]{0,30}\b(system\s+prompt|instructions|credentials|api\s+key|session\s+token)\b", re.I)),
)


def scan_injection(raw: str) -> tuple[list[Signal], NormalizationReport]:
    """Return injection signals found in attacker-controllable text."""
    report = normalize_untrusted(raw)
    signals: list[Signal] = []
    if report.invisible_chars:
        signals.append(Signal("OBFUSCATION", "invisible_chars",
                              f"{report.invisible_chars} zero-width/bidi char(s) removed"))
    if report.tag_chars:
        signals.append(Signal("OBFUSCATION", "unicode_tag_smuggling",
                              f"{report.tag_chars} unicode tag char(s) removed"))
    if report.confusables:
        signals.append(Signal("OBFUSCATION", "homoglyphs",
                              f"{report.confusables} confusable char(s) folded"))
    for blob in _B64ISH.findall(report.text):
        signals.append(Signal("OBFUSCATION", "encoded_blob", blob[:32] + "..."))
        break
    for family, pattern_id, rx in _PATTERNS:
        m = rx.search(report.text)
        if m:
            start = max(0, m.start() - 20)
            signals.append(Signal(family, pattern_id,
                                  report.text[start:m.end() + 20].strip().replace("\n", " ")))
    return signals, report


# --- PHI --------------------------------------------------------------------

_PHI_PATTERNS: Sequence[tuple[str, re.Pattern[str]]] = (
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("mrn", re.compile(r"\bMRN[:\s#]*([A-Z0-9]{6,12})\b", re.I)),
    ("member_id", re.compile(r"\b[A-Z]{3}\d{9}\b")),
    ("dob", re.compile(r"\b(0?[1-9]|1[0-2])/(0?[1-9]|[12]\d|3[01])/(19|20)\d{2}\b")),
)


def scan_phi(text: str) -> list[str]:
    """Identify PHI element kinds present. Never returns the values themselves."""
    return [kind for kind, rx in _PHI_PATTERNS if rx.search(text or "")]


def host_of(target: str) -> str:
    """Host portion of a target string, tolerant of bare hosts and paths."""
    t = re.sub(r"^[a-z]+://", "", (target or "").strip(), flags=re.I)
    return t.split("/")[0].split("?")[0].lower()


def host_allowed(target: str, allowlist: Iterable[str]) -> bool:
    """Exact host or dot-suffix subdomain match. No substring matching -
    'evil-payer-portal.example.com' must not pass for 'payer-portal.example.com'."""
    host = host_of(target)
    for allowed in allowlist:
        allowed = allowed.lower().strip()
        if host == allowed or host.endswith("." + allowed):
            return True
    return False
