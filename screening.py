"""Exclusion-list screening.

This module is deliberately list-agnostic. It normalises names, builds an
exact identifier index and a narrowed fuzzy name index, and screens. Point
it at a sanctions list and it screens sanctions; point it at the HHS-OIG
exclusion list and it screens excluded healthcare providers. The control
logic upstream does not change when the list changes - that is the whole
claim, and it is checkable by reading this file.

Identifier matching is exact and therefore has no false positives. Name
matching is a fallback for records without an identifier, and is reported
as a distinct match_kind so a downstream rule can treat the two differently.
"""
from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Iterable, Mapping

_PUNCT = re.compile(r"[^a-z0-9 ]+")
_WS = re.compile(r"\s+")
_SUFFIXES = frozenset({"jr", "sr", "ii", "iii", "iv", "md", "do", "dds", "rn", "np", "pa"})


def normalize_name(raw: str) -> str:
    """Fold case, strip accents, drop punctuation, suffixes and middle initials.

    Periods are deleted rather than replaced with a space, so "M.D." folds to
    the token "md" and is caught by the suffix list. Replacing them with a
    space instead would produce "m" and "d", which no suffix filter can see -
    that shape was a live bug before the test suite caught it.

    Single-character tokens are dropped so a middle initial does not make a
    person fail to match themselves. For a screening normalizer that trade is
    correct: it costs recall nothing and prevents "Whitfield, Marion T." and
    "Marion Whitfield" being treated as different people.
    """
    decomposed = unicodedata.normalize("NFKD", raw)
    ascii_only = "".join(c for c in decomposed if not unicodedata.combining(c))
    depunct = ascii_only.lower().replace(".", "")
    lowered = _PUNCT.sub(" ", depunct)
    tokens = [
        t for t in _WS.sub(" ", lowered).strip().split(" ")
        if t and len(t) > 1 and t not in _SUFFIXES
    ]
    return " ".join(sorted(tokens))  # order-insensitive: "Whitfield, Marion" == "Marion Whitfield"


@dataclass(frozen=True)
class ScreenHit:
    match_kind: str      # "identifier" (exact) | "name" (fuzzy)
    score: float         # 1.0 for identifier matches
    listed_identifier: str | None
    listed_name: str | None
    list_name: str
    list_version: str
    colliding_records: int = 1   # >1: several list records share this name

    def to_dict(self) -> dict:
        return {
            "match_kind": self.match_kind,
            "score": round(self.score, 4),
            "listed_identifier": self.listed_identifier,
            "listed_name": self.listed_name,
            "list": self.list_name,
            "list_version": self.list_version,
            "colliding_records": self.colliding_records,
        }


class NameListScreener:
    """Generic screener over (identifier, name) records."""

    def __init__(
        self,
        records: Iterable[Mapping[str, str]],
        list_name: str,
        list_version: str,
        fuzzy_threshold: float = 0.90,
    ) -> None:
        self.list_name = list_name
        self.list_version = list_version
        self.fuzzy_threshold = fuzzy_threshold
        self._by_identifier: dict[str, Mapping[str, str]] = {}
        self._by_name: dict[str, list[Mapping[str, str]]] = {}
        # Blocking key narrows fuzzy comparison to plausible candidates only,
        # so screening stays O(candidates) rather than O(list).
        self._blocks: dict[str, list[str]] = {}
        for rec in records:
            ident = (rec.get("identifier") or "").strip()
            name = (rec.get("name") or "").strip()
            if ident:
                self._by_identifier[ident] = rec
            if name:
                key = normalize_name(name)
                if not key:
                    continue
                self._by_name.setdefault(key, []).append(rec)
                self._blocks.setdefault(self._blocking_key(key), []).append(key)

    @staticmethod
    def _blocking_key(normalized: str) -> str:
        """First letter of each token, capped - cheap and recall-friendly."""
        return "".join(t[0] for t in normalized.split(" ")[:3])

    def _name_hit(self, key: str, score: float) -> ScreenHit:
        """Build a name hit for a normalized key present in the index.

        Several list records can normalize to the same name. Picking `[0]`
        silently would report whichever happened to load first; instead the
        record that carries an identifier is preferred - it is the one a
        reviewer can confirm against - and the collision count is reported.
        """
        recs = self._by_name[key]
        rec = next((r for r in recs if (r.get("identifier") or "").strip()), recs[0])
        return ScreenHit("name", score, rec.get("identifier") or None, rec.get("name"),
                         self.list_name, self.list_version, colliding_records=len(recs))

    def __len__(self) -> int:
        return max(len(self._by_identifier), len(self._by_name))

    @property
    def identifier_count(self) -> int:
        return len(self._by_identifier)

    @property
    def name_count(self) -> int:
        return len(self._by_name)

    def screen(self, identifier: str | None, name: str | None) -> ScreenHit | None:
        # Identifier first. Exact, deterministic, no false positives.
        if identifier:
            rec = self._by_identifier.get(identifier.strip())
            if rec is not None:
                return ScreenHit("identifier", 1.0, identifier.strip(),
                                 rec.get("name"), self.list_name, self.list_version)
        if not name:
            return None
        key = normalize_name(name)
        if not key:
            return None
        if key in self._by_name:
            return self._name_hit(key, 1.0)
        best, best_score = None, 0.0
        for candidate in set(self._blocks.get(self._blocking_key(key), ())):
            score = SequenceMatcher(None, key, candidate).ratio()
            if score > best_score:
                best, best_score = candidate, score
        if best is not None and best_score >= self.fuzzy_threshold:
            return self._name_hit(best, best_score)
        return None


def load_exclusion_screener(path: str | Path | None = None) -> NameListScreener:
    """Load the bundled HHS-OIG LEIE extract.

    Provenance and coverage limits live in the fixture itself and are echoed
    into every hit, so a reader is never left guessing what was screened.
    """
    path = Path(path) if path else Path(__file__).parent / "data" / "leie_extract.json"
    with open(path, "r", encoding="utf-8") as fh:
        blob = json.load(fh)
    return NameListScreener(
        records=blob["records"],
        list_name=blob["list_name"],
        list_version=blob["list_version"],
    )


def load_fixture_meta(path: str | Path | None = None) -> dict:
    """Fixture provenance and coverage limits, without the records."""
    path = Path(path) if path else Path(__file__).parent / "data" / "leie_extract.json"
    with open(path, "r", encoding="utf-8") as fh:
        blob = json.load(fh)
    return {k: v for k, v in blob.items() if k != "records"}
