"""Tamper-evident decision trace.

The question an auditor asks is never "what did your model score". It is
"why did the agent do that, and can you prove the record was not edited
afterwards". This is a hash-chained append-only ledger: each entry commits
to the previous entry's digest, so any retroactive edit breaks the chain at
a detectable point.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterator, Sequence

GENESIS = "0" * 64


def _digest(payload: str, prev_hash: str) -> str:
    return hashlib.sha256(f"{prev_hash}{payload}".encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TraceEntry:
    seq: int
    recorded_at: str
    prev_hash: str
    entry_hash: str
    body: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "recorded_at": self.recorded_at,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "body": self.body,
        }


class TraceLedger:
    """Append-only, hash-chained, verifiable."""

    def __init__(self, clock=None) -> None:
        self._entries: list[TraceEntry] = []
        # Injectable clock keeps the ledger deterministic under test.
        self._clock = clock or (lambda: datetime.now(timezone.utc).isoformat())

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[TraceEntry]:
        return iter(self._entries)

    @property
    def head(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS

    def append(self, body: dict[str, Any]) -> TraceEntry:
        prev = self.head
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
        entry = TraceEntry(
            seq=len(self._entries),
            recorded_at=self._clock(),
            prev_hash=prev,
            entry_hash=_digest(payload, prev),
            body=body,
        )
        self._entries.append(entry)
        return entry

    def verify(self) -> tuple[bool, int | None]:
        """Return (intact, first_broken_seq). Recomputes the whole chain."""
        prev = GENESIS
        for entry in self._entries:
            payload = json.dumps(entry.body, sort_keys=True, separators=(",", ":"))
            if entry.prev_hash != prev or entry.entry_hash != _digest(payload, prev):
                return False, entry.seq
            prev = entry.entry_hash
        return True, None

    def export(self) -> dict[str, Any]:
        intact, broken_at = self.verify()
        return {
            "schema": "actionguard.ledger.v1",
            "entries": [e.to_dict() for e in self._entries],
            "head": self.head,
            "chain_intact": intact,
            "first_broken_seq": broken_at,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.export(), indent=indent)


def load_and_verify(blob: str) -> tuple[bool, int | None]:
    """Verify an exported trace without trusting its own `chain_intact` flag."""
    data = json.loads(blob)
    prev = GENESIS
    for raw in data.get("entries", []):
        payload = json.dumps(raw["body"], sort_keys=True, separators=(",", ":"))
        if raw["prev_hash"] != prev or raw["entry_hash"] != _digest(payload, prev):
            return False, raw["seq"]
        prev = raw["entry_hash"]
    return True, None
