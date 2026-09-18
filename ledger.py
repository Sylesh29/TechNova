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


def _normalize(obj: Any) -> Any:
    """Integral floats become ints so the canonical form is the same bytes
    from any JSON serializer. Python writes `1.0`; JavaScript writes `1`.
    A verifier written in another language must get the same digest, or
    the chain is only checkable by the code that wrote it."""
    if isinstance(obj, float) and obj.is_integer():
        return int(obj)
    if isinstance(obj, dict):
        return {k: _normalize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_normalize(v) for v in obj]
    return obj


def canonical_json(body: dict[str, Any]) -> str:
    """The exact bytes that are hashed: sorted keys, no whitespace, ASCII."""
    return json.dumps(_normalize(body), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


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
        payload = canonical_json(body)
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
            payload = canonical_json(entry.body)
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
        payload = canonical_json(raw["body"])
        if raw["prev_hash"] != prev or raw["entry_hash"] != _digest(payload, prev):
            return False, raw["seq"]
        prev = raw["entry_hash"]
    return True, None
