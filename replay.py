"""Replay store: what has already been written, so it is not written twice.

"Record once, run infinitely" is only safe if a replayed write cannot pay
twice - and a store that lives in one process's memory only protects one
run. The second session, the retry after a crash, the same ERA file picked
up by tomorrow's queue: those are the cases a double payment actually comes
from. So the store is an interface, and the durable implementation is the
one a deployment should use.

Two implementations, one contract:

    get(fingerprint)            -> record | None
    setdefault(fingerprint, r)  -> the stored record (existing wins)

`dict` satisfies it and is the default for tests and single-episode demos.
`JsonlReplayStore` is append-only on disk: one line per executed write,
flushed and fsynced before the call returns, so a crash between "executed"
and "recorded" is the only window - and it is the same window a human
poster has.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterator, Protocol

ReplayRecord = dict[str, Any]   # {"step": int, "episode_id": str, "recorded_at": str}


class ReplayStore(Protocol):
    def get(self, fingerprint: str) -> ReplayRecord | None: ...
    def setdefault(self, fingerprint: str, record: ReplayRecord) -> ReplayRecord: ...
    def __len__(self) -> int: ...
    def __contains__(self, fingerprint: object) -> bool: ...


class JsonlReplayStore:
    """Append-only, file-backed. Survives the process; shared across sessions.

    The file is the source of truth and is never rewritten. Loading replays
    it line by line; the first record for a fingerprint wins, which is the
    same rule `setdefault` applies in memory, so a store reloaded from disk
    answers identically to the one that wrote it.
    """

    SCHEMA = "actionguard.replay.v1"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._seen: dict[str, ReplayRecord] = {}
        if self.path.exists():
            with open(self.path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    row = json.loads(line)
                    self._seen.setdefault(row["fingerprint"], row["record"])

    def get(self, fingerprint: str) -> ReplayRecord | None:
        return self._seen.get(fingerprint)

    def setdefault(self, fingerprint: str, record: ReplayRecord) -> ReplayRecord:
        existing = self._seen.get(fingerprint)
        if existing is not None:
            return existing
        line = json.dumps({"schema": self.SCHEMA, "fingerprint": fingerprint,
                           "record": record}, sort_keys=True, separators=(",", ":"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._seen[fingerprint] = record
        return record

    def __len__(self) -> int:
        return len(self._seen)

    def __contains__(self, fingerprint: object) -> bool:
        return fingerprint in self._seen

    def __iter__(self) -> Iterator[str]:
        return iter(self._seen)

    def items(self):
        return self._seen.items()
