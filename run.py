#!/usr/bin/env python3
"""Entry point that works from inside this directory.

`python -m actionguard.demo` requires the repo root as the working directory,
which is a real trap: run it from in here and Python puts THIS directory first
on sys.path. Any module named after a standard-library one then shadows it and
the interpreter fails on its own imports before reaching a line of our code.

Two things prevent that. No module in this package is named after a stdlib
module - `tests/test_packaging.py` asserts it, so a future rename cannot
quietly reintroduce the trap. And this script puts the parent directory on
the path so the package imports the same way from either location.

    python run.py            # the gated agent episode
    python run.py redteam    # injection red team
    python run.py eval       # eval harness, including its abstention
    python run.py test       # the full suite
    python run.py all        # everything, in order
"""
from __future__ import annotations

import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


def _demo() -> int:
    from actionguard.demo import main
    main()
    return 0


def _redteam() -> int:
    from actionguard import redteam
    print(redteam.format_report(redteam.run()))
    return 0


def _eval() -> int:
    from actionguard import evalharness as ev
    print(ev.format_report(ev.run(ev.labeled_cases())))
    print("\nThe same harness on a suite it cannot vouch for:\n")
    print(ev.format_report(ev.run(ev.unlabeled_cases())))
    return 0


def _test() -> int:
    suite = unittest.defaultTestLoader.discover(
        start_dir=str(HERE / "tests"), top_level_dir=str(HERE.parent))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() else 1


COMMANDS = {"demo": _demo, "redteam": _redteam, "eval": _eval, "test": _test}


def main(argv: list[str]) -> int:
    cmd = (argv[1] if len(argv) > 1 else "demo").lower()
    if cmd == "all":
        for name in ("demo", "redteam", "eval", "test"):
            print(f"\n{'#' * 78}\n# {name}\n{'#' * 78}\n")
            if COMMANDS[name]() != 0:
                return 1
        return 0
    if cmd not in COMMANDS:
        print(f"unknown command '{cmd}'. one of: {', '.join(COMMANDS)}, all")
        return 2
    return COMMANDS[cmd]()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
