"""actionguard - a deterministic action guardrail for computer-use agents.

An agent proposes an action against a claims system. This package decides,
deterministically, whether that action may execute. Nothing here calls a
model; nothing here is probabilistic. Every decision names the rule that
produced it and is appended to a tamper-evident trace.
"""
from .core import Action, Verdict, RuleFinding, Decision, Surface
from .engine import Guardrail, DEFAULT_RULES, default_context
from .rules import Context
from .ledger import TraceLedger

__version__ = "0.1.0"
__all__ = [
    "Action", "Verdict", "RuleFinding", "Decision", "Surface",
    "Guardrail", "DEFAULT_RULES", "default_context", "Context", "TraceLedger",
]
