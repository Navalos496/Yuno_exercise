"""Per-control evaluators (SOC 2 CC checks over a normalized snapshot)."""

from .bulk import evaluate_all, summarize

__all__ = ["evaluate_all", "summarize"]
