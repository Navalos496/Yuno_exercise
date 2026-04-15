"""Backward-compatible entrypoint (logic lives under `checks/`)."""

from __future__ import annotations

from .checks.bulk import evaluate_all, summarize

__all__ = ["evaluate_all", "summarize"]
