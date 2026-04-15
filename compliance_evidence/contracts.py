"""Interfaces so we can bolt on new clouds or frameworks without rewriting the runner."""

from __future__ import annotations

from typing import Any, Protocol

from .models import ControlFinding


class InfrastructureState(Protocol):
    """Normalized dict-shaped snapshot (today: JSON fixtures, tomorrow: live collectors)."""

    def __getitem__(self, key: str) -> Any: ...


class ControlEvaluator(Protocol):
    """One SOC 2 (or mapped) control implemented as pure logic over a snapshot."""

    def evaluate(self, state: dict[str, Any], frameworks: set[str]) -> ControlFinding: ...
