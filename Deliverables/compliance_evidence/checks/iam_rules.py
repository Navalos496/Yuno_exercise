"""IAM parsing helpers shared by CC6.1."""

from __future__ import annotations

from typing import Any


def actions(stmt: dict[str, Any]) -> list[str]:
    a = stmt.get("Action")
    if a is None:
        return []
    if isinstance(a, str):
        return [a]
    return list(a)


def resources(stmt: dict[str, Any]) -> list[str]:
    r = stmt.get("Resource")
    if r is None:
        return []
    if isinstance(r, str):
        return [r]
    return list(r)


def stmt_is_deny(stmt: dict[str, Any]) -> bool:
    return str(stmt.get("Effect", "")).lower() == "deny"


def has_condition(stmt: dict[str, Any]) -> bool:
    c = stmt.get("Condition")
    return bool(c and isinstance(c, dict))


def full_admin_star_star(stmt: dict[str, Any]) -> str | None:
    """True *:* style admin (Allow). Conditions reduce risk but we still flag as blocking."""
    if stmt_is_deny(stmt):
        return None
    acts = actions(stmt)
    res = resources(stmt)
    if "*" in acts and "*" in res:
        if has_condition(stmt):
            return (
                "Allow grants Action * on Resource * with a Condition block. "
                "That is still an administrative-class pattern; treat as high risk unless reviewed."
            )
        return "Allow grants Action * on Resource * (classic full-admin pattern)."
    return None


def action_star_scoped_resource(stmt: dict[str, Any]) -> str | None:
    """Action * with at least one non-* resource — powerful, not automatically *:*."""
    if stmt_is_deny(stmt):
        return None
    acts = actions(stmt)
    res = resources(stmt)
    if "*" not in acts:
        return None
    if "*" in res:
        return None
    if has_condition(stmt):
        return (
            "Allow includes Action * on specific ARNs plus a Condition. "
            "Common for tightly scoped automation; still needs human sign-off."
        )
    return (
        "Allow includes Action * on specific resources (not Resource *). "
        "Often break-glass or legacy automation. Confirm it is rare, monitored, and time-bound."
    )


def service_level_wildcard(stmt: dict[str, Any]) -> str | None:
    if stmt_is_deny(stmt):
        return None
    for a in actions(stmt):
        if isinstance(a, str) and a.endswith(":*") and a != "*":
            return f"Service-level wildcard action '{a}' (many auditors ask for a narrower action list)."
    return None
