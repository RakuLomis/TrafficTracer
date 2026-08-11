"""Stable, contract-safe error descriptions for persisted job state."""

from __future__ import annotations


def exception_message(exc: BaseException, fallback: str = "operation failed") -> str:
    """Describe an exception without ever returning an empty contract value."""
    message = str(exc).strip()
    if message:
        return message
    name = type(exc).__name__.strip()
    if name and name not in {"Exception", "BaseException"}:
        return name
    return fallback
