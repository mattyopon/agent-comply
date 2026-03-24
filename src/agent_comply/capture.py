# Copyright (c) 2025-2026 Yutaro Maeda. All rights reserved.
# Licensed under the Business Source License 1.1. See LICENSE file for details.

"""Event capture SDK — decorator-based audit trail for agent function calls.

Captures inputs, outputs, tool calls, decisions, and timestamps with minimal
performance overhead.  Works with both sync and async callables.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, TypeVar

from pydantic import BaseModel, Field

from agent_comply.ledger import EventLedger, LedgerEvent

F = TypeVar("F", bound=Callable[..., Any])

# ── Context variable for the active audit session ──────────────────────
_active_context: ContextVar["AuditContext | None"] = ContextVar(
    "_active_context", default=None
)


class CapturedEvent(BaseModel):
    """A single captured event from a decorated function."""

    event_id: str = Field(default_factory=lambda: f"EVT-{uuid.uuid4().hex[:12]}")
    session_id: str = ""
    agent_id: str = ""
    function_name: str = ""
    module: str = ""
    event_type: str = "function_call"
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    inputs: dict[str, Any] = Field(default_factory=dict)
    output: Any = None
    error: str | None = None
    duration_ms: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)
    parent_event_id: str | None = None


@dataclass
class AuditContext:
    """Manages an auditing session — every decorated call within this context
    is recorded to the configured ledger."""

    agent_id: str = "default-agent"
    session_id: str = field(default_factory=lambda: f"SES-{uuid.uuid4().hex[:12]}")
    ledger: EventLedger = field(default_factory=EventLedger)
    events: list[CapturedEvent] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    _token: Any = field(default=None, repr=False)

    # ── context-manager protocol ───────────────────────────────────────
    def __enter__(self) -> "AuditContext":
        self._token = _active_context.set(self)
        return self

    def __exit__(self, *_: Any) -> None:
        _active_context.reset(self._token)

    async def __aenter__(self) -> "AuditContext":
        return self.__enter__()

    async def __aexit__(self, *_: Any) -> None:
        self.__exit__()

    # ── public helpers ─────────────────────────────────────────────────
    def record(self, event: CapturedEvent) -> LedgerEvent:
        """Persist a captured event to both the in-memory list and the ledger."""
        event.session_id = self.session_id
        event.agent_id = self.agent_id
        self.events.append(event)
        return self.ledger.append(event.model_dump())

    def get_events(self) -> list[CapturedEvent]:
        return list(self.events)


def get_current_context() -> AuditContext | None:
    """Return the active AuditContext if one exists."""
    return _active_context.get(None)


# ── @audit decorator ──────────────────────────────────────────────────
def audit(
    func: F | None = None,
    *,
    event_type: str = "function_call",
    capture_output: bool = True,
    metadata: dict[str, Any] | None = None,
) -> F | Callable[[F], F]:
    """Decorator that transparently captures every invocation of *func*.

    Usage::

        @audit
        def search(query: str) -> list[str]:
            ...

        @audit(event_type="tool_call", metadata={"tool": "web_search"})
        async def web_search(url: str) -> str:
            ...
    """

    def decorator(fn: F) -> F:
        _meta = metadata or {}

        @functools.wraps(fn)
        def _sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            ctx = _active_context.get(None)
            sig = inspect.signature(fn)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            inputs = {
                k: _safe_serialize(v) for k, v in bound.arguments.items()
            }

            start = time.perf_counter_ns()
            error: str | None = None
            output: Any = None
            try:
                output = fn(*args, **kwargs)
                return output
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                raise
            finally:
                elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
                ev = CapturedEvent(
                    function_name=fn.__qualname__,
                    module=fn.__module__,
                    event_type=event_type,
                    inputs=inputs,
                    output=_safe_serialize(output) if capture_output else None,
                    error=error,
                    duration_ms=round(elapsed_ms, 3),
                    metadata=_meta,
                )
                if ctx is not None:
                    ctx.record(ev)

        @functools.wraps(fn)
        async def _async_wrapper(*args: Any, **kwargs: Any) -> Any:
            ctx = _active_context.get(None)
            sig = inspect.signature(fn)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            inputs = {
                k: _safe_serialize(v) for k, v in bound.arguments.items()
            }

            start = time.perf_counter_ns()
            error: str | None = None
            output: Any = None
            try:
                output = await fn(*args, **kwargs)
                return output
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                raise
            finally:
                elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
                ev = CapturedEvent(
                    function_name=fn.__qualname__,
                    module=fn.__module__,
                    event_type=event_type,
                    inputs=inputs,
                    output=_safe_serialize(output) if capture_output else None,
                    error=error,
                    duration_ms=round(elapsed_ms, 3),
                    metadata=_meta,
                )
                if ctx is not None:
                    ctx.record(ev)

        if asyncio.iscoroutinefunction(fn):
            return _async_wrapper  # type: ignore[return-value]
        return _sync_wrapper  # type: ignore[return-value]

    if func is not None:
        return decorator(func)
    return decorator  # type: ignore[return-value]


# ── helpers ────────────────────────────────────────────────────────────
def _safe_serialize(value: Any, *, depth: int = 0, max_depth: int = 4) -> Any:
    """Best-effort JSON-safe serialisation of arbitrary values."""
    if depth > max_depth:
        return repr(value)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (list, tuple)):
        return [_safe_serialize(v, depth=depth + 1) for v in value]
    if isinstance(value, dict):
        return {
            str(k): _safe_serialize(v, depth=depth + 1) for k, v in value.items()
        }
    if isinstance(value, BaseModel):
        return value.model_dump()
    return repr(value)
