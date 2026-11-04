"""Cancellation and progress for the tool call running on this thread.

The SDK runs each (sync) tool on a worker thread. When the client cancels the request
(``notifications/cancelled``, a timeout, the user pressing Escape) the host task is
cancelled, but the thread keeps going until it looks: the runner polls
:func:`cancelled` while tshark runs and kills it, then raises :class:`Cancelled`, a
``BaseException`` so no ``except Exception`` or ``except ToolError`` in a tool keeps
working on a request nobody waits for.

Progress goes to the client only when it asked for it (a ``progressToken``): one
notification per finished tshark run and per file of a multi-file call, at most one per
second apart from the last, always increasing. Outside a request (unit tests, in-process
calls) both are no-ops.
"""

from __future__ import annotations

import threading
import time
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from typing import Any

MIN_INTERVAL_SECONDS = 1.0


class Cancelled(BaseException):
    """The client cancelled the request; tshark was killed and nothing is returned."""


def cancelled() -> bool:
    """True when this thread runs a tool call whose request was cancelled."""
    try:
        import anyio.from_thread
        anyio.from_thread.check_cancelled()
    except RuntimeError:
        return False  # not an AnyIO worker thread: nothing can cancel it
    except BaseException:  # noqa: BLE001 - the backend's cancellation exception
        return True
    return False


def raise_if_cancelled() -> None:
    if cancelled():
        raise Cancelled()


@dataclass
class _Reporter:
    ctx: Any
    sent: float = 0.0
    last_at: float = 0.0
    runs: int = 0
    total: float | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def send(self, value: float, total: float | None, message: str | None, final: bool) -> bool:
        with self.lock:
            now = time.monotonic()
            if value <= self.sent or (not final and now - self.last_at < MIN_INTERVAL_SECONDS):
                return False
            self.sent, self.last_at = value, now
        try:
            import anyio.from_thread
            anyio.from_thread.run(self.ctx.report_progress, value, total, message)
        except BaseException:  # noqa: BLE001 - progress is best effort, never fails a call
            return False
        return True


_REPORTER: ContextVar[_Reporter | None] = ContextVar("tshark_mcp_progress", default=None)


def bind(ctx: Any) -> Token:
    """Report progress for this call to ``ctx`` (an SDK Context, or None for no reporting)."""
    return _REPORTER.set(_Reporter(ctx) if ctx is not None and hasattr(ctx, "report_progress") else None)


def unbind(token: Token) -> None:
    _REPORTER.reset(token)


def report(done: float, total: float | None = None, message: str | None = None, *, final: bool = False) -> bool:
    """Report ``done`` of ``total`` (rate-limited, strictly increasing); True when sent."""
    reporter = _REPORTER.get()
    if reporter is None:
        return False
    if total is not None:
        reporter.total = total
    return reporter.send(float(done), reporter.total if total is None else total, message, final)


def run_finished(duration_ms: int) -> None:
    """Called by the runner after each child exits: a sign of life for calls without their own steps."""
    reporter = _REPORTER.get()
    if reporter is None or reporter.total is not None:
        return
    reporter.runs += 1
    reporter.send(float(reporter.runs), None, f"tshark run {reporter.runs} finished in {duration_ms} ms", False)
