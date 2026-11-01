"""Sliding-window rate limiting per (agent, tool).

Caps the blast radius of a looping or hijacked agent: even an allowed tool cannot be
called a thousand times a minute.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable


class RateLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._calls: defaultdict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check_and_record(self, agent_id: str, tool: str, max_calls: int, per_seconds: int) -> bool:
        """Record a call and return True, or return False if it would exceed the limit."""
        now = self._clock()
        key = (agent_id, tool)
        with self._lock:
            window = self._calls[key]
            while window and window[0] <= now - per_seconds:
                window.popleft()
            if len(window) >= max_calls:
                return False
            window.append(now)
            return True
