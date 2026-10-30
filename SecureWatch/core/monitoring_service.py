"""Single-worker periodic monitoring with explicit lifecycle controls."""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class MonitoringService:
    def __init__(
        self,
        interval_seconds: int,
        cycle: Callable[[], Any],
        on_result: Callable[[Any], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ):
        if not 5 <= interval_seconds <= 3600:
            raise ValueError("Monitoring interval must be between 5 and 3600 seconds.")
        self._interval = interval_seconds
        self._cycle = cycle
        self._on_result = on_result
        self._on_error = on_error
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._paused = threading.Event()
        self._lock = threading.Lock()
        self._last_error: str | None = None
        self._last_result: Any = None

    @property
    def status(self) -> str:
        if self._stop.is_set():
            return "Stopped"
        if self._thread is None or not self._thread.is_alive():
            return "Stopped"
        return "Paused" if self._paused.is_set() else "Monitoring"

    @property
    def last_result(self) -> Any:
        with self._lock:
            return self._last_result

    @property
    def last_error(self) -> str | None:
        with self._lock:
            return self._last_error

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            self.resume()
            return
        self._stop.clear()
        self._paused.clear()
        self._thread = threading.Thread(
            target=self._run, name="SecureWatchMonitor", daemon=True,
        )
        self._thread.start()

    def pause(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            self._paused.set()
            self._wake.set()

    def resume(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            self._paused.clear()
            self._wake.set()

    def update_interval(self, interval_seconds: int) -> None:
        if not 5 <= interval_seconds <= 3600:
            raise ValueError("Monitoring interval must be between 5 and 3600 seconds.")
        self._interval = interval_seconds
        self._wake.set()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=max(0.0, timeout))
            if self._thread.is_alive():
                raise TimeoutError("Monitoring worker did not stop before the timeout.")

    def _run(self) -> None:
        while not self._stop.is_set():
            if self._paused.is_set():
                self._wake.wait()
                self._wake.clear()
                continue
            try:
                result = self._cycle()
                with self._lock:
                    self._last_result = result
                    self._last_error = None
                if self._on_result:
                    self._on_result(result)
            except Exception as exc:
                logger.exception("Monitoring cycle failed")
                with self._lock:
                    self._last_error = str(exc)
                if self._on_error:
                    self._on_error(exc)
            self._wake.wait(self._interval)
            self._wake.clear()
