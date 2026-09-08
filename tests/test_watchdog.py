"""Watchdog: trip-once semantics, threaded loop, reset, and on_trip errors."""

from __future__ import annotations

import time

from reforge.core.watchdog import Watchdog


def test_should_trip_only_when_silent_and_not_yet_tripped():
    wd = Watchdog(heartbeat_age=lambda: 5.0, timeout=1.0, on_trip=lambda: None)
    assert wd.should_trip() is True
    wd.tripped = True
    assert wd.should_trip() is False              # never trips twice


def test_check_once_trips_exactly_once():
    calls = []
    wd = Watchdog(heartbeat_age=lambda: 9.0, timeout=1.0, on_trip=lambda: calls.append(1))
    wd._check_once(); wd._check_once()
    assert calls == [1] and wd.tripped is True


def test_on_trip_exception_is_swallowed():
    def boom():
        raise RuntimeError("fail policy blew up")
    wd = Watchdog(heartbeat_age=lambda: 9.0, timeout=1.0, on_trip=boom)
    wd._check_once()                              # must not raise
    assert wd.tripped is True


def test_reset_allows_retrip():
    calls = []
    wd = Watchdog(heartbeat_age=lambda: 9.0, timeout=1.0, on_trip=lambda: calls.append(1))
    wd._check_once()
    wd.reset()
    assert wd.tripped is False
    wd._check_once()
    assert calls == [1, 1]


def test_threaded_loop_trips_then_stops():
    age = [0.0]
    calls = []
    wd = Watchdog(heartbeat_age=lambda: age[0], timeout=0.2,
                  on_trip=lambda: calls.append(1), poll_interval=0.02)
    wd.start()
    try:
        time.sleep(0.1)
        assert calls == []                        # healthy so far
        age[0] = 5.0                              # loop goes silent
        end = time.time() + 1.0
        while time.time() < end and not calls:
            time.sleep(0.02)
        assert calls == [1]
    finally:
        wd.stop()
    assert wd._thread is None
