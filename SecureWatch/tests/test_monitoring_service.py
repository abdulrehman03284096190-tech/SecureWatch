import threading
import time

from core.monitoring_service import MonitoringService


def test_monitoring_service_starts_pauses_resumes_and_stops():
    calls = []
    called = threading.Event()

    def cycle():
        calls.append(len(calls) + 1)
        called.set()
        return calls[-1]

    service = MonitoringService(5, cycle)
    service.start()
    assert called.wait(2)
    assert service.status == "Monitoring"
    service.pause()
    assert service.status == "Paused"
    count = len(calls)
    time.sleep(0.05)
    assert len(calls) == count
    service.resume()
    service.stop()
    assert service.status == "Stopped"


def test_monitoring_interval_is_bounded():
    try:
        MonitoringService(1, lambda: None)
    except ValueError as exc:
        assert "between 5 and 3600" in str(exc)
    else:
        raise AssertionError("Expected invalid interval to fail.")
