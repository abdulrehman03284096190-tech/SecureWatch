"""Best-effort local system metrics and process snapshots."""
from __future__ import annotations

import getpass
import platform
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil


def collect_system_metrics() -> dict[str, Any]:
    memory = psutil.virtual_memory()
    root = Path.home().anchor or ("C:\\" if platform.system() == "Windows" else "/")
    try:
        disk_percent = psutil.disk_usage(root).percent
        disk_error = None
    except (OSError, PermissionError) as exc:
        disk_percent = None
        disk_error = str(exc)
    boot = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc).astimezone()
    return {
        "computer": platform.node() or "Unavailable",
        "os": f"{platform.system()} {platform.release()}",
        "username": getpass.getuser() or "Unavailable",
        "uptime_seconds": max(0, int(time.time() - psutil.boot_time())),
        "boot_time": boot.isoformat(timespec="seconds"),
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory_percent": memory.percent,
        "memory_total_bytes": memory.total,
        "memory_available_bytes": memory.available,
        "disk_percent": disk_percent,
        "disk_error": disk_error,
        "process_count": len(psutil.pids()),
        "sampled_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }


def collect_processes() -> list[dict[str, Any]]:
    fields = ("pid", "name", "memory_percent", "memory_info", "status",
              "create_time", "exe", "username")
    rows: list[dict[str, Any]] = []
    for process in psutil.process_iter(fields):
        try:
            info = process.info
            create_time = info.get("create_time")
            rows.append({
                "pid": info.get("pid"),
                "name": info.get("name") or "Unavailable",
                "cpu_percent": process.cpu_percent(interval=None),
                "memory_percent": info.get("memory_percent") or 0.0,
                "memory_bytes": getattr(info.get("memory_info"), "rss", 0),
                "status": info.get("status") or "Unavailable",
                "start_time": (datetime.fromtimestamp(create_time).astimezone().isoformat()
                               if create_time else "Unavailable"),
                "path": info.get("exe") or "Unavailable",
                "username": info.get("username") or "Unavailable",
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return rows
