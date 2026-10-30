"""Read-only network connection snapshots."""
from __future__ import annotations

import socket
from typing import Any

import psutil


def collect_interface_addresses() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for interface, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family == socket.AF_INET:
                family = "IPv4"
            elif address.family == socket.AF_INET6:
                family = "IPv6"
            else:
                continue
            rows.append({
                "interface": interface,
                "family": family,
                "address": address.address.split("%", 1)[0],
                "netmask": address.netmask or "",
            })
    return rows


def collect_connections() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for connection in psutil.net_connections(kind="inet"):
        try:
            process_name = psutil.Process(connection.pid).name() if connection.pid else "Unavailable"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            process_name = "Unavailable"
        local = connection.laddr
        remote = connection.raddr
        rows.append({
            "pid": connection.pid,
            "process": process_name,
            "local_ip": local.ip if local else "",
            "local_port": local.port if local else "",
            "remote_ip": remote.ip if remote else "",
            "remote_port": remote.port if remote else "",
            "status": connection.status,
            "type": "TCP" if connection.type == 1 else "UDP",
        })
    return rows
