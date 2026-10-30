"""
SecureWatch - Windows Security & Monitoring System
Defensive Windows monitoring application. Requires Python 3.11 or newer.
"""
from __future__ import annotations

import csv
import json
import os
import platform
import queue
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

try:
    import customtkinter as ctk  # type: ignore[reportMissingImports]
except ImportError:
    raise SystemExit("Missing dependencies. Run: python -m pip install -r requirements.txt")

try:
    import psutil  # type: ignore[reportMissingModuleSource]
except ImportError:
    raise SystemExit("Missing psutil. Run: python -m pip install -r requirements.txt")

from core.detection_engine import DetectionEngine
from core.defender_manager import (
    get_defender_detections,
    get_defender_status,
    request_scan,
)
from core.event_collector import collect_events
from core.file_analyzer import analyze_file, iter_directory
from core.monitoring_service import MonitoringService
from core.network_collector import collect_connections, collect_interface_addresses
from core.system_info import collect_processes, collect_system_metrics
from database.db_manager import DatabaseManager
from reporting.csv_export import export_csv
from reporting.pdf_report import generate_pdf_report
from utils.logging_config import configure_logging
from utils.validation import load_settings, save_settings, validate_settings
from utils.windows_permissions import (
    is_running_as_administrator,
    request_administrator_relaunch,
)

APP_NAME = "SecureWatch"
APP_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SecureWatch"
APP_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = APP_DIR / "securewatch.db"
LOG_PATH = APP_DIR / "securewatch.log"
SETTINGS_PATH = APP_DIR / "settings.json"
logger = configure_logging(LOG_PATH)

try:
    settings = load_settings(SETTINGS_PATH if SETTINGS_PATH.exists()
                             else Path(__file__).with_name("config.json"))
    save_settings(SETTINGS_PATH, settings)
except (OSError, ValueError) as exc:
    logger.exception("Could not load application settings")
    raise SystemExit(f"SecureWatch settings could not be loaded: {exc}")


def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Store(DatabaseManager):
    def __init__(self, path=DB_PATH):
        super().__init__(path)

    def add_alert(self, severity, title, details, source="SecureWatch"):
        return self.create_alert(severity, title, details, source)

    def add_scan(self, path, size, sha256, extension="", modified_at="",
                 result="No local indicator match"):
        return self.add_file_scan(path, size, sha256, extension, modified_at, result)


store = Store()


def tree(parent, columns, headings=None, height=16):
    frame = ttk.Frame(parent)
    frame.pack(fill="both", expand=True, padx=10, pady=10)
    widget = ttk.Treeview(frame, columns=columns, show="headings", height=height)
    for col in columns:
        widget.heading(col, text=(headings or {}).get(col, col.replace("_", " ").title()))
        widget.column(col, width=150, anchor="w")
    ybar = ttk.Scrollbar(frame, orient="vertical", command=widget.yview)
    xbar = ttk.Scrollbar(frame, orient="horizontal", command=widget.xview)
    widget.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
    widget.grid(row=0, column=0, sticky="nsew")
    ybar.grid(row=0, column=1, sticky="ns")
    xbar.grid(row=1, column=0, sticky="ew")
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)
    return widget


def clear_tree(widget):
    for item in widget.get_children():
        widget.delete(item)


class SecureWatchApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self._saved_retention_days = settings["log_retention_days"]
        self.title("SecureWatch — Windows Security & Monitoring System")
        self.geometry("1280x800")
        self.minsize(980, 650)
        ctk.set_appearance_mode(settings["appearance"])
        ctk.set_default_color_theme("blue")
        self.event_queue = queue.Queue()
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="SecureWatch")
        self.job_lock = threading.Lock()
        self.active_jobs = set()
        self.process_rows = []
        self.network_rows = []
        self.file_cancel = threading.Event()
        self.is_admin = is_running_as_administrator()
        self.detection_engine = DetectionEngine(
            store,
            cooldown_seconds=settings["alert_cooldown_seconds"],
            failed_logon_threshold=settings["failed_logon_threshold"],
            error_threshold=settings["security_error_threshold"],
            event_window_minutes=settings["event_window_minutes"],
            cpu_threshold_percent=settings["cpu_threshold_percent"],
            ram_threshold_percent=settings["ram_threshold_percent"],
            resource_observation_count=settings["resource_observation_count"],
            expected_listening_ports=settings["expected_listening_ports"],
        )
        self.monitor = MonitoringService(
            settings["monitoring_interval_seconds"],
            self._monitor_cycle,
            on_result=lambda result: self.event_queue.put(("monitor_cycle", result)),
            on_error=lambda exc: self.event_queue.put(("monitor_error", str(exc))),
        )
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.refresh_dashboard()
        self.refresh_processes()
        self.refresh_network()
        self.refresh_alerts()
        self.after(250, self._poll_queue)
        self.after(5000, self._periodic_refresh)

    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        sidebar = ctk.CTkFrame(self, width=205, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsw")
        sidebar.grid_propagate(False)
        ctk.CTkLabel(sidebar, text="SECUREWATCH", font=ctk.CTkFont(size=22, weight="bold")).pack(padx=16, pady=(24, 2))
        ctk.CTkLabel(sidebar, text="Windows Security Monitor", text_color="#9ca3af").pack(padx=12, pady=(0, 22))
        self.tabs = ctk.CTkTabview(self, corner_radius=12)
        self.tabs.grid(row=0, column=1, sticky="nsew", padx=12, pady=12)
        names = ["Dashboard", "Task Manager", "Event Viewer", "Antivirus", "File Scanner", "Network", "Alerts", "Settings"]
        for name in names:
            self.tabs.add(name)
            ctk.CTkButton(sidebar, text=name, anchor="w", command=lambda n=name: self.tabs.set(n)).pack(fill="x", padx=12, pady=5)
        ctk.CTkLabel(sidebar, text="Ch Abdul Rehman Bajwa\n+92 328 4096190", text_color="#9ca3af", justify="left").pack(side="bottom", padx=12, pady=18)

        self._build_dashboard()
        self._build_processes()
        self._build_events()
        self._build_defender()
        self._build_file_scanner()
        self._build_network()
        self._build_alerts_tab()
        self._build_settings_tab()

    def _build_dashboard(self):
        tab = self.tabs.tab("Dashboard")
        ctk.CTkLabel(tab, text="Security Overview", font=ctk.CTkFont(size=26, weight="bold")).pack(anchor="w", padx=18, pady=(18, 8))
        ctk.CTkLabel(
            tab,
            text="Unified Endpoint Monitoring, Threat Detection, and Security Analysis.",
            anchor="w", text_color="#9ca3af",
        ).pack(anchor="w", padx=18, pady=(0, 4))
        self.sys_label = ctk.CTkLabel(tab, text="", justify="left", anchor="w")
        self.sys_label.pack(fill="x", padx=18, pady=8)
        self.monitor_status = ctk.CTkLabel(
            tab, text="Monitoring stopped (periodic polling is not real-time).",
            text_color="#fbbf24", anchor="w",
        )
        self.monitor_status.pack(fill="x", padx=18, pady=4)
        self.security_summary = ctk.CTkLabel(
            tab, text="Defender status: Unavailable / not queried | Alerts: 0 | Recent stored events: 0",
            text_color="#d1d5db", anchor="w",
        )
        self.security_summary.pack(fill="x", padx=18, pady=4)
        self.recent_events_label = ctk.CTkLabel(
            tab, text="Recent stored events will appear after an Event Viewer query.",
            text_color="#9ca3af", anchor="w", justify="left", wraplength=950,
        )
        self.recent_events_label.pack(fill="x", padx=18, pady=4)
        permission_row = ctk.CTkFrame(tab)
        permission_row.pack(fill="x", padx=14, pady=4)
        self.permission_status = ctk.CTkLabel(
            permission_row,
            text=("Administrator permissions active." if self.is_admin
                  else "Standard user: some Windows logs or process details may be restricted."),
            text_color="#86efac" if self.is_admin else "#fbbf24",
            anchor="w",
        )
        self.permission_status.pack(side="left", fill="x", expand=True, padx=8, pady=6)
        if not self.is_admin:
            ctk.CTkButton(
                permission_row,
                text="Relaunch as Administrator",
                command=self.relaunch_as_administrator,
            ).pack(side="right", padx=8, pady=6)
        cards = ctk.CTkFrame(tab)
        cards.pack(fill="x", padx=14, pady=10)
        self.metric_labels = {}
        for key in ("CPU", "Memory", "Disk", "Processes"):
            card = ctk.CTkFrame(cards)
            card.pack(side="left", fill="both", expand=True, padx=6, pady=8)
            ctk.CTkLabel(card, text=key, font=ctk.CTkFont(size=14)).pack(pady=(12, 3))
            val = ctk.CTkLabel(card, text="--", font=ctk.CTkFont(size=24, weight="bold"))
            val.pack(pady=(0, 12))
            self.metric_labels[key] = val
        actions = ctk.CTkFrame(tab)
        actions.pack(fill="x", padx=18, pady=4)
        ctk.CTkButton(actions, text="Refresh Dashboard", command=self.refresh_dashboard).pack(side="left", padx=5, pady=6)
        ctk.CTkButton(actions, text="Check Defender", command=self.check_defender).pack(side="left", padx=5, pady=6)
        ctk.CTkButton(actions, text="Load Recent Events", command=self.load_events).pack(side="left", padx=5, pady=6)
        monitoring = ctk.CTkFrame(tab)
        monitoring.pack(fill="x", padx=18, pady=4)
        ctk.CTkLabel(monitoring, text="Periodic security monitoring:").pack(side="left", padx=8, pady=6)
        ctk.CTkButton(monitoring, text="Start", command=self.start_monitoring).pack(side="left", padx=4, pady=6)
        ctk.CTkButton(monitoring, text="Pause", command=self.pause_monitoring).pack(side="left", padx=4, pady=6)
        ctk.CTkButton(monitoring, text="Resume", command=self.resume_monitoring).pack(side="left", padx=4, pady=6)
        ctk.CTkButton(monitoring, text="Stop", command=self.stop_monitoring).pack(side="left", padx=4, pady=6)
        ctk.CTkLabel(tab, text=f"Local database: {DB_PATH}", text_color="#9ca3af").pack(anchor="w", padx=18, pady=8)

    def _build_processes(self):
        tab = self.tabs.tab("Task Manager")
        bar = ctk.CTkFrame(tab)
        bar.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(bar, text="Running processes", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left", padx=10, pady=10)
        self.process_search = tk.StringVar()
        ctk.CTkEntry(bar, textvariable=self.process_search, placeholder_text="Search name or PID", width=190).pack(side="left", padx=5)
        self.process_search.trace_add("write", lambda *_: self._render_processes())
        self.process_sort = tk.StringVar(value="Memory")
        ttk.Combobox(bar, textvariable=self.process_sort, values=["Memory", "CPU"], state="readonly", width=9).pack(side="left", padx=5)
        self.process_sort.trace_add("write", lambda *_: self._render_processes())
        ctk.CTkButton(bar, text="Refresh", command=self.refresh_processes).pack(side="right", padx=8, pady=8)
        ctk.CTkButton(bar, text="Export CSV", command=self.export_processes).pack(side="right", padx=8, pady=8)
        self.process_tree = tree(tab, ("pid", "name", "cpu", "memory", "memory_bytes", "status", "started", "path", "username"),
                                 {"pid": "PID", "name": "Process", "cpu": "CPU %", "memory": "Memory %", "memory_bytes": "Memory bytes", "status": "Status", "started": "Start time", "path": "Executable path", "username": "User"})
        self.process_tree.bind("<<TreeviewSelect>>", self._show_process_details)
        self.process_detail = ctk.CTkLabel(tab, text="Select a process to view details.", anchor="w", justify="left")
        self.process_detail.pack(fill="x", padx=16, pady=(0, 8))
        ctk.CTkLabel(tab, text="Read-only process view. Protected/system processes are not terminated by this app.", text_color="#9ca3af").pack(anchor="w", padx=16, pady=(0, 8))

    def _build_events(self):
        tab = self.tabs.tab("Event Viewer")
        heading = ctk.CTkFrame(tab)
        heading.pack(fill="x", padx=10, pady=(10, 4))
        ctk.CTkLabel(heading, text="Windows Event Logs", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left", padx=10, pady=8)
        ctk.CTkButton(heading, text="Export CSV", command=self.export_events).pack(side="right", padx=4, pady=6)
        ctk.CTkButton(heading, text="Load latest", command=self.load_events).pack(side="right", padx=4, pady=6)
        filters = ctk.CTkFrame(tab)
        filters.pack(fill="x", padx=10, pady=3)
        self.event_log_var = tk.StringVar(value="System")
        ttk.Combobox(filters, textvariable=self.event_log_var, values=["System", "Application", "Security"], state="readonly", width=15).pack(side="left", padx=6)
        self.event_id_var = tk.StringVar()
        ctk.CTkEntry(filters, textvariable=self.event_id_var, placeholder_text="Event ID", width=90).pack(side="left", padx=4)
        self.event_severity_var = tk.StringVar(value="All")
        ttk.Combobox(filters, textvariable=self.event_severity_var, values=["All", "Error", "Warning", "Information", "Critical"], state="readonly", width=13).pack(side="left", padx=4)
        self.event_search_var = tk.StringVar()
        ctk.CTkEntry(filters, textvariable=self.event_search_var, placeholder_text="Search event text", width=160).pack(side="left", padx=4)
        date_filters = ctk.CTkFrame(tab)
        date_filters.pack(fill="x", padx=10, pady=3)
        self.event_from_var = tk.StringVar()
        self.event_to_var = tk.StringVar()
        ctk.CTkEntry(date_filters, textvariable=self.event_from_var, placeholder_text="From YYYY-MM-DD", width=150).pack(side="left", padx=6)
        ctk.CTkEntry(date_filters, textvariable=self.event_to_var, placeholder_text="To YYYY-MM-DD", width=150).pack(side="left", padx=4)
        self.event_date_range = (None, None)
        ctk.CTkButton(date_filters, text="Apply dates", command=self.apply_event_date_filter).pack(side="left", padx=4)
        ctk.CTkLabel(tab, text="Security log access may require running VS Code / SecureWatch as Administrator. Empty results do not prove that logging is broken.", text_color="#9ca3af", wraplength=900).pack(anchor="w", padx=16)
        self.events_tree = tree(tab, ("time", "id", "log", "level", "provider", "message"),
                                {"time": "Time", "id": "Event ID", "log": "Log", "level": "Level", "provider": "Provider", "message": "Message"})
        self.events_tree.column("message", width=550)
        self.event_rows = []

    def _build_defender(self):
        tab = self.tabs.tab("Antivirus")
        ctk.CTkLabel(tab, text="Microsoft Defender Center", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", padx=18, pady=(18, 8))
        ctk.CTkLabel(tab, text="This module queries Defender where available and requests scans. It does not replace antivirus protection.", wraplength=850, text_color="#9ca3af").pack(anchor="w", padx=18, pady=4)
        row = ctk.CTkFrame(tab)
        row.pack(fill="x", padx=18, pady=12)
        ctk.CTkButton(row, text="Check Protection Status", command=self.check_defender).pack(side="left", padx=8, pady=10)
        ctk.CTkButton(row, text="View Threat History", command=self.load_defender_history).pack(side="left", padx=8, pady=10)
        ctk.CTkButton(row, text="Quick Scan", command=lambda: self.start_defender_scan("QuickScan")).pack(side="left", padx=8, pady=10)
        ctk.CTkButton(row, text="Full Scan", command=lambda: self.start_defender_scan("FullScan")).pack(side="left", padx=8, pady=10)
        ctk.CTkButton(row, text="Custom Scan", command=self.custom_defender_scan).pack(side="left", padx=8, pady=10)
        self.defender_text = ctk.CTkTextbox(tab, height=400)
        self.defender_text.pack(fill="both", expand=True, padx=18, pady=10)
        self.defender_text.insert("end", "Click 'Check Protection Status' to query Microsoft Defender.\n")

    def _build_file_scanner(self):
        tab = self.tabs.tab("File Scanner")
        ctk.CTkLabel(tab, text="File Hash & Metadata Scanner", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", padx=18, pady=(18, 8))
        ctk.CTkLabel(tab, text="Calculates SHA-256 locally. A hash alone does not determine whether a file is malicious.", text_color="#9ca3af").pack(anchor="w", padx=18)
        actions = ctk.CTkFrame(tab)
        actions.pack(fill="x", padx=18, pady=4)
        ctk.CTkButton(actions, text="Choose File and Calculate SHA-256", command=self.scan_file).pack(side="left", padx=6, pady=6)
        ctk.CTkButton(actions, text="Scan Directory", command=self.scan_directory).pack(side="left", padx=6, pady=6)
        ctk.CTkButton(actions, text="Cancel Directory Scan", command=self.cancel_directory_scan).pack(side="left", padx=6, pady=6)
        ctk.CTkButton(actions, text="Export Scan History CSV", command=self.export_file_scans).pack(side="left", padx=6, pady=6)
        self.file_text = ctk.CTkTextbox(tab, height=400)
        self.file_text.pack(fill="both", expand=True, padx=18, pady=10)
        self.file_progress = ctk.CTkProgressBar(tab, mode="indeterminate")
        self.file_progress.pack(fill="x", padx=18, pady=(0, 10))
        self.file_progress.stop()

    def _build_network(self):
        tab = self.tabs.tab("Network")
        bar = ctk.CTkFrame(tab)
        bar.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(bar, text="Active Network Connections", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left", padx=10, pady=10)
        ctk.CTkButton(bar, text="Refresh", command=self.refresh_network).pack(side="right", padx=8, pady=8)
        self.network_filter = tk.StringVar()
        ctk.CTkEntry(bar, textvariable=self.network_filter, placeholder_text="Filter process / remote IP / state", width=240).pack(side="left", padx=8)
        self.network_filter.trace_add("write", lambda *_: self._render_network())
        ctk.CTkButton(bar, text="Export CSV", command=self.export_network).pack(side="right", padx=8, pady=8)
        self.network_addresses_label = ctk.CTkLabel(
            tab, text="Local interface addresses: loading...", anchor="w", justify="left"
        )
        self.network_addresses_label.pack(fill="x", padx=16, pady=(0, 4))
        self.network_tree = tree(tab, ("pid", "process", "local", "remote", "status"),
                                 {"pid": "PID", "process": "Process", "local": "Local endpoint", "remote": "Remote endpoint", "status": "Status"})
        ctk.CTkLabel(tab, text="Connection details may be unavailable without sufficient permissions. An unfamiliar connection is not automatically malicious.", text_color="#9ca3af").pack(anchor="w", padx=16, pady=(0, 8))

    def _build_alerts_tab(self):
        tab = self.tabs.tab("Alerts")
        ctk.CTkLabel(
            tab, text="Security Alerts & Reports",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(anchor="w", padx=20, pady=(12, 4))
        heading = ctk.CTkFrame(tab)
        heading.pack(fill="x", padx=10, pady=(10, 4))
        ctk.CTkButton(heading, text="Add Note", command=self.add_alert_note).pack(side="right", padx=4, pady=6)
        ctk.CTkButton(heading, text="Mark Reviewed", command=self.review_selected_alert).pack(side="right", padx=4, pady=6)
        ctk.CTkButton(heading, text="Refresh", command=self.refresh_alerts).pack(side="right", padx=4, pady=6)
        ctk.CTkButton(heading, text="Export CSV", command=self.export_alerts).pack(side="right", padx=4, pady=6)
        ctk.CTkButton(heading, text="Export PDF Report", command=self.export_pdf).pack(side="right", padx=4, pady=6)
        filters = ctk.CTkFrame(tab)
        filters.pack(fill="x", padx=10, pady=4)
        self.alert_severity_var = tk.StringVar(value="All")
        ttk.Combobox(filters, textvariable=self.alert_severity_var, values=["All", "Informational", "Low", "Medium", "High", "Critical"], state="readonly", width=13).pack(side="left", padx=5)
        self.alert_search_var = tk.StringVar()
        ctk.CTkEntry(filters, textvariable=self.alert_search_var, placeholder_text="Search alerts", width=180).pack(side="left", padx=5)
        self.alert_from_var = tk.StringVar()
        self.alert_to_var = tk.StringVar()
        ctk.CTkEntry(filters, textvariable=self.alert_from_var, placeholder_text="From YYYY-MM-DD", width=125).pack(side="left", padx=3)
        ctk.CTkEntry(filters, textvariable=self.alert_to_var, placeholder_text="To YYYY-MM-DD", width=125).pack(side="left", padx=3)
        self.alert_date_range = (None, None)
        ctk.CTkButton(filters, text="Apply dates", command=self.apply_alert_date_filter).pack(side="left", padx=3)
        self.alert_status = ctk.CTkLabel(tab, text="", anchor="w", text_color="#fca5a5")
        self.alert_status.pack(fill="x", padx=14, pady=2)
        self.alert_tree = tree(tab, ("id", "timestamp", "severity", "rule_id", "title", "status", "source"),
                               {"id": "ID", "timestamp": "Time", "severity": "Severity", "rule_id": "Rule", "title": "Alert", "status": "Status", "source": "Source"})
        self.alert_tree.bind("<<TreeviewSelect>>", self._show_alert_details)
        self.alert_detail = ctk.CTkTextbox(tab, height=100)
        self.alert_detail.pack(fill="x", padx=12, pady=8)
        self.alert_severity_var.trace_add("write", lambda *_: self.refresh_alerts())
        self.alert_search_var.trace_add("write", lambda *_: self.refresh_alerts())

    def _build_settings_tab(self):
        tab = self.tabs.tab("Settings")
        ctk.CTkLabel(tab, text="Monitoring and Detection Settings", font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w", padx=18, pady=(18, 10))
        form = ctk.CTkFrame(tab)
        form.pack(fill="x", padx=18, pady=10)
        fields = (
            ("monitoring_interval_seconds", "Monitoring interval (5–3600 seconds)"),
            ("alert_cooldown_seconds", "Alert cooldown (seconds)"),
            ("cpu_threshold_percent", "CPU threshold (%)"),
            ("ram_threshold_percent", "RAM threshold (%)"),
            ("resource_observation_count", "Sustained observations"),
            ("event_query_limit", "Event query limit (1–2000)"),
            ("failed_logon_threshold", "Failed logon threshold"),
            ("security_error_threshold", "Security error threshold"),
            ("event_window_minutes", "Event analysis window (minutes)"),
            ("log_retention_days", "Event/metric retention (days; alerts preserved)"),
        )
        self.setting_vars = {}
        for index, (key, label) in enumerate(fields):
            row, column = divmod(index, 2)
            ctk.CTkLabel(form, text=label).grid(row=row, column=column * 2, padx=8, pady=5, sticky="w")
            variable = tk.StringVar(value=str(settings[key]))
            ctk.CTkEntry(form, textvariable=variable, width=130).grid(row=row, column=column * 2 + 1, padx=8, pady=5, sticky="w")
            self.setting_vars[key] = variable
        ctk.CTkLabel(form, text="Default report directory").grid(row=5, column=0, padx=8, pady=8, sticky="w")
        self.report_directory_var = tk.StringVar(value=settings["report_directory"])
        ctk.CTkEntry(form, textvariable=self.report_directory_var, width=280).grid(row=5, column=1, padx=8, pady=8, sticky="w")
        ctk.CTkButton(form, text="Browse", command=self.choose_report_directory).grid(row=5, column=2, padx=8, pady=8)
        ctk.CTkLabel(form, text="Appearance").grid(row=6, column=0, padx=8, pady=8, sticky="w")
        self.appearance_var = tk.StringVar(value=settings["appearance"])
        ttk.Combobox(form, textvariable=self.appearance_var, values=["dark", "light", "system"], state="readonly", width=12).grid(row=6, column=1, padx=8, pady=8, sticky="w")
        ctk.CTkLabel(tab, text="Known SHA-256 indicators (one per line; use only verified local indicators):").pack(anchor="w", padx=18, pady=(12, 2))
        self.indicator_text = ctk.CTkTextbox(tab, height=120)
        self.indicator_text.pack(fill="x", padx=18, pady=6)
        self.indicator_text.insert("1.0", "\n".join(settings["known_hashes"]))
        ctk.CTkLabel(
            tab,
            text="Expected listening ports (comma-separated; ports outside this list alert; leave empty to disable listener alerts):",
        ).pack(anchor="w", padx=18, pady=(8, 2))
        self.expected_ports_var = tk.StringVar(
            value=", ".join(map(str, settings["expected_listening_ports"]))
        )
        ctk.CTkEntry(tab, textvariable=self.expected_ports_var).pack(fill="x", padx=18, pady=6)
        ctk.CTkButton(tab, text="Save and validate settings", command=self.save_app_settings).pack(anchor="w", padx=18, pady=12)
        self.settings_status = ctk.CTkLabel(tab, text=f"Settings stored locally: {SETTINGS_PATH}", anchor="w")
        self.settings_status.pack(fill="x", padx=18, pady=4)

    def refresh_dashboard(self):
        self._run_async("Refreshing system metrics...", self._dashboard_worker, "dashboard")

    def _dashboard_worker(self):
        try:
            metrics = collect_system_metrics()
            persisted_config = store.get_config()
            with store.connect() as connection:
                alert_count = connection.execute(
                    "SELECT COUNT(*) FROM alerts WHERE status='Open'"
                ).fetchone()[0]
                event_count = connection.execute(
                    """SELECT COUNT(*) FROM windows_events
                       WHERE datetime(timestamp) >= datetime('now','-24 hours')"""
                ).fetchone()[0]
                recent_events = connection.execute(
                    """SELECT timestamp,log_name,event_id,level,message
                       FROM windows_events ORDER BY id DESC LIMIT 3"""
                ).fetchall()
            metrics["open_alert_count"] = alert_count
            metrics["recent_event_count"] = event_count
            metrics["defender_status"] = persisted_config.get(
                "last_defender_status", "Unavailable / not queried"
            )
            metrics["defender_checked_at"] = persisted_config.get(
                "last_defender_status_checked_at", "Time not recorded"
            )
            metrics["recent_events"] = [
                f'{row["timestamp"]} | {row["log_name"]} {row["event_id"]} '
                f'({row["level"]}): {row["message"][:240]}'
                for row in recent_events
            ]
            self.event_queue.put(("dashboard", metrics))
        except Exception as exc:
            logger.exception("Dashboard metrics collection failed")
            self.event_queue.put(("dashboard_error", str(exc)))

    def refresh_processes(self):
        if not hasattr(self, "process_tree"):
            return
        self._run_async("Refreshing process list...", self._process_worker, "processes")

    def _process_worker(self):
        try:
            self.event_queue.put(("processes", collect_processes()))
        except Exception as exc:
            logger.exception("Process collection failed")
            self.event_queue.put(("processes_error", str(exc)))

    def _render_processes(self):
        if not hasattr(self, "process_tree"):
            return
        query = self.process_search.get().strip().lower()
        sort_by_cpu = self.process_sort.get() == "CPU"
        rows = [
            row for row in self.process_rows
            if not query or query in str(row["name"]).lower() or query in str(row["pid"])
        ]
        rows.sort(key=lambda row: float(row["cpu_percent"] if sort_by_cpu else row["memory_percent"]), reverse=True)
        clear_tree(self.process_tree)
        for row in rows:
            self.process_tree.insert(
                "", "end",
                values=(row["pid"], row["name"], f'{row["cpu_percent"]:.1f}',
                        f'{row["memory_percent"]:.2f}', row["memory_bytes"], row["status"],
                        row["start_time"], row["path"], row["username"]),
            )

    def _show_process_details(self, _event=None):
        selected = self.process_tree.selection()
        if not selected:
            return
        values = self.process_tree.item(selected[0], "values")
        self.process_detail.configure(
            text=(f"PID {values[0]} | {values[1]} | CPU {values[2]}% | "
                  f"Memory {values[3]}% ({values[4]} bytes)\n"
                  f"Start: {values[6]} | User: {values[8]} | Path: {values[7]}")
        )

    def export_processes(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")], initialfile="securewatch_processes.csv")
        if not path:
            return
        rows = [
            self.process_tree.item(item, "values")
            for item in self.process_tree.get_children()
        ]
        self._save_csv(
            path,
            ["PID", "Process", "CPU %", "Memory %", "Memory bytes", "Status",
             "Start time", "Executable path", "User"],
            rows,
        )

    def _save_csv(self, path, headers, rows):
        try:
            export_csv(path, headers, rows)
        except (OSError, csv.Error) as exc:
            logger.exception("Could not export CSV file: %s", path)
            messagebox.showerror("CSV export failed", str(exc))
            return
        messagebox.showinfo("Export complete", f"Saved:\n{path}")

    def load_events(self):
        log_name = self.event_log_var.get()
        if log_name not in {"System", "Application", "Security"}:
            messagebox.showerror("Event Viewer", "Unsupported event log.")
            return
        self.tabs.set("Event Viewer")
        self._run_async("Loading events...", lambda: self._event_worker(log_name), "events")

    def _event_worker(self, log_name):
        try:
            data = collect_events(log_name, settings["event_query_limit"])
            rows = []
            detection_events = []
            for item in data:
                msg = " ".join(str(item.get("Message") or "").split())
                rows.append((item.get("Time", ""), item.get("Id", ""), log_name,
                             item.get("LevelDisplayName", ""),
                             item.get("ProviderName", ""), msg[:1800]))
                detection_events.append(item)
            store.add_windows_events(log_name, data)
            self.detection_engine.analyze_events(detection_events)
            self.event_queue.put(("events", rows))
        except RuntimeError as exc:
            self.event_queue.put(("events_error", f"{log_name} log: {self._permission_hint(exc)}"))
        except (OSError, sqlite3.Error) as exc:
            logger.exception("Could not load or persist Windows events")
            self.event_queue.put(("events_error", f"{log_name} log operation failed: {exc}"))

    def _render_events(self):
        if not hasattr(self, "events_tree"):
            return
        event_id = self.event_id_var.get().strip()
        severity = self.event_severity_var.get()
        term = self.event_search_var.get().strip().lower()
        start_date, end_date = self.event_date_range
        clear_tree(self.events_tree)
        for row in self.event_rows:
            event_date = str(row[0])[:10]
            if start_date and event_date < start_date.isoformat():
                continue
            if end_date and event_date > end_date.isoformat():
                continue
            if event_id and str(row[1]) != event_id:
                continue
            if severity != "All" and str(row[3]).lower() != severity.lower():
                continue
            if term and term not in " ".join(map(str, row)).lower():
                continue
            self.events_tree.insert("", "end", values=row)

    def apply_event_date_filter(self):
        try:
            start_date = date.fromisoformat(self.event_from_var.get().strip()) if self.event_from_var.get().strip() else None
            end_date = date.fromisoformat(self.event_to_var.get().strip()) if self.event_to_var.get().strip() else None
            if start_date and end_date and start_date > end_date:
                raise ValueError("Start date must not be after end date.")
        except ValueError as exc:
            messagebox.showerror("Event Viewer date filter", str(exc))
            return
        self.event_date_range = (start_date, end_date)
        self._render_events()

    def export_events(self):
        if not self.event_rows:
            messagebox.showinfo("Event Viewer", "Load event records before exporting.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")],
            initialfile="securewatch_events.csv",
        )
        if not path:
            return
        self._save_csv(
            path, ["Time", "Event ID", "Log", "Level", "Provider", "Message"],
            [self.events_tree.item(item, "values")
             for item in self.events_tree.get_children()],
        )

    def check_defender(self):
        self.tabs.set("Antivirus")
        self._run_async("Checking Defender...", self._defender_worker, "defender_status")

    def _defender_worker(self):
        try:
            data = get_defender_status()
        except RuntimeError as exc:
            store.set_config("last_defender_status", f"Unavailable: {exc}")
            store.set_config("last_defender_status_checked_at", now_text())
            self.event_queue.put(("defender", "Unable to query Microsoft Defender:\n" + str(exc)))
            return
        text = "\n".join(f"{key}: {value}" for key, value in data.items())
        store.set_config("last_defender_status", json.dumps(data, ensure_ascii=False))
        store.set_config("last_defender_status_checked_at", now_text())
        self.event_queue.put(("defender", text))

    def load_defender_history(self):
        self.tabs.set("Antivirus")
        self._run_async(
            "Loading Defender threat history...",
            self._defender_history_worker,
            "defender_history",
        )

    def _defender_history_worker(self):
        try:
            detections = get_defender_detections()
            new_detections = store.add_defender_detections(detections)
            self.detection_engine.analyze_defender_detections(new_detections)
            self.event_queue.put(("defender_history", detections))
        except Exception as exc:
            logger.exception("Could not retrieve Microsoft Defender threat history")
            self.event_queue.put(("defender_history_error", str(exc)))

    def start_defender_scan(self, scan_type):
        if not messagebox.askyesno("Confirm scan", f"Request Microsoft Defender {scan_type}? A full scan may take a long time."):
            return
        self._run_async(
            f"Requesting {scan_type}...",
            lambda: self._scan_worker(scan_type),
            f"defender_scan_{scan_type}",
        )

    def custom_defender_scan(self):
        folder = filedialog.askdirectory(title="Choose folder for Defender custom scan")
        if not folder:
            return
        if not messagebox.askyesno("Confirm custom scan", f"Request Defender scan of:\n{folder}\n\nContinue?"):
            return
        self._run_async(
            "Requesting custom scan...",
            lambda: self._scan_worker("CustomScan", folder),
            "defender_scan_CustomScan",
        )

    def _scan_worker(self, scan_type, folder=None):
        try:
            result = request_scan(scan_type, folder)
            succeeded = True
        except (RuntimeError, ValueError) as exc:
            result = f"Failed: {exc}"
            succeeded = False
        store.add_action(f"Defender {scan_type}", result)
        if not succeeded:
            store.create_alert(
                "Medium", f"Defender {scan_type} request failed", result,
                "Antivirus", "SW-DEFENDER-SCAN-REQUEST",
                cooldown_seconds=settings["alert_cooldown_seconds"],
            )
        self.event_queue.put(("defender", result))
        self.event_queue.put(("status", f"{scan_type}: {result}"))

    def scan_file(self):
        path = filedialog.askopenfilename(title="Select a file to analyze")
        if not path:
            return
        self._run_async("Calculating SHA-256...", lambda: self._file_worker(path), "file_scan")

    def _file_worker(self, path):
        result = analyze_file(path, settings["known_hashes"])
        store.add_scan(result.path, result.size or 0, result.sha256 or "",
                       result.extension, result.modified_at or "", result.result)
        if result.sha256 is not None and result.result == "Known indicator match":
            self.detection_engine.analyze_file(result.path, result.sha256, settings["known_hashes"])
        text = (
            f"File: {result.path}\nSize: {result.size if result.size is not None else 'Unavailable'} bytes\n"
            f"Extension: {result.extension or 'None'}\nModified: {result.modified_at or 'Unavailable'}\n"
            f"SHA-256: {result.sha256 or 'Unavailable'}\nResult: {result.result}\n"
            f"{'Details: ' + result.error if result.error else ''}\n\n"
            "A local indicator match requires investigation; no local match does not guarantee safety."
        )
        self.event_queue.put(("file", text))

    def scan_directory(self):
        directory = filedialog.askdirectory(title="Choose directory for local file analysis")
        if not directory:
            return
        self.file_cancel.clear()
        self.file_progress.start()
        self._run_async(
            "Scanning directory...",
            lambda: self._directory_worker(directory),
            "directory_scan",
        )

    def cancel_directory_scan(self):
        self.file_cancel.set()
        self.file_text.insert("end", "\nCancellation requested; current file will finish first.\n")

    def _directory_worker(self, directory):
        count = 0
        matches = 0
        for result in iter_directory(
            directory, settings["known_hashes"], self.file_cancel,
            progress=lambda count, path: (
                self.event_queue.put(
                    ("file_progress", f"Analyzed {count} file(s): {path}")
                ) if count == 1 or count % 25 == 0 else None
            ),
        ):
            count += 1
            store.add_scan(result.path, result.size or 0, result.sha256 or "", result.extension,
                           result.modified_at or "", result.result)
            if result.sha256 is not None and result.result == "Known indicator match":
                matches += 1
                self.detection_engine.analyze_file(result.path, result.sha256, settings["known_hashes"])
        self.event_queue.put((
            "file",
            f"Directory: {directory}\nFiles analyzed: {count}\n"
            f"Known local indicator matches: {matches}\n"
            f"Cancelled: {'Yes' if self.file_cancel.is_set() else 'No'}\n\n"
            "Inaccessible and incomplete files are retained in scan results when encountered. "
            "A match is an indicator for investigation, not proof of malware.",
        ))

    def refresh_network(self):
        if not hasattr(self, "network_tree"):
            return
        self._run_async("Refreshing network connections...", self._network_worker, "network")

    def _network_worker(self):
        try:
            rows = collect_connections()
            addresses = collect_interface_addresses()
            if self.monitor.status == "Monitoring":
                self.detection_engine.analyze_connections(rows)
            self.event_queue.put(("network", (rows, addresses)))
        except Exception as exc:
            logger.exception("Network connection collection failed")
            self.event_queue.put(("network_error", str(exc)))

    def _render_network(self):
        if not hasattr(self, "network_tree"):
            return
        query = self.network_filter.get().strip().lower()
        clear_tree(self.network_tree)
        for row in self.network_rows:
            local = f'{row["local_ip"]}:{row["local_port"]}' if row["local_ip"] else ""
            remote = f'{row["remote_ip"]}:{row["remote_port"]}' if row["remote_ip"] else ""
            values = (row["pid"] or "", row["process"], local, remote, row["status"])
            if not query or query in " ".join(map(str, values)).lower():
                self.network_tree.insert("", "end", values=values)

    def export_network(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")],
            initialfile="securewatch_connections.csv",
        )
        if not path:
            return
        self._save_csv(
            path, ["pid", "process", "local_ip", "local_port", "remote_ip",
                   "remote_port", "status", "type"], self.network_rows,
        )

    def refresh_alerts(self):
        if not hasattr(self, "alert_tree"):
            return
        clear_tree(self.alert_tree)
        start_date, end_date = self.alert_date_range
        try:
            rows = store.alerts(
                limit=10000, severity=self.alert_severity_var.get(),
                search=self.alert_search_var.get(),
                start_date=start_date.isoformat() if start_date else None,
                end_date=end_date.isoformat() if end_date else None,
            )
        except sqlite3.Error as exc:
            logger.exception("Could not retrieve persisted alerts")
            self.alert_status.configure(text=f"Alert database unavailable: {exc}")
            self.alert_rows = []
            return
        self.alert_status.configure(text="")
        self.alert_rows = rows
        for row in self.alert_rows:
            self.alert_tree.insert(
                "", "end",
                values=(row["id"], row["timestamp"], row["severity"], row["rule_id"],
                        row["title"], row["status"], row["source"]),
            )

    def apply_alert_date_filter(self):
        try:
            start_date = date.fromisoformat(self.alert_from_var.get().strip()) if self.alert_from_var.get().strip() else None
            end_date = date.fromisoformat(self.alert_to_var.get().strip()) if self.alert_to_var.get().strip() else None
            if start_date and end_date and start_date > end_date:
                raise ValueError("Start date must not be after end date.")
        except ValueError as exc:
            messagebox.showerror("Alert Center date filter", str(exc))
            return
        self.alert_date_range = (start_date, end_date)
        self.refresh_alerts()

    def _selected_alert(self):
        selected = self.alert_tree.selection()
        if not selected:
            messagebox.showinfo("Alert Center", "Select an alert first.")
            return None
        try:
            return int(self.alert_tree.item(selected[0], "values")[0])
        except (IndexError, ValueError):
            messagebox.showerror("Alert Center", "The selected alert ID is invalid.")
            return None

    def _show_alert_details(self, _event=None):
        alert_id = self._selected_alert_id()
        if alert_id is None:
            return
        selected = next((row for row in self.alert_rows if row["id"] == alert_id), None)
        if selected is None:
            return
        try:
            notes = store.notes_for_alert(alert_id)
        except sqlite3.Error as exc:
            logger.exception("Could not retrieve alert investigation notes")
            self.alert_detail.delete("1.0", "end")
            self.alert_detail.insert("end", f"Alert notes unavailable: {exc}")
            return
        note_text = "\n".join(
            f'{note["timestamp"]}: {note["note"]}' for note in notes
        )
        text = (
            f'Rule: {selected["rule_id"] or "User/application record"}\n'
            f'Source: {selected["source"]}\nStatus: {selected["status"]}\n\n'
            f'{selected["details"]}\n\nInvestigation notes:\n{note_text or "None"}'
        )
        self.alert_detail.delete("1.0", "end")
        self.alert_detail.insert("end", text)

    def _selected_alert_id(self):
        selected = self.alert_tree.selection()
        if not selected:
            return None
        try:
            return int(self.alert_tree.item(selected[0], "values")[0])
        except (IndexError, ValueError):
            return None

    def review_selected_alert(self):
        alert_id = self._selected_alert()
        if alert_id is None:
            return
        try:
            if store.review_alert(alert_id):
                self.refresh_alerts()
                for item in self.alert_tree.get_children():
                    if int(self.alert_tree.item(item, "values")[0]) == alert_id:
                        self.alert_tree.selection_set(item)
                        self.alert_tree.focus(item)
                        self._show_alert_details()
                        break
        except sqlite3.Error as exc:
            logger.exception("Could not review selected alert")
            messagebox.showerror("Alert Center", f"Could not update alert status: {exc}")

    def add_alert_note(self):
        alert_id = self._selected_alert()
        if alert_id is None:
            return
        note = simpledialog.askstring("Investigation note", "Add a note to this alert:")
        if note is None:
            return
        try:
            store.add_investigation_note(alert_id, note)
        except ValueError as exc:
            messagebox.showwarning("Investigation note", str(exc))
            return
        except sqlite3.Error as exc:
            logger.exception("Could not save investigation note")
            messagebox.showerror("Investigation note", f"Could not save the note: {exc}")
            return
        self._show_alert_details()

    def export_alerts(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")],
            initialfile="securewatch_alerts.csv",
        )
        if not path:
            return
        self._save_csv(
            path, ["id", "timestamp", "severity", "rule_id", "title", "details",
                   "source", "status", "reviewed_at"],
            [dict(row) for row in self.alert_rows],
        )

    def export_file_scans(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")], initialfile="securewatch_file_scans.csv")
        if not path:
            return
        try:
            rows = store.file_scans(limit=10000)
        except sqlite3.Error as exc:
            logger.exception("Could not retrieve file scan history")
            messagebox.showerror("File scan export failed", str(exc))
            return
        self._save_csv(
            path, ["timestamp", "path", "size", "sha256", "extension",
                   "modified_at", "result"], [dict(row) for row in rows],
        )

    def export_pdf(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")],
            initialfile="securewatch_report.pdf",
            initialdir=settings["report_directory"],
        )
        if not path:
            return
        self._run_async("Generating PDF report...", lambda: self._pdf_worker(path), "pdf_report")

    def _pdf_worker(self, path):
        try:
            generate_pdf_report(
                path, store, computer=platform.node(),
                operating_system=platform.platform(), monitoring_status=self.monitor.status,
                defender_status=store.get_config().get(
                    "last_defender_status", "Not queried in this session"
                ),
            )
            self.event_queue.put(("report", (True, path)))
        except Exception as exc:
            logger.exception("PDF report generation failed")
            self.event_queue.put(("report", (False, str(exc))))

    def _run_async(self, label, fn, job_key=None):
        job_key = job_key or label
        with self.job_lock:
            if job_key in self.active_jobs:
                return
            self.active_jobs.add(job_key)
        self.title(f"SecureWatch — {label}")
        future = self.executor.submit(fn)

        def finished(task):
            with self.job_lock:
                self.active_jobs.discard(job_key)
            if task.cancelled():
                return
            error = task.exception()
            if error is not None:
                logger.error(
                    "Background job failed: %s", label,
                    exc_info=(type(error), error, error.__traceback__),
                )
                self.event_queue.put(("worker_error", (label, str(error))))

        future.add_done_callback(finished)

    def _monitor_cycle(self):
        metrics = collect_system_metrics()
        processes = collect_processes()
        alert_ids = self.detection_engine.analyze_processes(processes)
        warnings = []
        observed_events = []
        for log_name in ("Security", "System", "Application"):
            try:
                events = collect_events(log_name, min(settings["event_query_limit"], 200))
                observed_events.extend(events)
                store.add_windows_events(log_name, events)
            except (RuntimeError, OSError) as exc:
                reason = "permission required" if "denied" in str(exc).lower() else str(exc)
                warnings.append(f"{log_name} log: {reason}")
        if observed_events:
            alert_ids.extend(self.detection_engine.analyze_events(observed_events))
        try:
            detections = get_defender_detections(limit=100)
            new_detections = store.add_defender_detections(detections)
            alert_ids.extend(
                self.detection_engine.analyze_defender_detections(new_detections)
            )
        except (RuntimeError, OSError) as exc:
            warnings.append(f"Defender history unavailable: {exc}")
        try:
            connections = collect_connections()
            alert_ids.extend(self.detection_engine.analyze_connections(connections))
        except (OSError, psutil.AccessDenied) as exc:
            reason = "permission required" if isinstance(exc, psutil.AccessDenied) else str(exc)
            warnings.append(f"Network observations: {reason}")
            logger.warning("Network observations unavailable during monitoring: %s", exc)
        store.add_monitoring_run(json.dumps(metrics, ensure_ascii=False))
        return {
            "timestamp": now_text(),
            "metrics": metrics,
            "process_count": len(processes),
            "new_alert_count": len(alert_ids),
            "warnings": warnings,
        }

    @staticmethod
    def _permission_hint(error: Exception) -> str:
        detail = str(error)
        if "denied" in detail.lower() or "unauthorized" in detail.lower():
            return (
                f"Access denied. {detail}\nUse the Dashboard's "
                "'Relaunch as Administrator' action and approve the Windows UAC prompt."
            )
        return detail

    def relaunch_as_administrator(self):
        if not messagebox.askyesno(
            "Administrator access",
            "SecureWatch will ask Windows to relaunch the app with administrator "
            "permissions. This requires approval in the standard UAC prompt. "
            "No Windows security controls will be changed. Continue?",
        ):
            return
        succeeded, message = request_administrator_relaunch()
        if succeeded:
            self.permission_status.configure(
                text="Elevation requested. Complete the Windows UAC prompt in the new window.",
                text_color="#fbbf24",
            )
            messagebox.showinfo("Administrator access", message)
        else:
            logger.warning("Administrator relaunch was not started: %s", message)
            messagebox.showwarning("Administrator access", message)

    def start_monitoring(self):
        self.monitor.start()
        self._update_monitor_status()

    def pause_monitoring(self):
        self.monitor.pause()
        self._update_monitor_status()

    def resume_monitoring(self):
        self.monitor.resume()
        self._update_monitor_status()

    def stop_monitoring(self):
        try:
            self.monitor.stop()
            self._update_monitor_status()
        except TimeoutError as exc:
            logger.error("Could not stop monitoring cleanly: %s", exc)
            messagebox.showerror("Monitoring", str(exc))

    def _update_monitor_status(self, detail=""):
        if not hasattr(self, "monitor_status"):
            return
        text = f"Polling status: {self.monitor.status}. Polling is periodic, not instantaneous."
        if detail:
            text += f" {detail}"
        self.monitor_status.configure(text=text)

    def choose_report_directory(self):
        directory = filedialog.askdirectory(title="Choose default report directory")
        if directory:
            self.report_directory_var.set(directory)

    def save_app_settings(self):
        global settings
        updated = dict(settings)
        try:
            for key, variable in self.setting_vars.items():
                old_value = settings[key]
                raw = variable.get().strip()
                updated[key] = float(raw) if isinstance(old_value, float) else int(raw)
            updated["known_hashes"] = [
                line.strip() for line in self.indicator_text.get("1.0", "end").splitlines()
                if line.strip()
            ]
            ports_text = self.expected_ports_var.get().strip()
            updated["expected_listening_ports"] = (
                [int(value.strip()) for value in ports_text.split(",") if value.strip()]
                if ports_text else []
            )
            updated["report_directory"] = self.report_directory_var.get().strip()
            updated["appearance"] = self.appearance_var.get()
            validated = validate_settings(updated)
            if validated["log_retention_days"] != self._saved_retention_days:
                if not messagebox.askyesno(
                    "Confirm retention change",
                    "Applying this retention setting will remove expired local event and "
                    "monitoring-metric records. Alert evidence and investigation notes are preserved. Continue?",
                ):
                    return
            settings = save_settings(SETTINGS_PATH, validated)
            removed = store.prune_retained_observations(settings["log_retention_days"])
            store.add_audit_record(
                "Apply observation retention",
                f"Removed {removed} expired Windows event and monitoring metric records",
            )
            for key, value in settings.items():
                store.set_config(key, json.dumps(value, ensure_ascii=False))
            store.add_audit_record("Update settings", "Validated settings saved locally")
            self.monitor.update_interval(settings["monitoring_interval_seconds"])
            self.detection_engine = DetectionEngine(
                store,
                cooldown_seconds=settings["alert_cooldown_seconds"],
                failed_logon_threshold=settings["failed_logon_threshold"],
                error_threshold=settings["security_error_threshold"],
                event_window_minutes=settings["event_window_minutes"],
                cpu_threshold_percent=settings["cpu_threshold_percent"],
                ram_threshold_percent=settings["ram_threshold_percent"],
                resource_observation_count=settings["resource_observation_count"],
                expected_listening_ports=settings["expected_listening_ports"],
            )
            ctk.set_appearance_mode(settings["appearance"])
            self.settings_status.configure(text=f"Settings saved: {SETTINGS_PATH}")
            self._saved_retention_days = settings["log_retention_days"]
            messagebox.showinfo("Settings", "Settings validated and saved locally.")
        except (ValueError, OSError, sqlite3.Error) as exc:
            logger.exception("Could not apply SecureWatch settings")
            messagebox.showerror("Settings update failed", str(exc))

    def _on_close(self):
        self.file_cancel.set()
        try:
            self.monitor.stop(timeout=3)
        except TimeoutError:
            logger.exception("Monitoring thread did not stop during application close")
        self.executor.shutdown(wait=False, cancel_futures=True)
        self.destroy()

    def _poll_queue(self):
        try:
            while True:
                kind, data = self.event_queue.get_nowait()
                if kind == "dashboard":
                    metrics = data
                    self.metric_labels["CPU"].configure(text=f'{metrics["cpu_percent"]:.1f}%')
                    self.metric_labels["Memory"].configure(text=f'{metrics["memory_percent"]:.1f}%')
                    disk_percent = metrics["disk_percent"]
                    self.metric_labels["Disk"].configure(
                        text=f"{disk_percent:.1f}%" if disk_percent is not None else "Unavailable"
                    )
                    self.metric_labels["Processes"].configure(text=str(metrics["process_count"]))
                    uptime = time.strftime("%d days %H:%M:%S", time.gmtime(metrics["uptime_seconds"]))
                    self.sys_label.configure(
                        text=(f'Computer: {metrics["computer"]} | OS: {metrics["os"]} | '
                              f'User: {metrics["username"]} | Uptime: {uptime}\n'
                              f'RAM: {metrics["memory_available_bytes"] / (1024 ** 3):.1f} GiB available / '
                              f'{metrics["memory_total_bytes"] / (1024 ** 3):.1f} GiB total | '
                              f'Updated: {metrics["sampled_at"]}')
                    )
                    defender = metrics["defender_status"]
                    if defender.startswith("{"):
                        try:
                            parsed = json.loads(defender)
                            enabled = parsed.get("AntivirusEnabled")
                            defender = (
                                "Antivirus enabled" if enabled is True
                                else "Antivirus reported disabled" if enabled is False
                                else "Antivirus state unavailable"
                            )
                        except json.JSONDecodeError:
                            defender = "Status available"
                    self.security_summary.configure(
                        text=(f'Defender last query: {defender} at {metrics["defender_checked_at"]} | '
                              f'Open alerts: {metrics["open_alert_count"]} | '
                              f'Stored events (24h): {metrics["recent_event_count"]}')
                    )
                    self.recent_events_label.configure(
                        text="Recent stored events:\n" + (
                            "\n".join(metrics["recent_events"])
                            if metrics["recent_events"] else "No persisted event records."
                        )
                    )
                elif kind == "dashboard_error":
                    self.sys_label.configure(text=f"System metrics unavailable: {data}")
                elif kind == "processes":
                    self.process_rows = data
                    self._render_processes()
                elif kind == "processes_error":
                    messagebox.showwarning("Task Manager", data)
                elif kind == "network":
                    self.network_rows, addresses = data
                    self.network_addresses_label.configure(
                        text="Local interface addresses: " + (
                            " | ".join(
                                f'{row["interface"]} {row["family"]}: {row["address"]}'
                                for row in addresses
                            ) or "Unavailable"
                        )
                    )
                    self._render_network()
                elif kind == "network_error":
                    messagebox.showwarning("Network Monitor", f"Connection data unavailable: {data}")
                elif kind == "events":
                    self.event_rows = data
                    self._render_events()
                elif kind == "events_error":
                    messagebox.showwarning("Event Viewer", data)
                elif kind == "defender":
                    self.defender_text.delete("1.0", "end")
                    self.defender_text.insert("end", data)
                elif kind == "defender_history":
                    if not data:
                        text = (
                            "No retained Defender threat detections were returned. "
                            "This does not prove that no threats were ever detected."
                        )
                    else:
                        text = "Recent Microsoft Defender detection history:\n\n" + "\n\n".join(
                            f'Time: {item.get("InitialDetectionTime", "Unavailable")}\n'
                            f'Threat: {item.get("ThreatName", "Unavailable")} '
                            f'(ID {item.get("ThreatID", "Unavailable")})\n'
                            f'Action success: {item.get("ActionSuccess", "Unavailable")}\n'
                            f'Process: {item.get("ProcessName", "Unavailable")}\n'
                            f'Resources: {item.get("Resources", "Unavailable")}'
                            for item in data
                        )
                    self.defender_text.delete("1.0", "end")
                    self.defender_text.insert("end", text)
                elif kind == "defender_history_error":
                    self.defender_text.delete("1.0", "end")
                    self.defender_text.insert("end", f"Threat history unavailable:\n{data}")
                elif kind == "file":
                    self.file_progress.stop()
                    self.file_text.delete("1.0", "end")
                    self.file_text.insert("end", data)
                elif kind == "file_progress_stop":
                    self.file_progress.stop()
                elif kind == "status":
                    self.defender_text.insert("end", "\n\n" + data)
                elif kind == "file_progress":
                    self.file_text.delete("1.0", "end")
                    self.file_text.insert("end", data)
                elif kind == "monitor_cycle":
                    self._update_monitor_status(
                        f'Last cycle {data["timestamp"]}; processes: {data["process_count"]}; '
                        f'new findings: {data["new_alert_count"]}.'
                        + (f' Warnings: {"; ".join(data["warnings"])}'
                           if data["warnings"] else " Event, Defender, and network checks completed.")
                    )
                    self.refresh_alerts()
                elif kind == "monitor_error":
                    self._update_monitor_status(f"Latest cycle error: {data}")
                elif kind == "report":
                    succeeded, result = data
                    if succeeded:
                        messagebox.showinfo("Report created", f"Saved:\n{result}")
                    else:
                        messagebox.showerror("Report error", result)
                elif kind == "worker_error":
                    label, error = data
                    if label == "Scanning directory...":
                        self.file_progress.stop()
                    messagebox.showerror(label, f"Operation failed: {error}")
                self.title("SecureWatch — Windows Security & Monitoring System")
                self.refresh_alerts()
        except queue.Empty:
            pass
        self.after(250, self._poll_queue)

    def _periodic_refresh(self):
        self.refresh_dashboard()
        self.refresh_processes()
        self.refresh_network()
        self.after(settings["monitoring_interval_seconds"] * 1000, self._periodic_refresh)


if __name__ == "__main__":
    if platform.system() != "Windows":
        print("Warning: SecureWatch is designed for Windows; Defender and Windows Event Viewer features will not work on other operating systems.")
    app = SecureWatchApp()
    app.mainloop()
