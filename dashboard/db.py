"""SQLite data access for the HoneyWatch dashboard.

Reads from the honeypot database produced by the VPS parser. Schema:

    attacks(id, timestamp, src_ip, src_port, username, password,
            success, event_type, source)
    commands(id, attack_id, timestamp, src_ip, command)
    http_attacks(id, attack_id, timestamp, src_ip, method, path, attack_type)

event_type: connect | login_failed | login_success | command
source:     cowrie | dionaea | glastopf

The DB path defaults to ``honeywatch.db`` in the project root and can be
overridden with the ``HONEYWATCH_DB`` environment variable. Download it with:

    scp -P 2223 root@91.228.196.200:/opt/honeywatch/honeywatch.db ./honeywatch.db
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

from . import geoip
from .iso_codes import to_iso3

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def _resolve_db_path() -> str:
    """Locate the honeypot DB: env var, VPS path, project root, then Desktop."""
    env = os.environ.get("HONEYWATCH_DB")
    if env:
        return env
    candidates = [
        "/opt/honeywatch/honeywatch.db",
        os.path.join(_ROOT, "honeywatch.db"),
        os.path.join(os.path.expanduser("~"), "Desktop", "honeywatch.db"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return candidates[0]


DB_PATH = _resolve_db_path()

# Friendly labels + donut colours for each event type.
_EVENT_LABELS = {
    "connect": ("Port Scanning", "#c2410c"),
    "login_failed": ("Failed Login", "#f59e0b"),
    "login_success": ("Successful Login", "#ea7c1f"),
    "command": ("Command Execution", "#7c2d12"),
    "http_probe": ("HTTP Probe", "#2563eb"),
    "smb": ("SMB", "#6366f1"),
    "ftp": ("FTP", "#16a34a"),
    "mysql": ("MySQL", "#0891b2"),
    "rdp": ("RDP", "#7c3aed"),
    "git": ("Git", "#ca8a04"),
    "mssql": ("MSSQL", "#db2777"),
    "sip": ("SIP", "#059669"),
    "vnc": ("VNC", "#dc2626"),
}
_DEFAULT_EVENT = ("Other", "#64748b")

# Honeypot sources always offered in the log filter, even with no rows yet.
_KNOWN_SOURCES = {"cowrie", "dionaea", "opencanary"}
_PORT_COLORS = (
    "#0d9488",
    "#4f46e5",
    "#e11d48",
    "#65a30d",
    "#d97706",
    "#9333ea",
    "#0284c7",
    "#be123c",
)


def _resolve_event(event_type: str | None) -> tuple[str, str]:
    """Map raw DB event_type to display label and chart colour."""
    key = event_type or ""
    if key in _EVENT_LABELS:
        return _EVENT_LABELS[key]
    if key.startswith("port_"):
        port = key[5:]
        try:
            idx = int(port) % len(_PORT_COLORS)
        except ValueError:
            idx = sum(ord(c) for c in port) % len(_PORT_COLORS)
        return (f"Port {port}", _PORT_COLORS[idx])
    return _DEFAULT_EVENT

_DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

_RANGES = {
    "1h": {
        "period": "1 hour",
        "prev_start": "2 hours",
        "prev_end": "1 hour",
        "timeline_minutes": 60,
        "delta_label": "1h",
        "display": "Last hour",
    },
    "24h": {
        "period": "1 day",
        "prev_start": "2 days",
        "prev_end": "1 day",
        "timeline_hours": 24,
        "delta_label": "24h",
        "display": "Last 24 hours",
    },
    "week": {
        "period": "7 days",
        "prev_start": "14 days",
        "prev_end": "7 days",
        "timeline_days": 7,
        "delta_label": "7d",
        "display": "Last 7 days",
    },
    "month": {
        "period": "30 days",
        "prev_start": "60 days",
        "prev_end": "30 days",
        "timeline_days": 30,
        "delta_label": "30d",
        "display": "Last 30 days",
    },
}


def normalize_range(range_key: str | None) -> str:
    key = (range_key or "24h").strip().lower()
    return key if key in _RANGES else "24h"


def range_delta_label(range_key: str | None) -> str:
    return _RANGES[normalize_range(range_key)]["delta_label"]


def range_display_label(range_key: str | None) -> str:
    return _RANGES[normalize_range(range_key)]["display"]


def _window_sql(mod: str, range_key: str) -> str:
    period = _RANGES[normalize_range(range_key)]["period"]
    return f"datetime(timestamp{mod}) >= datetime('now','-{period}')"


# --------------------------------------------------------------------------- #
# Performance: indexes + a small in-process TTL cache                          #
# --------------------------------------------------------------------------- #
_CACHE_TTL = 15.0  # seconds; VPS parser writes ~once/min, UI auto-refreshes ~30s
_cache_store: dict = {}
_cache_lock = threading.Lock()
_indexes_ready = False


def _ensure_indexes() -> None:
    """Create helpful indexes once per process (best-effort, ignores failures)."""
    global _indexes_ready
    if _indexes_ready:
        return
    _indexes_ready = True  # set first so a read-only DB doesn't retry every call
    statements = (
        "PRAGMA journal_mode=WAL",
        "CREATE INDEX IF NOT EXISTS idx_attacks_ts ON attacks(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_attacks_src_ip ON attacks(src_ip)",
        "CREATE INDEX IF NOT EXISTS idx_attacks_event_type ON attacks(event_type)",
        "CREATE INDEX IF NOT EXISTS idx_attacks_source ON attacks(source)",
        # Expression indexes matching the datetime() wrapping used in queries.
        "CREATE INDEX IF NOT EXISTS idx_attacks_dt_iso ON attacks(datetime(timestamp))",
        "CREATE INDEX IF NOT EXISTS idx_attacks_dt_epoch "
        "ON attacks(datetime(timestamp,'unixepoch'))",
    )
    try:
        conn = sqlite3.connect(DB_PATH)
        try:
            for stmt in statements:
                try:
                    conn.execute(stmt)
                except sqlite3.Error:
                    pass
            conn.commit()
        finally:
            conn.close()
    except sqlite3.Error:
        pass


def _cached(fn):
    """Cache a function's result by its args for a short TTL."""

    def wrapper(*args, **kwargs):
        key = (fn.__name__, args, tuple(sorted(kwargs.items())))
        now = time.monotonic()
        with _cache_lock:
            hit = _cache_store.get(key)
            if hit and hit[0] > now:
                return hit[1]
        result = fn(*args, **kwargs)
        with _cache_lock:
            _cache_store[key] = (now + _CACHE_TTL, result)
        return result

    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


def _connect() -> sqlite3.Connection:
    _ensure_indexes()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=3000")
    return conn


def _ts_mod(conn: sqlite3.Connection) -> str:
    """Detect whether timestamps are epoch numbers or ISO/text.

    Returns the modifier to feed SQLite datetime()/strftime() (",'unixepoch'"
    for numeric epochs, "" for ISO-8601 / text timestamps).
    """
    row = conn.execute(
        "SELECT timestamp FROM attacks WHERE timestamp IS NOT NULL LIMIT 1"
    ).fetchone()
    if row is None:
        return ""
    val = row[0]
    if isinstance(val, (int, float)):
        return ",'unixepoch'"
    if isinstance(val, str) and val.strip().isdigit():
        return ",'unixepoch'"
    return ""


def _anchor(conn: sqlite3.Connection, mod: str) -> datetime:
    max_ts = conn.execute(
        f"SELECT MAX(datetime(timestamp{mod})) FROM attacks"
    ).fetchone()[0]
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    anchor = now
    if max_ts:
        try:
            anchor = max(now, datetime.strptime(max_ts, "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            pass
    return anchor


def _delta(
    conn: sqlite3.Connection, mod: str, range_key: str, where: str = ""
) -> tuple[int, float]:
    """Count rows in the selected window and % change vs the previous window."""
    cfg = _RANGES[normalize_range(range_key)]
    clause = f" AND {where}" if where else ""
    last = conn.execute(
        f"SELECT COUNT(*) FROM attacks "
        f"WHERE datetime(timestamp{mod}) >= datetime('now','-{cfg['period']}'){clause}"
    ).fetchone()[0]
    prev = conn.execute(
        f"SELECT COUNT(*) FROM attacks "
        f"WHERE datetime(timestamp{mod}) >= datetime('now','-{cfg['prev_start']}') "
        f"AND datetime(timestamp{mod}) < datetime('now','-{cfg['prev_end']}'){clause}"
    ).fetchone()[0]
    if prev:
        pct = round((last - prev) / prev * 100, 1)
    else:
        pct = 100.0 if last else 0.0
    return last, pct


def _ip_counts(conn: sqlite3.Connection, range_key: str) -> list[tuple[str, int]]:
    mod = _ts_mod(conn)
    window = _window_sql(mod, range_key)
    rows = conn.execute(
        f"SELECT src_ip, COUNT(*) AS c FROM attacks "
        f"WHERE src_ip IS NOT NULL AND {window} GROUP BY src_ip"
    ).fetchall()
    return [(r["src_ip"], r["c"]) for r in rows]


def _country_aggregate(conn: sqlite3.Connection, range_key: str) -> list[dict]:
    """Aggregate attack counts by geolocated country."""
    ip_counts = _ip_counts(conn, range_key)
    geo = geoip.locate([ip for ip, _ in ip_counts])
    agg: dict[str, dict] = {}
    for ip, count in ip_counts:
        info = geo.get(ip)
        if not info:
            continue
        code = info["country_code"]
        entry = agg.setdefault(
            code,
            {
                "name": info["country"],
                "code": code,
                "iso3": to_iso3(code),
                "flag": geoip.flag(code),
                "lat": info["lat"],
                "lng": info["lng"],
                "count": 0,
            },
        )
        entry["count"] += count
    return sorted(agg.values(), key=lambda e: e["count"], reverse=True)


# --------------------------------------------------------------------------- #
# Public API                                                                #
# --------------------------------------------------------------------------- #
@_cached
def get_summary(period: str = "24h") -> dict:
    range_key = normalize_range(period)
    cfg = _RANGES[range_key]
    with _connect() as conn:
        mod = _ts_mod(conn)
        total, total_d = _delta(conn, mod, range_key)
        logins, logins_d = _delta(
            conn,
            mod,
            range_key,
            "event_type IN ('login_failed','login_success')",
        )
        window = _window_sql(mod, range_key)
        unique_ips = conn.execute(
            f"SELECT COUNT(DISTINCT src_ip) FROM attacks WHERE {window}"
        ).fetchone()[0]
        uniq_last = unique_ips
        uniq_prev = conn.execute(
            f"SELECT COUNT(DISTINCT src_ip) FROM attacks "
            f"WHERE datetime(timestamp{mod}) >= datetime('now','-{cfg['prev_start']}') "
            f"AND datetime(timestamp{mod}) < datetime('now','-{cfg['prev_end']}')"
        ).fetchone()[0]
        uniq_d = (
            round((uniq_last - uniq_prev) / uniq_prev * 100, 1)
            if uniq_prev
            else (100.0 if uniq_last else 0.0)
        )
        countries = len(_country_aggregate(conn, range_key))

    return {
        "total_attacks": {"value": total, "delta_24h": total_d},
        "unique_ips": {"value": unique_ips, "delta_24h": uniq_d},
        "login_attempts": {"value": logins, "delta_24h": logins_d},
        "countries": {"value": countries, "delta_24h": 0.0},
    }


@_cached
def get_top_countries(limit: int = 10, period: str = "24h") -> list[dict]:
    with _connect() as conn:
        agg = _country_aggregate(conn, normalize_range(period))
    top = agg[:limit]
    other = sum(e["count"] for e in agg[limit:])
    rows = [
        {"name": e["name"], "code": e["code"], "flag": e["flag"], "count": e["count"]}
        for e in top
    ]
    if other:
        rows.append(
            {"name": "Other", "code": "XX", "flag": "\U0001F30D", "count": other}
        )
    return rows


@_cached
def get_geo(period: str = "24h") -> list[dict]:
    with _connect() as conn:
        agg = _country_aggregate(conn, normalize_range(period))
    return [
        {
            "name": e["name"],
            "code": e["code"],
            "iso3": e.get("iso3") or to_iso3(e["code"]),
            "lat": e["lat"],
            "lng": e["lng"],
            "count": e["count"],
        }
        for e in agg
        if e.get("lat") is not None and e.get("lng") is not None
    ]


def _timeline_hours(hours: int) -> list[dict]:
    with _connect() as conn:
        mod = _ts_mod(conn)
        anchor = _anchor(conn, mod).replace(minute=0, second=0, microsecond=0)
        start = anchor - timedelta(hours=hours - 1)
        start_key = start.strftime("%Y-%m-%d %H:00")

        rows = conn.execute(
            f"SELECT strftime('%Y-%m-%d %H:00', timestamp{mod}) AS bucket, "
            f"COUNT(*) AS c FROM attacks "
            f"WHERE strftime('%Y-%m-%d %H:00', timestamp{mod}) >= ? "
            f"GROUP BY bucket",
            (start_key,),
        ).fetchall()
        counts = {r["bucket"]: r["c"] for r in rows}

    out = []
    for i in range(hours):
        b = start + timedelta(hours=i)
        key = b.strftime("%Y-%m-%d %H:00")
        out.append({"label": b.strftime("%H:00"), "value": counts.get(key, 0)})
    return out


def _timeline_days(days: int) -> list[dict]:
    with _connect() as conn:
        mod = _ts_mod(conn)
        anchor = _anchor(conn, mod).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        start = anchor - timedelta(days=days - 1)
        start_key = start.strftime("%Y-%m-%d")

        rows = conn.execute(
            f"SELECT strftime('%Y-%m-%d', timestamp{mod}) AS bucket, "
            f"COUNT(*) AS c FROM attacks "
            f"WHERE strftime('%Y-%m-%d', timestamp{mod}) >= ? "
            f"GROUP BY bucket",
            (start_key,),
        ).fetchall()
        counts = {r["bucket"]: r["c"] for r in rows}

    out = []
    for i in range(days):
        b = start + timedelta(days=i)
        key = b.strftime("%Y-%m-%d")
        out.append({"label": b.strftime("%d %b"), "value": counts.get(key, 0)})
    return out


def _timeline_minutes(minutes: int) -> list[dict]:
    with _connect() as conn:
        mod = _ts_mod(conn)
        anchor = _anchor(conn, mod).replace(second=0, microsecond=0)
        start = anchor - timedelta(minutes=minutes - 1)
        start_key = start.strftime("%Y-%m-%d %H:%M")

        rows = conn.execute(
            f"SELECT strftime('%Y-%m-%d %H:%M', timestamp{mod}) AS bucket, "
            f"COUNT(*) AS c FROM attacks "
            f"WHERE strftime('%Y-%m-%d %H:%M', timestamp{mod}) >= ? "
            f"GROUP BY bucket",
            (start_key,),
        ).fetchall()
        counts = {r["bucket"]: r["c"] for r in rows}

    out = []
    for i in range(minutes):
        b = start + timedelta(minutes=i)
        key = b.strftime("%Y-%m-%d %H:%M")
        out.append({"label": b.strftime("%H:%M"), "value": counts.get(key, 0)})
    return out


@_cached
def get_timeline(period: str = "24h") -> list[dict]:
    """Attacks over time: per minute (1h), hourly (24h), or daily (week / month)."""
    range_key = normalize_range(period)
    cfg = _RANGES[range_key]
    if "timeline_minutes" in cfg:
        return _timeline_minutes(cfg["timeline_minutes"])
    if "timeline_hours" in cfg:
        return _timeline_hours(cfg["timeline_hours"])
    return _timeline_days(cfg["timeline_days"])


@_cached
def get_event_types(period: str = "24h") -> list[dict]:
    range_key = normalize_range(period)
    with _connect() as conn:
        mod = _ts_mod(conn)
        window = _window_sql(mod, range_key)
        rows = conn.execute(
            f"SELECT event_type, COUNT(*) AS c FROM attacks "
            f"WHERE {window} GROUP BY event_type"
        ).fetchall()
    total = sum(r["c"] for r in rows) or 1
    agg: dict[str, dict] = {}
    for r in rows:
        label, color = _resolve_event(r["event_type"])
        entry = agg.setdefault(
            label, {"label": label, "color": color, "count": 0}
        )
        entry["count"] += r["c"]
    out = []
    for entry in agg.values():
        out.append(
            {
                "label": entry["label"],
                "value": round(entry["count"] / total * 100, 1),
                "count": entry["count"],
                "color": entry["color"],
            }
        )
    return sorted(out, key=lambda e: e["value"], reverse=True)


def _top_field(field: str, limit: int, range_key: str) -> list[dict]:
    with _connect() as conn:
        mod = _ts_mod(conn)
        window = _window_sql(mod, range_key)
        rows = conn.execute(
            f"SELECT {field} AS label, COUNT(*) AS c FROM attacks "
            f"WHERE {field} IS NOT NULL AND {field} <> '' AND {window} "
            f"GROUP BY {field} ORDER BY c DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [{"label": r["label"], "value": r["c"]} for r in rows]


@_cached
def get_top_usernames(limit: int = 8, period: str = "24h") -> list[dict]:
    return _top_field("username", limit, normalize_range(period))


@_cached
def get_top_passwords(limit: int = 8, period: str = "24h") -> list[dict]:
    return _top_field("password", limit, normalize_range(period))


@_cached
def get_heatmap(period: str = "24h") -> dict:
    """Attacks by day-of-week x hour-of-day in the selected window."""
    range_key = normalize_range(period)
    with _connect() as conn:
        mod = _ts_mod(conn)
        window = _window_sql(mod, range_key)
        rows = conn.execute(
            f"SELECT CAST(strftime('%w', timestamp{mod}) AS INTEGER) AS dow, "
            f"CAST(strftime('%H', timestamp{mod}) AS INTEGER) AS hour, "
            f"COUNT(*) AS c FROM attacks WHERE {window} GROUP BY dow, hour"
        ).fetchall()
    # strftime %w: 0=Sunday..6=Saturday -> remap to Mon..Sun index.
    remap = {0: 6, 1: 0, 2: 1, 3: 2, 4: 3, 5: 4, 6: 5}
    cells = []
    grid = {(d, h): 0 for d in range(7) for h in range(24)}
    for r in rows:
        di = remap.get(r["dow"], 0)
        grid[(di, r["hour"])] = r["c"]
    for (d, h), v in grid.items():
        cells.append({"day": d, "hour": h, "value": v})
    return {"days": _DAYS, "cells": cells}


@_cached
def get_recent(limit: int = 8, period: str = "24h") -> list[dict]:
    range_key = normalize_range(period)
    with _connect() as conn:
        mod = _ts_mod(conn)
        window = _window_sql(mod, range_key)
        rows = conn.execute(
            f"SELECT src_ip, event_type, "
            f"strftime('%H:%M:%S', timestamp{mod}) AS t "
            f"FROM attacks WHERE {window} "
            f"ORDER BY datetime(timestamp{mod}) DESC LIMIT ?",
            (limit,),
        ).fetchall()
        geo = geoip.locate([r["src_ip"] for r in rows])
    out = []
    for r in rows:
        info = geo.get(r["src_ip"])
        code = info["country_code"] if info else None
        label = _resolve_event(r["event_type"])[0]
        out.append(
            {
                "ip": r["src_ip"],
                "flag": geoip.flag(code),
                "type": label,
                "time": r["t"] or "",
            }
        )
    return out


@_cached
def get_log_sources() -> list[str]:
    """Source values for the filter dropdown.

    Always offers the known honeypot sources (so e.g. ``dionaea`` can be
    selected before its first events arrive) merged with any other distinct
    ``source`` values already present in the DB.
    """
    with _connect() as conn:
        rows = conn.execute(
            "SELECT DISTINCT source FROM attacks "
            "WHERE source IS NOT NULL AND source <> ''"
        ).fetchall()
    sources = _KNOWN_SOURCES | {r[0] for r in rows}
    return sorted(sources)


@_cached
def get_logs(
    period: str = "24h",
    limit: int = 100,
    offset: int = 0,
    search: str = "",
    source: str = "",
) -> dict:
    """Paginated, filterable attack log rows for the logs table.

    ``search`` matches src_ip / username / password (substring).
    ``source`` restricts to a single honeypot source (e.g. ``cowrie``).
    """
    range_key = normalize_range(period)
    limit = min(max(int(limit), 1), 500)
    offset = max(int(offset), 0)
    search = (search or "").strip()
    source = (source or "").strip()

    with _connect() as conn:
        mod = _ts_mod(conn)
        filters = [_window_sql(mod, range_key)]
        params: list = []
        if search:
            like = f"%{search}%"
            filters.append(
                "(src_ip LIKE ? OR username LIKE ? OR password LIKE ?)"
            )
            params.extend([like, like, like])
        if source:
            filters.append("source = ?")
            params.append(source)
        where = " AND ".join(filters)

        total = conn.execute(
            f"SELECT COUNT(*) FROM attacks WHERE {where}", params
        ).fetchone()[0]
        rows = conn.execute(
            f"SELECT id, timestamp, src_ip, src_port, username, password, "
            f"event_type, source, "
            f"strftime('%Y-%m-%d %H:%M:%S', timestamp{mod}) AS ts "
            f"FROM attacks WHERE {where} "
            f"ORDER BY datetime(timestamp{mod}) DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
        geo = geoip.locate([r["src_ip"] for r in rows if r["src_ip"]])

    items = []
    for r in rows:
        info = geo.get(r["src_ip"])
        code = info["country_code"] if info else None
        label = _resolve_event(r["event_type"])[0]
        items.append(
            {
                "id": r["id"],
                "timestamp": r["ts"] or str(r["timestamp"] or ""),
                "ip": r["src_ip"] or "—",
                "port": r["src_port"],
                "country": info["country"] if info else "—",
                "flag": geoip.flag(code),
                "type": label,
                "username": r["username"] or "—",
                "password": r["password"] or "—",
                "source": r["source"] or "—",
            }
        )

    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }
