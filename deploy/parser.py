"""HoneyWatch log parser — Cowrie + Dionaea + OpenCanary -> SQLite.

Reads only *new* bytes from each log file (parser_state). Identical events
are skipped via UNIQUE indexes (same IP may attack many times; exact duplicates
from re-parsing the same log line are not stored twice).
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime

DB_PATH = "/opt/honeywatch/honeywatch.db"
COWRIE_LOG = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
OPENCANARY_LOG = "/var/log/opencanary.log"
# Dionaea log_json ihandler output (file:// handler). Common alternatives:
#   /opt/dionaea/var/lib/dionaea/dionaea.json, /var/lib/dionaea/dionaea.json
DIONAEA_LOG = "/opt/dionaea/var/lib/dionaea/dionaea.json"

# Map Dionaea service/protocol names to dashboard event_type values.
# Unknown protocols fall back to their lowercased name (shown as "Other").
DIONAEA_PROTOCOL_MAP = {
    "httpd": "http_probe",
    "http": "http_probe",
    "ftp": "ftp",
    "ftpd": "ftp",
    "smbd": "smb",
    "smb": "smb",
    "mysqld": "mysql",
    "mysql": "mysql",
    "mssqld": "mssql",
    "mssql": "mssql",
    "sipsession": "sip",
    "sip": "sip",
    "epmapper": "epmap",
    "mqttd": "mqtt",
    "mqtt": "mqtt",
    "tftp": "tftp",
    "tftpd": "tftp",
    "pptp": "pptp",
    "upnp": "upnp",
    "blackhole": "blackhole",
    "mongod": "mongodb",
    "mongo": "mongodb",
    "memcached": "memcache",
    "memcache": "memcache",
}

# Only inbound connection types are real attacks; skip listen/connect (outbound).
DIONAEA_INBOUND_TYPES = {"accept", "reject"}


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute(
        """CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        src_port INTEGER,
        username TEXT,
        password TEXT,
        success INTEGER,
        event_type TEXT,
        source TEXT
    )"""
    )

    c.execute(
        """CREATE TABLE IF NOT EXISTS commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_id INTEGER,
        timestamp TEXT,
        src_ip TEXT,
        command TEXT,
        FOREIGN KEY (attack_id) REFERENCES attacks(id)
    )"""
    )

    c.execute(
        """CREATE TABLE IF NOT EXISTS http_attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_id INTEGER,
        timestamp TEXT,
        src_ip TEXT,
        method TEXT,
        path TEXT,
        attack_type TEXT,
        FOREIGN KEY (attack_id) REFERENCES attacks(id)
    )"""
    )

    c.execute(
        """CREATE TABLE IF NOT EXISTS parser_state (
        log_path TEXT PRIMARY KEY,
        byte_offset INTEGER NOT NULL DEFAULT 0
    )"""
    )

    _ensure_dedup_indexes(c)

    conn.commit()
    conn.close()


def _dedupe_existing(c: sqlite3.Cursor) -> None:
    """Remove exact duplicate rows (keeps lowest id). Safe to run multiple times."""
    c.execute(
        """DELETE FROM attacks WHERE id NOT IN (
            SELECT MIN(id) FROM attacks
            GROUP BY timestamp, src_ip, src_port, username, password,
                     success, event_type, source
        )"""
    )
    c.execute(
        """DELETE FROM commands WHERE id NOT IN (
            SELECT MIN(id) FROM commands
            GROUP BY timestamp, src_ip, command
        )"""
    )
    c.execute(
        """DELETE FROM http_attacks WHERE id NOT IN (
            SELECT MIN(id) FROM http_attacks
            GROUP BY timestamp, src_ip, method, path, attack_type
        )"""
    )


def _ensure_dedup_indexes(c: sqlite3.Cursor) -> None:
    indexes = (
        """CREATE UNIQUE INDEX IF NOT EXISTS idx_attacks_dedup
        ON attacks(
            timestamp, src_ip, src_port, username, password,
            success, event_type, source
        )""",
        """CREATE UNIQUE INDEX IF NOT EXISTS idx_commands_dedup
        ON commands(timestamp, src_ip, command)""",
        """CREATE UNIQUE INDEX IF NOT EXISTS idx_http_attacks_dedup
        ON http_attacks(timestamp, src_ip, method, path, attack_type)""",
    )
    for sql in indexes:
        try:
            c.execute(sql)
        except sqlite3.IntegrityError:
            _dedupe_existing(c)
            c.execute(sql)


def _get_offset(c: sqlite3.Cursor, log_path: str) -> int:
    c.execute("SELECT byte_offset FROM parser_state WHERE log_path = ?", (log_path,))
    row = c.fetchone()
    return int(row[0]) if row else 0


def _set_offset(c: sqlite3.Cursor, log_path: str, byte_offset: int) -> None:
    c.execute(
        """INSERT INTO parser_state (log_path, byte_offset) VALUES (?, ?)
        ON CONFLICT(log_path) DO UPDATE SET byte_offset = excluded.byte_offset""",
        (log_path, byte_offset),
    )


def _iter_new_lines(c: sqlite3.Cursor, log_path: str):
    """Yield decoded lines from log_path starting at the saved byte offset."""
    if not os.path.exists(log_path):
        print(f"Brak pliku: {log_path}")
        return

    offset = _get_offset(c, log_path)
    file_size = os.path.getsize(log_path)
    if file_size < offset:
        offset = 0

    with open(log_path, "rb") as fh:
        fh.seek(offset)
        chunk = fh.read()

    if not chunk:
        return

    if chunk.endswith(b"\n"):
        processable = chunk
        new_offset = offset + len(chunk)
    else:
        last_nl = chunk.rfind(b"\n")
        if last_nl == -1:
            return
        processable = chunk[: last_nl + 1]
        new_offset = offset + last_nl + 1

    for raw_line in processable.splitlines():
        line = raw_line.decode("utf-8", errors="replace").strip()
        if line:
            yield line

    _set_offset(c, log_path, new_offset)


def parse_cowrie() -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    inserted = 0

    for line in _iter_new_lines(c, COWRIE_LOG):
        try:
            entry = json.loads(line)
            eventid = entry.get("eventid")

            if eventid == "cowrie.session.connect":
                c.execute(
                    """INSERT OR IGNORE INTO attacks
                    (timestamp, src_ip, src_port, username, password, success, event_type, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        entry.get("timestamp"),
                        entry.get("src_ip"),
                        entry.get("src_port"),
                        None,
                        None,
                        None,
                        "connect",
                        "cowrie",
                    ),
                )
            elif eventid == "cowrie.login.failed":
                c.execute(
                    """INSERT OR IGNORE INTO attacks
                    (timestamp, src_ip, src_port, username, password, success, event_type, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        entry.get("timestamp"),
                        entry.get("src_ip"),
                        entry.get("src_port"),
                        entry.get("username"),
                        entry.get("password"),
                        0,
                        "login_failed",
                        "cowrie",
                    ),
                )
            elif eventid == "cowrie.login.success":
                c.execute(
                    """INSERT OR IGNORE INTO attacks
                    (timestamp, src_ip, src_port, username, password, success, event_type, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        entry.get("timestamp"),
                        entry.get("src_ip"),
                        entry.get("src_port"),
                        entry.get("username"),
                        entry.get("password"),
                        1,
                        "login_success",
                        "cowrie",
                    ),
                )
            elif eventid == "cowrie.command.input":
                c.execute(
                    """INSERT OR IGNORE INTO commands (timestamp, src_ip, command)
                    VALUES (?, ?, ?)""",
                    (
                        entry.get("timestamp"),
                        entry.get("src_ip"),
                        entry.get("input"),
                    ),
                )

            if c.rowcount:
                inserted += 1
        except (json.JSONDecodeError, TypeError, sqlite3.Error):
            continue

    conn.commit()
    conn.close()
    print(f"Cowrie: {inserted} new rows at {datetime.now()}")


<<<<<<< Updated upstream
DIONAEA_LOG = '/opt/dionaea/var/log/dionaea/dionaea.json'

EVENT_MAP = {
    "connection": "connect",
    "http_request": "http_request",
    "download": "malware_download"
}

def classify_attack(command=None, path=None):
    text = ((command or "") + " " + (path or "")).lower()

    if any(x in text for x in ["wget", "curl"]):
        return "malware_download"

    if any(x in text for x in ["select", "union", "sleep("]):
        return "sqli"

    if "/etc/passwd" in text:
        return "lfi"

    if any(x in text for x in ["bash", "sh", "nc ", "netcat"]):
        return "rce"

    if any(x in text for x in ["nmap", "masscan", "zmap"]):
        return "scanner"

    return "unknown"


def parse_dionaea():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    if not os.path.exists(DIONAEA_LOG):
        print(f"Brak pliku Dionaea: {DIONAEA_LOG}")
        return

    position = get_position('dionaea')

    with open(DIONAEA_LOG, 'r') as f:
        f.seek(position)

        for line in f:
            try:
                entry = json.loads(line.strip())

                raw_event = entry.get("eventid")
                event_type = EVENT_MAP.get(raw_event, "unknown")

                connection = entry.get("connection", {})
                src_ip = connection.get("remote", {}).get("host")
                src_port = connection.get("remote", {}).get("port")
                timestamp = entry.get("timestamp")

                # 🔹 Zawsze twórz attack (spójny model)
                c.execute('''INSERT INTO attacks 
                    (timestamp, src_ip, src_port, username, password, success, event_type, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                    (timestamp, src_ip, src_port,
                     None, None, None, event_type, 'dionaea'))

                attack_id = c.lastrowid

                # 🔹 HTTP request
                if raw_event == "http_request":
                    method = entry.get("request", {}).get("method")
                    path = entry.get("request", {}).get("path")

                    attack_type = classify_attack(path=path)

                    c.execute('''INSERT INTO http_attacks
                        (attack_id, timestamp, src_ip, method, path, attack_type)
                        VALUES (?, ?, ?, ?, ?, ?)''',
                        (attack_id, timestamp, src_ip, method, path, attack_type))

                # 🔹 Malware download
                elif raw_event == "download":
                    url = entry.get("url")

                    c.execute('''INSERT INTO commands
                        (attack_id, timestamp, src_ip, command)
                        VALUES (?, ?, ?, ?)''',
                        (attack_id, timestamp, src_ip, f"DOWNLOAD {url}"))

                # 🔹 Inne eventy jako commands (debug + przyszłość)
                elif raw_event not in ["connection"]:
                    c.execute('''INSERT INTO commands
                        (attack_id, timestamp, src_ip, command)
                        VALUES (?, ?, ?, ?)''',
                        (attack_id, timestamp, src_ip, raw_event))

            except Exception:
                continue

        save_position('dionaea', f.tell())

    conn.commit()
    conn.close()
    print(f"Dionaea parsed at {datetime.now()}")
=======
def _dionaea_event_type(protocol: str | None) -> str:
    """Map a Dionaea connection protocol to a dashboard event_type."""
    key = (protocol or "").strip().lower()
    return DIONAEA_PROTOCOL_MAP.get(key, key or "dionaea_conn")


def parse_dionaea() -> None:
    """Parse the Dionaea log_json output into the shared schema.

    One JSON object is emitted per connection (on free). Maps to:
      - attacks: one row per inbound connection (event_type = service name)
      - attacks: one login_failed row per captured credential pair
      - commands: one row per FTP command
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    inserted = 0

    for line in _iter_new_lines(c, DIONAEA_LOG):
        try:
            entry = json.loads(line)
            connection = entry.get("connection") or {}
            conn_type = (connection.get("type") or "").lower()
            if conn_type not in DIONAEA_INBOUND_TYPES:
                continue

            src_ip = entry.get("src_ip")
            if not src_ip:
                continue
            src_port = entry.get("src_port")
            ts = entry.get("timestamp")
            event_type = _dionaea_event_type(connection.get("protocol"))

            c.execute(
                """INSERT OR IGNORE INTO attacks
                (timestamp, src_ip, src_port, username, password, success, event_type, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (ts, src_ip, src_port, None, None, None, event_type, "dionaea"),
            )
            if c.rowcount:
                inserted += 1

            for cred in entry.get("credentials") or []:
                username = cred.get("username")
                password = cred.get("password")
                if username is None and password is None:
                    continue
                c.execute(
                    """INSERT OR IGNORE INTO attacks
                    (timestamp, src_ip, src_port, username, password, success, event_type, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (ts, src_ip, src_port, username, password, 0, "login_failed", "dionaea"),
                )
                if c.rowcount:
                    inserted += 1

            ftp = entry.get("ftp") or {}
            for cmd in ftp.get("commands") or []:
                command = cmd.get("command")
                if not command:
                    continue
                arguments = cmd.get("arguments")
                full = command if not arguments else f"{command} {arguments}"
                c.execute(
                    """INSERT OR IGNORE INTO commands (timestamp, src_ip, command)
                    VALUES (?, ?, ?)""",
                    (ts, src_ip, full),
                )
                if c.rowcount:
                    inserted += 1
        except (json.JSONDecodeError, TypeError, sqlite3.Error):
            continue

    conn.commit()
    conn.close()
    print(f"Dionaea: {inserted} new rows at {datetime.now()}")
>>>>>>> Stashed changes


def parse_opencanary() -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    inserted = 0

    for line in _iter_new_lines(c, OPENCANARY_LOG):
        try:
            entry = json.loads(line)
            dst_port = entry.get("dst_port")
            if dst_port == -1:
                continue

            src_ip = entry.get("src_host")
            ts = entry.get("local_time")
            logdata = entry.get("logdata", {})

            if dst_port in (80, 8080):
                c.execute(
                    """INSERT OR IGNORE INTO attacks
                    (timestamp, src_ip, src_port, username, password, success, event_type, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        ts,
                        src_ip,
                        entry.get("src_port"),
                        None,
                        None,
                        0,
                        "http_probe",
                        "opencanary",
                    ),
                )
                if c.rowcount == 0:
                    continue
                attack_id = c.lastrowid
                c.execute(
                    """INSERT OR IGNORE INTO http_attacks
                    (attack_id, timestamp, src_ip, method, path, attack_type)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        attack_id,
                        ts,
                        src_ip,
                        logdata.get("METHOD", "GET"),
                        logdata.get("PATH", "/"),
                        "probe",
                    ),
                )
            else:
                username = logdata.get("USERNAME") or logdata.get("username")
                password = logdata.get("PASSWORD") or logdata.get("password")
                service_map = {
                    21: "ftp",
                    3306: "mysql",
                    3389: "rdp",
                    9418: "git",
                    1433: "mssql",
                    5060: "sip",
                    5900: "vnc",
                }
                event_type = service_map.get(dst_port, f"port_{dst_port}")
                c.execute(
                    """INSERT OR IGNORE INTO attacks
                    (timestamp, src_ip, src_port, username, password, success, event_type, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        ts,
                        src_ip,
                        entry.get("src_port"),
                        username,
                        password,
                        0,
                        event_type,
                        "opencanary",
                    ),
                )

            if c.rowcount:
                inserted += 1
        except (json.JSONDecodeError, TypeError, sqlite3.Error):
            continue

    conn.commit()
    conn.close()
    print(f"OpenCanary: {inserted} new rows at {datetime.now()}")


if __name__ == "__main__":
    init_db()
    parse_cowrie()
    parse_dionaea()
    parse_opencanary()
    print("Done!")
