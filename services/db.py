"""SQLite persistence for cases and findings."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _db_path() -> Path:
    # repo root is parent of services/
    root = Path(__file__).resolve().parent.parent
    return root / "secops.sqlite3"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_db_path()), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cases (
            case_reference TEXT PRIMARY KEY,
            case_name TEXT NOT NULL,
            analyst_name TEXT NOT NULL,
            classification TEXT NOT NULL,
            selected_tools_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL,
            user_id INTEGER,
            device_label TEXT,
            adb_serial TEXT,
            detailed_info_json TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
        """
    )
    # Perform migration if columns are missing
    cur.execute("PRAGMA table_info(cases)")
    columns = [col["name"] for col in cur.fetchall()]
    if "device_label" not in columns:
        cur.execute("ALTER TABLE cases ADD COLUMN device_label TEXT")
    if "adb_serial" not in columns:
        cur.execute("ALTER TABLE cases ADD COLUMN adb_serial TEXT")
    if "detailed_info_json" not in columns:
        cur.execute("ALTER TABLE cases ADD COLUMN detailed_info_json TEXT")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS case_findings (
            case_reference TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            summary TEXT NOT NULL,
            detail TEXT NOT NULL,
            status TEXT NOT NULL,
            severity TEXT,
            recorded_at TEXT NOT NULL,
            PRIMARY KEY (case_reference, tool_name),
            FOREIGN KEY (case_reference) REFERENCES cases(case_reference) ON DELETE CASCADE
        )
        """
    )

    conn.commit()
    conn.close()


def login_user(email: str, password: str):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM users WHERE email=? AND password=?",
        (email, password),
    )

    user = cur.fetchone()
    conn.close()

    return user

def register_user(name: str, email: str, password: str) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            (name, email, password),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # email already exists
    finally:
        conn.close()
        

@dataclass
class CaseRow:
    case_reference: str
    case_name: str
    analyst_name: str
    classification: str
    selected_tools: list[str]
    created_at: str
    status: str
    device_label: str | None = None
    adb_serial: str | None = None
    detailed_info: dict[str, str] | None = None


def create_or_update_case(
    *,
    case_reference: str,
    case_name: str,
    analyst_name: str,
    classification: str,
    selected_tools: list[str],
    created_at: str,
    status: str,
    user_id: int,
    device_label=None,
    adb_serial=None,
    detailed_info=None,
) -> None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO cases (case_reference, case_name, analyst_name, classification,
        selected_tools_json, created_at, status, user_id, device_label,
        adb_serial, detailed_info_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(case_reference) DO UPDATE SET
            case_name=excluded.case_name,
            analyst_name=excluded.analyst_name,
            classification=excluded.classification,
            selected_tools_json=excluded.selected_tools_json,
            status=excluded.status,
            user_id=excluded.user_id,
            device_label=COALESCE(excluded.device_label, device_label),
            adb_serial=COALESCE(excluded.adb_serial, adb_serial),
            detailed_info_json=COALESCE(excluded.detailed_info_json, detailed_info_json)
        """,
        (
            case_reference,
            case_name,
            analyst_name,
            classification,
            json.dumps(selected_tools),
            created_at,
            status,
            user_id,
            device_label,
            adb_serial,
            json.dumps(detailed_info) if detailed_info else None,
        ),
    )
    conn.commit()
    conn.close()


def update_case_status(case_reference: str, status: str) -> None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE cases SET status=? WHERE case_reference=?", (status, case_reference))
    conn.commit()
    conn.close()


def get_case(case_reference: str) -> CaseRow | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM cases WHERE case_reference=?", (case_reference,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return CaseRow(
        case_reference=row["case_reference"],
        case_name=row["case_name"],
        analyst_name=row["analyst_name"],
        classification=row["classification"],
        selected_tools=json.loads(row["selected_tools_json"]),
        created_at=row["created_at"],
        status=row["status"],
        device_label=row["device_label"] if "device_label" in row.keys() else None,
        adb_serial=row["adb_serial"] if "adb_serial" in row.keys() else None,
        detailed_info=json.loads(row["detailed_info_json"]) if "detailed_info_json" in row.keys() and row["detailed_info_json"] else None,
    )


def list_cases(user_id:int,limit: int = 10) -> list[CaseRow]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM cases WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
        (user_id,limit),
    )
    rows = cur.fetchall()
    conn.close()
    out: list[CaseRow] = []
    for r in rows:
        out.append(
            CaseRow(
                case_reference=r["case_reference"],
                case_name=r["case_name"],
                analyst_name=r["analyst_name"],
                classification=r["classification"],
                selected_tools=json.loads(r["selected_tools_json"]),
                created_at=r["created_at"],
                status=r["status"],
                device_label=r["device_label"] if "device_label" in r.keys() else None,
                adb_serial=r["adb_serial"] if "adb_serial" in r.keys() else None,
                detailed_info=json.loads(r["detailed_info_json"]) if "detailed_info_json" in r.keys() and r["detailed_info_json"] else None,
            )
        )
    return out


def upsert_finding(
    *,
    case_reference: str,
    tool_name: str,
    summary: str,
    detail: str,
    status: str,
    severity: str | None,
    recorded_at: str,
) -> None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO case_findings
            (case_reference, tool_name, summary, detail, status, severity, recorded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(case_reference, tool_name) DO UPDATE SET
            summary=excluded.summary,
            detail=excluded.detail,
            status=excluded.status,
            severity=excluded.severity,
            recorded_at=excluded.recorded_at
        """,
        (
            case_reference,
            tool_name,
            summary,
            detail,
            status,
            severity,
            recorded_at,
        ),
    )
    conn.commit()
    conn.close()



def get_findings(case_reference: str) -> dict[str, dict[str, Any]]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT tool_name, summary, detail, status, severity, recorded_at FROM case_findings WHERE case_reference=?",
        (case_reference,),
    )
    rows = cur.fetchall()
    conn.close()
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        out[r["tool_name"]] = {
            "summary": r["summary"],
            "detail": r["detail"],
            "status": r["status"],
            "severity": r["severity"],
            "recorded_at": r["recorded_at"],
        }
    return out

def delete_case(case_reference: str) -> None:
    """Delete a case and its findings from the database."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM cases WHERE case_reference=?", (case_reference,))
    conn.commit()
    conn.close()

