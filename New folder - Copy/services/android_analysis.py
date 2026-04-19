"""Android-oriented forensic parsers and heuristics."""

from __future__ import annotations

import io
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

import pandas as pd
from pandas.api.types import is_numeric_dtype

# Common Android "dangerous" permission groups (API-level naming)
DANGEROUS_PERMISSION_KEYWORDS = (
    "CAMERA",
    "RECORD_AUDIO",
    "READ_SMS",
    "RECEIVE_SMS",
    "SEND_SMS",
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "READ_PHONE_STATE",
    "CALL_PHONE",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
    "READ_MEDIA_",
    "BODY_SENSORS",
    "ACTIVITY_RECOGNITION",
)

ADB_INDICATORS = (
    "adb_enabled",
    "persist.sys.usb.config",
    "ro.adb.secure",
    "adb_keys",
    "adb_wifi_enabled",
)

PROTOCOL_PATTERNS = {
    "IRC": re.compile(r"\b(IRC|JOIN\s+#|:\d+\s+PRIVMSG)\b", re.I),
    "FTP": re.compile(r"\b(FTP|RETR\s+|STOR\s+|USER\s+\w+)\b", re.I),
    "Telnet": re.compile(r"\bTELNET\b|\b23/tcp\b", re.I),
    "SMB": re.compile(r"\b(SMB|\\\\[\w.-]+\\)\b", re.I),
}


@dataclass
class ParseResult:
    ok: bool
    message: str
    data: Any = None


def parse_package_lists(text: str) -> dict[str, list[str]]:
    """Compare 'all' vs 'launcher-visible' package dumps to infer hidden/sideloaded apps."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    all_pkgs: set[str] = set()
    visible: set[str] = set()
    for ln in lines:
        m = re.search(r"package:([^\s]+)", ln)
        if not m:
            continue
        pkg_str = m.group(1).strip()
        if "=" in pkg_str:
            pkg = pkg_str.split("=")[-1]
        else:
            pkg = pkg_str
            
        if "launcher" in ln.lower() or "visible" in ln.lower():
            visible.add(pkg)
        all_pkgs.add(pkg)
        
    def _is_system_or_oem(p: str) -> bool:
        vendors = ("com.android.", "com.google.", "android", "com.motorola.", "com.facebook.", "com.amazon.", "com.qualcomm.", "com.qti.", "vendor.")
        return any(p.startswith(v) for v in vendors) or p == "android"
        
    # If user only pasted one list, treat non-system heuristically
    if not visible and all_pkgs:
        hidden = sorted(p for p in all_pkgs if not _is_system_or_oem(p) and "launcher" not in p)
    else:
        # Filter out common system namespaces to reduce false positives
        hidden_raw = all_pkgs - visible
        hidden = sorted(p for p in hidden_raw if not _is_system_or_oem(p))
        
    return {"all_packages": sorted(all_pkgs), "launcher_visible": sorted(visible), "possibly_hidden": hidden}


def audit_permissions_text(text: str) -> pd.DataFrame:
    rows = []
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or "permission" not in ln.lower():
            continue
        app = None
        m_app = re.search(r"(?:for|package)\s+([a-zA-Z0-9_.]+)", ln, re.I)
        if m_app:
            app = m_app.group(1)
        for kw in DANGEROUS_PERMISSION_KEYWORDS:
            if kw.lower() in ln.lower():
                rows.append({"component": app or "(unknown)", "permission_line": ln, "matched_keyword": kw})
                break
    if not rows:
        for kw in DANGEROUS_PERMISSION_KEYWORDS:
            if kw.lower() in text.lower():
                rows.append({"component": "(parse)", "permission_line": f"Keyword match: {kw}", "matched_keyword": kw})
    return pd.DataFrame(rows)


def parse_sms_csv_or_text(raw: str) -> pd.DataFrame:
    rows = []
    # Try to parse `Row: X address=..., body=..., date=...` format
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        
        if ln.startswith("Row:"):
            addr_m = re.search(r"address=([^,]+)", ln)
            date_m = re.search(r"date=(\d+)", ln)
            
            body_start = ln.find("body=")
            body_end = ln.rfind(", date=") if ", date=" in ln else len(ln)
            body = ln[body_start+5:body_end] if body_start != -1 else ""
            
            num_m = re.search(r"number=([^,]+)", ln)
            type_m = re.search(r"type=([^,]+)", ln)
            
            r = {}
            if addr_m: r["address"] = addr_m.group(1)
            if num_m: r["number"] = num_m.group(1)
            if type_m: r["type"] = type_m.group(1)
            if body: r["body"] = body
            
            if date_m:
                try:
                    r["date"] = pd.to_datetime(int(date_m.group(1)), unit='ms').strftime("%Y-%m-%d %H:%M:%S")
                except:
                    r["date"] = date_m.group(1)
                    
            if not r:
                r["raw"] = ln[:200]
            rows.append(r)
        elif re.search(r"\d{4,}", ln) and not ln.startswith("==="):
            rows.append({"raw": ln[:200]})
            
    if rows:
        return pd.DataFrame(rows)
        
    buf = io.StringIO(raw)
    try:
        df = pd.read_csv(buf, on_bad_lines='skip')
        if len(df.columns) >= 2:
            return df
    except Exception:
        pass
        
    return pd.DataFrame()


def audit_paths_in_text(haystack: str, paths: list[str]) -> list[dict[str, str]]:
    hits = []
    for p in paths:
        if p.strip() and p.strip() in haystack:
            hits.append({"path": p.strip(), "status": "found"})
        elif p.strip():
            hits.append({"path": p.strip(), "status": "not found in upload"})
    return hits


def analyze_adb_indicators(text: str) -> list[dict[str, str]]:
    out = []
    lower = text.lower()
    for ind in ADB_INDICATORS:
        if ind.lower() in lower:
            out.append({"indicator": ind, "found": "yes"})
    if "adb" in lower and not out:
        out.append({"indicator": "generic 'adb' mention", "found": "yes"})
    if not out:
        out.append({"indicator": "ADB-related settings", "found": "no strong match"})
    return out


def parse_location_csv(raw: str) -> ParseResult:
    buf = io.StringIO(raw)
    try:
        df = pd.read_csv(buf)
    except Exception as e:
        return ParseResult(False, str(e), None)
    cols = {c.lower(): c for c in df.columns}
    lat_c = next((cols[k] for k in cols if "lat" in k), None)
    lon_c = next((cols[k] for k in cols if "lon" in k or "lng" in k), None)
    if not lat_c or not lon_c:
        return ParseResult(False, "Need columns containing 'lat' and 'lon'/'lng'.", None)
    df = df.rename(columns={lat_c: "lat", lon_c: "lon"})
    time_c = next((cols[k] for k in cols if "time" in k or "date" in k), None)
    if time_c:
        df["timestamp"] = df[time_c]
    return ParseResult(True, "OK", df)


def detect_protocols_in_log(text: str) -> pd.DataFrame:
    rows = []
    for name, pat in PROTOCOL_PATTERNS.items():
        for i, ln in enumerate(text.splitlines(), 1):
            if pat.search(ln):
                rows.append({"line_no": i, "protocol": name, "snippet": ln[:500]})
    return pd.DataFrame(rows)


def bandwidth_anomalies_from_csv(raw: str, z_threshold: float = 2.0) -> ParseResult:
    buf = io.StringIO(raw)
    try:
        df = pd.read_csv(buf)
    except Exception as e:
        return ParseResult(False, str(e), None)
    num_cols = [c for c in df.columns if is_numeric_dtype(df[c])]
    if not num_cols:
        return ParseResult(False, "No numeric column for bytes/volume.", None)
    col = num_cols[0]
    if "byte" in " ".join(df.columns).lower() or "upload" in " ".join(df.columns).lower():
        for c in df.columns:
            if "byte" in c.lower() or "upload" in c.lower():
                col = c
                break
    s = df[col].astype(float)
    mu, sigma = s.mean(), s.std()
    if sigma == 0 or pd.isna(sigma):
        anomalies = df[s > mu]
    else:
        z = (s - mu) / sigma
        anomalies = df[z.abs() > z_threshold]
    return ParseResult(True, "OK", {"series": df, "column": col, "anomalies": anomalies})
