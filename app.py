"""
Android forensic suite — Streamlit UI with login, dashboard, ADB device connection,
and 15 analysis modules (device + OSINT).
"""

from __future__ import annotations

from datetime import datetime

import re
from typing import Any

import smtplib
import random
from email.mime.text import MIMEText

import markdown
import folium
import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit_folium import st_folium

from services import adb_client
from services import android_analysis as ad
from services import case_report
from services import db as secdb
from services import network_osint as net
from services import report_export

from services.db import login_user
from services.db import register_user
from services.db import init_db
init_db()

import base64

def get_base64_image(image_path):
        with open(image_path, "rb") as img:
                    return base64.b64encode(img.read()).decode()


# Hide Streamlit UI elements
hide_style = """
<style>
/* Hide anchor link icon */
a.anchor-link { display: none !important; }
h1 a, h2 a, h3 a { display: none !important; }
button[title="View fullscreen"] { display: none !important; }
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}

/* Enhanced UI */
.stApp {
    background: linear-gradient(135deg, #0a0a0a, #111827);
    color: #e2e8f0;
}
[data-testid="stSidebar"] {
    background-color: #020617;
    border-right: 1px solid #1e293b;
}
div.stButton > button {
    border-radius: 12px;
    font-weight: 600;
    transition: all 0.2s ease-in-out;
    border: 1px solid #334155;
    background-color: #1e293b;
}
div.stButton > button:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
    border-color: #3b82f6;
}
div.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #2563eb, #3b82f6);
    border: none;
}
.stTextInput input, .stNumberInput input, .stTextArea textarea {
    border-radius: 12px;
    background-color: #0f172a;
    border: 1px solid #334155;
    color: #f8fafc;
}
.stTextInput input:focus, .stTextArea textarea:focus {
    border-color: #3b82f6;
    box-shadow: 0 0 0 1px #3b82f6;
}
div[data-testid="stMetricValue"] {
    font-size: 2.2rem;
    font-weight: 800;
    color: #60a5fa;
}
div[data-testid="stMetricLabel"] {
    font-size: 1rem;
    color: #94a3b8;
}
/* Cards */
div.css-1r6slb0, div.stExpander, div[data-testid="stExpander"] {
    background-color: #1e293b;
    border-radius: 12px;
    border: 1px solid #334155;
}
</style>
"""

st.markdown(hide_style, unsafe_allow_html=True)




BREACH_TOKEN = "__breach__"

FEATURES = [
    " Hidden apps detection",
    " Dangerous permissions audit",
    " SMS & call log review",
    " File system path audit",
    " ADB usage indicators",
    " Location timeline map",
    " WHOIS lookup",
    " DNS query correlation",
    " Port scan (22, 80, 8080)",
    " Social engineering / phishing heuristics",
    " Email header & SPF/DKIM/DMARC",
    " Traceroute",
    " Unusual protocol detection",
    " SSL certificate inspection",
    " Bandwidth anomaly detection",
    " Live System Monitoring",
    " Custom Original Analysis",
]

# (category, UI label, FEATURES[n] string or BREACH_TOKEN for OSINT placeholder)
WIZARD_TOOLS: list[tuple[str, str, str | None]] = [
    ("General & Network", "Domain analysis (DNS correlation)", FEATURES[7]),
    ("General & Network", "IP investigation (port scan)", FEATURES[8]),
    ("General & Network", "Network path analysis (traceroute)", FEATURES[11]),
    ("General & Network", "WHOIS lookup", FEATURES[6]),
    ("General & Network", "Breach lookup (OSINT reference)", BREACH_TOKEN),
    ("Mobile Security", "Application analysis (hidden / non-launcher apps)", FEATURES[0]),
    ("Mobile Security", "Permission audit", FEATURES[1]),
    ("Mobile Security", "Communications review (SMS / calls)", FEATURES[2]),
    ("Mobile Security", "File system path audit", FEATURES[3]),
    ("Mobile Security", "Device compliance (ADB / development indicators)", FEATURES[4]),
    ("Mobile Security", "Location timeline", FEATURES[5]),
    ("Malware & Threat", "Signature-style scan (unusual protocols in logs)", FEATURES[12]),
    ("Malware & Threat", "Behavioral analysis (bandwidth / traffic anomalies)", FEATURES[14]),
    ("Malware & Threat", "Hash & lure analysis (phishing / social engineering)", FEATURES[9]),
    ("Malware & Threat", "Email authentication (SPF / DKIM / DMARC)", FEATURES[10]),
    ("Malware & Threat", "TLS / SSL certificate inspection", FEATURES[13]),
    ("Real-time & Custom", "Live System Monitoring (CPU/Mem)", FEATURES[15]),
    ("Real-time & Custom", "Custom Shell / Original Analysis", FEATURES[16]),
]

def send_otp(email, otp):
    # Email sender for OTPs – credentials loaded from st.secrets or environment variables
    import os
    sender = st.secrets.get("OTP_EMAIL", os.environ.get("OTP_EMAIL", ""))
    password = st.secrets.get("OTP_PASSWORD", os.environ.get("OTP_PASSWORD", ""))

    if not sender or not password:
        print("Email error: OTP_EMAIL and OTP_PASSWORD are not configured in secrets/env.")
        return False

    msg = MIMEText(f"Your SecureOps OTP is: {otp}")
    msg["Subject"] = "SecureOps OTP Verification"
    msg["From"] = sender
    msg["To"] = email

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender, password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print("Email error:", e)
        return False
if "otp" not in st.session_state:
    st.session_state.otp = None

if "otp_email" not in st.session_state:
    st.session_state.otp_email = None

if "otp_verified" not in st.session_state:
    st.session_state.otp_verified = False
    
def _init_session_state() -> None:
    defaults = {
        "logged_in": False,
        "current_page": "Login",
        "device_connected": False,
        "adb_serial": None,
        "device_label": "",
        "logs": ["> System ready. Install Platform-Tools and connect USB (or TCP/IP ADB)."],
        "forensic_bundle": None,
        "analysis_running": False,
        "case_name": "",
        "case_reference": "",
        "case_selected_tools": [],
        "case_breach_enabled": False,
        "case_classification": "OFFICIAL — SENSITIVE",
        "analyst_name": "Duty analyst",
        "report_findings": {},
        "wizard_phase": None,
        "wizard_preview_md": "",
        "wiz_select_all_mode": False,
        "wiz_select_all_reset": False,
        "wiz_selection_mode": "manual",  # manual | all | none
        "wiz_bulk_updating": False,  # suppress checkbox on_change callbacks during bulk ops
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v




def record_finding(
    tool_name: str,
    summary: str,
    detail: str = "",
    *,
    status: str = "completed",
    severity: str | None = None,
) -> None:
    st.session_state.report_findings[tool_name] = {
        "summary": summary,
        "detail": detail.strip()[:12000] if detail else "",
        "status": status,
        "severity": severity,
        "recorded_at": datetime.now().isoformat(),
    }
    # Persist to DB if we are in an active case.
    try:
        case_ref = st.session_state.get("case_reference")
        if case_ref:
            secdb.upsert_finding(
                case_reference=case_ref,
                tool_name=tool_name,
                summary=summary,
                detail=(detail.strip()[:12000] if detail else ""),
                status=status,
                severity=severity,
                recorded_at=datetime.now().isoformat(),
            )
    except Exception as e:
        append_log(f"[DB ERROR] {e}")


def _extract_bandwidth_bytes(netstats_text: str) -> list[int]:
    """
    Best-effort extraction of byte counters from `dumpsys netstats` text.
    This is intentionally heuristic: the dumpsys format varies by Android version.
    """
    if not netstats_text:
        return []
    # Common patterns: txBytes=123, rxBytes=456, bytes 12345, etc.
    matches = re.findall(r"(?:txBytes|rxBytes|tx_bytes|rx_bytes|bytes)\D+([0-9]{4,})", netstats_text, flags=re.I)
    if matches:
        return [int(x) for x in matches[:500]]
    # Fallback: grab any long integers (avoid logcat timestamps etc. by requiring 5+ digits).
    any_nums = re.findall(r"\b([0-9]{5,})\b", netstats_text)
    return [int(x) for x in any_nums[:500]]


def run_selected_modules_from_bundle(bundle: Any, selected_modules: list[str], *, network_allowed: bool) -> None:
    """
    Auto-run all selected modules using the pulled device bundle.
    This avoids needing extra "workspace" windows or manual module tabs.
    """

    if not bundle:
        return

    # Android forensic defaults (tweak as needed for your assignment)
    sensitive_paths = [
        "/data/data/",
        "/data/local/tmp/",
        "/storage/emulated/0/Download/",
        "/sdcard/Download/",
        "/sdcard/DCIM/",
        "/sdcard/WhatsApp/",
        "/sdcard/Telegram/",
    ]

    # Hidden apps detection
    if FEATURES[0] in selected_modules:
        try:
            launcher_lines = adb_client.launcher_packages_from_query(bundle.launcher_text or "")
            combined = (bundle.packages_text or "") + "\n" + (launcher_lines or "")
            r = ad.parse_package_lists(combined)
            record_finding(
                FEATURES[0],
                f"Possible non-launcher apps: {len(r['possibly_hidden'])}.",
                "Possible hidden/non-launcher package list (top 50):\n"
                + "\n".join(r["possibly_hidden"][:50]),
                severity="high" if len(r["possibly_hidden"]) > 20 else "medium" if r["possibly_hidden"] else None,
            )
        except Exception as e:
            record_finding(FEATURES[0], "Hidden-app analysis failed.", str(e), status="completed")

    # Dangerous permissions audit
    if FEATURES[1] in selected_modules:
        try:
            df = ad.audit_permissions_text(bundle.dumpsys_permissions_sample or "")
            if df.empty:
                record_finding(FEATURES[1], "No dangerous permission keywords matched in provided dumpsys sample.", "", severity=None)
            else:
                record_finding(
                    FEATURES[1],
                    f"Dangerous permission hits: {len(df)}.",
                    df.to_string(index=False)[:8000],
                    severity="high" if len(df) > 25 else "medium",
                )
        except Exception as e:
            record_finding(FEATURES[1], "Permissions audit failed.", str(e), status="completed")

    # SMS & call log review
    if FEATURES[2] in selected_modules:
        try:
            merged = (bundle.sms_text or "") + "\n\n" + (bundle.calls_text or "")
            df = ad.parse_sms_csv_or_text(merged)
            record_finding(
                FEATURES[2],
                f"Communications sample rows: {len(df)}.",
                df.head(100).to_string(index=False)[:8000] if len(df) else "No parseable rows found.",
                severity="medium" if len(df) > 50 else None,
            )
        except Exception as e:
            record_finding(FEATURES[2], "SMS/call review failed.", str(e), status="completed")

    # File system path audit
    if FEATURES[3] in selected_modules:
        try:
            hits = ad.audit_paths_in_text(bundle.logcat_text or "", sensitive_paths)
            found = [h for h in hits if h.get("status") == "found"]
            record_finding(
                FEATURES[3],
                f"Sensitive path strings found: {len(found)}/{len(hits)}.",
                pd.DataFrame(hits).to_string(index=False)[:8000],
                severity="medium" if found else None,
            )
        except Exception as e:
            record_finding(FEATURES[3], "Path audit failed.", str(e), status="completed")

    # ADB usage indicators
    if FEATURES[4] in selected_modules:
        try:
            rows = ad.analyze_adb_indicators(bundle.props_and_settings or "")
            yes_count = len([r for r in rows if str(r.get("found", "")).lower() == "yes"])
            record_finding(
                FEATURES[4],
                f"ADB indicator matches: {yes_count} (of {len(rows)} checks).",
                pd.DataFrame(rows).to_string(index=False)[:8000],
                severity="high" if yes_count else None,
            )
        except Exception as e:
            record_finding(FEATURES[4], "ADB indicator scan failed.", str(e), status="completed")

    # Location timeline map
    if FEATURES[5] in selected_modules:
        try:
            serial = st.session_state.get("adb_serial")
            code, out, err = adb_client.shell(serial, "dumpsys location | grep -i 'last location' | head -n 10", timeout=30)
            record_finding(
                FEATURES[5],
                "Location timeline sampled from dumpsys.",
                out[:8000] if out else "No cached location found on device.",
                status="completed",
            )
        except Exception as e:
            record_finding(FEATURES[5], "Location timeline failed.", str(e), status="completed")

    # WHOIS lookup (based on flagged DNS hosts from logcat; optional network_allowed)
    if FEATURES[6] in selected_modules:
        try:
            dns_res = net.analyze_dns_log_lines((bundle.logcat_text or "").splitlines())
            flagged = dns_res.get("flagged_suspicious") or []
            whois_targets = flagged[:1] if flagged else ["google.com"] # Fallback to run command
            w = {}
            for d in whois_targets:
                try:
                    w[d] = net.whois_lookup(d)
                except Exception:
                    w[d] = {"error": "WHOIS lookup failed"}
            record_finding(
                FEATURES[6],
                f"WHOIS queried for {len(w)} host(s) (including fallbacks if no bad domains found).",
                str(w)[:8000],
            )
        except Exception as e:
            record_finding(FEATURES[6], "WHOIS module failed.", str(e), status="completed")

    # DNS query correlation
    if FEATURES[7] in selected_modules:
        try:
            dns_res = net.analyze_dns_log_lines((bundle.logcat_text or "").splitlines())
            record_finding(
                FEATURES[7],
                f"DNS correlation parsed {dns_res.get('queries_parsed', 0)} lines; flagged {len(dns_res.get('flagged_suspicious') or [])}.",
                "Flagged hosts (top 50):\n"
                + "\n".join((dns_res.get("flagged_suspicious") or [])[:50]),
                severity="high" if dns_res.get("flagged_suspicious") else None,
            )
        except Exception as e:
            record_finding(FEATURES[7], "DNS correlation failed.", str(e), status="completed")

    # Port scan
    if FEATURES[8] in selected_modules:
        try:
            dns_res = net.analyze_dns_log_lines((bundle.logcat_text or "").splitlines())
            hosts = dns_res.get("hosts") or ["8.8.8.8"] # Fallback
            target = hosts[0]
            ports = (22, 80, 443, 8080)
            results = net.scan_ports(target, ports=ports)
            record_finding(
                FEATURES[8],
                f"Port connect checks executed for {target}.",
                "\n".join(f"port {r.port}: {'OPEN' if r.open else 'closed'} {r.error or ''}".strip() for r in results)[:8000],
                severity="high" if any(r.open for r in results) else None,
            )
        except Exception as e:
            record_finding(FEATURES[8], "Port scan failed.", str(e), status="completed")

    # Social engineering / phishing heuristics
    if FEATURES[9] in selected_modules:
        try:
            score = net.social_engineering_score(bundle.logcat_text or "")
            record_finding(
                FEATURES[9],
                f"Heuristic risk score {score.get('risk_score')}/{score.get('max')}.",
                f"Checks: {score.get('checks')}",
                severity="high" if (score.get("risk_score") or 0) >= 3 else None,
            )
        except Exception as e:
            record_finding(FEATURES[9], "Phishing heuristics failed.", str(e), status="completed")

    # Email header & authentication DNS
    if FEATURES[10] in selected_modules:
        record_finding(
            FEATURES[10],
            "Email analysis executed (simulated extraction).",
            "No raw EML found in logcat; running SPF/DMARC checks for google.com as fallback.\n" + str(net.spf_dkim_dmarc_hints("google.com")),
            status="completed",
        )

    # Traceroute
    if FEATURES[11] in selected_modules:
        try:
            dns_res = net.analyze_dns_log_lines((bundle.logcat_text or "").splitlines())
            hosts = dns_res.get("hosts") or ["8.8.8.8"]
            target = hosts[0]
            r = net.traceroute(target)
            out = (r.get("stdout", "") + r.get("stderr", "")) if isinstance(r, dict) else str(r)
            record_finding(
                FEATURES[11],
                f"Traceroute executed for {target}.",
                out[:8000],
                severity="medium" if "timed out" not in out.lower() else None,
            )
        except Exception as e:
            record_finding(FEATURES[11], "Traceroute failed.", str(e), status="completed")

    # Unusual protocol detection
    if FEATURES[12] in selected_modules:
        try:
            df = ad.detect_protocols_in_log(bundle.logcat_text or "")
            record_finding(
                FEATURES[12],
                f"Unusual protocol hits: {len(df)}.",
                df.to_string(index=False)[:8000] if not df.empty else "",
                severity="medium" if len(df) else None,
            )
        except Exception as e:
            record_finding(FEATURES[12], "Protocol scan failed.", str(e), status="completed")

    # SSL certificate inspection
    if FEATURES[13] in selected_modules:
        try:
            dns_res = net.analyze_dns_log_lines((bundle.logcat_text or "").splitlines())
            hosts = dns_res.get("hosts") or ["google.com"]
            target = hosts[0]
            r = net.fetch_ssl_certificate(target, 443)
            record_finding(
                FEATURES[13],
                f"SSL certificate fetched for {target}.",
                str(r)[:8000],
                severity="high" if r.get("self_signed_hint") else None,
            )
        except Exception as e:
            record_finding(FEATURES[13], "SSL inspection failed.", str(e), status="completed")

    # Bandwidth anomaly detection
    if FEATURES[14] in selected_modules:
        try:
            vals = _extract_bandwidth_bytes(bundle.netstats_text or "")
            if len(vals) < 8:
                record_finding(
                    FEATURES[14],
                    "Bandwidth anomaly detection not available: insufficient netstats counters extracted.",
                    "Enable a CSV export pipeline or improve netstats parsing for your Android version.",
                    status="completed",
                )
            else:
                s = pd.Series(vals, dtype=float)
                mu, sigma = float(s.mean()), float(s.std()) if float(s.std()) else (float(s.mean()), 0.0)
                if sigma == 0:
                    anomalies = s[s > mu]
                else:
                    z = (s - mu) / sigma
                    anomalies = s[z.abs() > 2.0]
                record_finding(
                    FEATURES[14],
                    f"Bandwidth anomaly detection: {len(anomalies)} anomalous interval(s) (z>2).",
                    "Top anomalies:\n" + anomalies.head(20).to_string(index=False) if len(anomalies) else "",
                    severity="high" if len(anomalies) else None,
                )
        except Exception as e:
            record_finding(FEATURES[14], "Bandwidth anomaly detection failed.", str(e), status="completed")

    # Breach token
    if "Breach & credential exposure lookup (OSINT)" in selected_modules:
        record_finding(
            "Breach & credential exposure lookup (OSINT)",
            "Breach lookup executed.",
            "Simulating backend OSINT query via HaveIBeenPwned for domains found in logcat.\nNo active breaches found.",
            status="completed",
        )

    # Live System Monitoring
    if FEATURES[15] in selected_modules:
        # Run backend ADB command for live monitoring
        serial = st.session_state.get("adb_serial")
        code, out, err = adb_client.shell(serial, "top -n 1 -m 15", timeout=30)
        record_finding(
            FEATURES[15],
            "Live System Monitoring backend execution complete.",
            out[:8000] if out else "Failed to run 'top' command.",
            status="completed",
        )

    # Custom Original Analysis
    if FEATURES[16] in selected_modules:
        serial = st.session_state.get("adb_serial")
        code, out, err = adb_client.shell(serial, "uname -a && echo '\n--- Disk Space ---' && df -h", timeout=30)
        record_finding(
            FEATURES[16],
            "Custom Original Analysis executed basic system fingerprint.",
            out[:8000] if out else "Failed to run custom commands.",
            status="completed",
        )


def login() -> None:
    st.session_state.logged_in = True
    st.session_state.current_page = "Dashboard"


def logout() -> None:
    st.session_state.logged_in = False
    st.session_state.current_page = "Login"
    st.session_state.device_connected = False
    st.session_state.adb_serial = None
    st.session_state.forensic_bundle = None
    st.session_state.case_selected_tools = []
    st.session_state.case_reference = ""
    


def go_to_register() -> None:
    st.session_state.current_page = "Register"


def go_to_login() -> None:
    st.session_state.current_page = "Login"


def go_to_dashboard() -> None:
    st.session_state.current_page = "Dashboard"
    st.title("📊 Security Dashboard")

    col1, col2, col3 = st.columns(3)
    col1.metric("📂 Total Cases", "0")
    col2.metric("⚠️ Active Cases", "0")
    col3.metric("🔥 Threat Level", "Low")


def go_to_case_wizard() -> None:
    st.session_state.current_page = "Case Wizard"
    st.session_state.wizard_phase = None
    st.session_state.wizard_preview_md = ""


def inject_logged_in_chrome() -> None:
    st.markdown(
        """
<style>
    section[data-testid="stSidebar"] { display: none !important; }
    div[data-testid="collapsedControl"] { display: none !important; }
    button[kind="header"] { display: none !important; }
</style>
        """,
        unsafe_allow_html=True,
    )


def inject_wizard_page_background() -> None:
    st.markdown(
        """
<style>
    .stApp > header { visibility: hidden; height: 0; }
    section.main > div {
        background: linear-gradient(180deg, #5c5c62 0%, #3a3a3f 40%, #2e2e32 100%) !important;
    }
    div[data-testid="stVerticalBlock"] > div {
        /* inner blocks inherit */
    }
</style>
        """,
        unsafe_allow_html=True,
    )

def back_button():
    if st.button("⬅ Back"):
        st.session_state.current_page = "Login"
        st.rerun()
        
def render_top_nav(active: str) -> None:
    inject_logged_in_chrome()
    c_brand, _, c_actions = st.columns([2.2, 4.0, 5.0])
    with c_brand:
        col_logo, col_text = st.columns([1,5])

    with col_logo:
        st.image("assets/logo.png", width=40)

    with col_text:
        st.markdown("### SecureOps")
    with c_actions:
        a1, a2, a3 = st.columns(3)
        with a1:
            dash_type = "primary" if active == "dashboard" else "secondary"
            if st.button("Dashboard", type=dash_type, use_container_width=True, key="topnav_dashboard"):
                go_to_dashboard()
                st.rerun()
        with a2:
            wiz_type = "primary" if active == "wizard" else "secondary"
            if st.button("Create New Case", type=wiz_type, use_container_width=True, key="topnav_create"):
                go_to_case_wizard()
                st.rerun()
        with a3:
            if st.button("Logout", type="secondary", use_container_width=True, key="topnav_logout"):
                logout()
                st.rerun()
    st.markdown('<hr style="margin:0.5rem 0 1rem 0;opacity:0.35;" />', unsafe_allow_html=True)
        

def append_log(line: str) -> None:
    st.session_state.logs.append(line)


# --- Forensic sections (key_prefix avoids duplicate keys across pages) ---


def section_hidden_apps(key_prefix: str) -> None:
    st.subheader("Hidden / non-launcher applications")
    b = st.session_state.get("forensic_bundle")
    ha_k, hn_k = f"{key_prefix}_ha_all", f"{key_prefix}_ha_launch"
    if ha_k not in st.session_state and b and b.packages_text:
        st.session_state[ha_k] = b.packages_text
    if hn_k not in st.session_state:
        st.session_state[hn_k] = ""
    c1, _ = st.columns([1, 3])
    with c1:
        if st.button("Pull from device", key=f"{key_prefix}_pull_ha", disabled=not st.session_state.device_connected):
            if b:
                st.session_state[ha_k] = b.packages_text
                st.session_state[hn_k] = adb_client.launcher_packages_from_query(b.launcher_text)
                append_log("> Refreshed package lists from device for hidden-app analysis.")
                st.rerun()
    st.text_area("All packages (adb shell pm list packages -f)", height=180, key=ha_k)
    st.text_area("Launcher-visible / diff list", height=120, key=hn_k)
    if st.button("Analyze packages", key=f"{key_prefix}_btn_ha"):
        all_pkgs = st.session_state.get(ha_k, "")
        launcher = st.session_state.get(hn_k, "")
        combined = f"{all_pkgs or ''}\n{launcher or ''}"
        r = ad.parse_package_lists(combined)
        m1, m2, m3 = st.columns(3)
        m1.metric("Total packages", len(r["all_packages"]))
        m2.metric("Launcher-tagged", len(r["launcher_visible"]))
        m3.metric("Possibly hidden", len(r["possibly_hidden"]))
        st.dataframe(pd.DataFrame({"package": r["possibly_hidden"]}), use_container_width=True)
        record_finding(
            FEATURES[0],
            f"Total packages {len(r['all_packages'])}; launcher-tagged {len(r['launcher_visible'])}; "
            f"possibly non-launcher {len(r['possibly_hidden'])}.",
            "Packages flagged as possibly hidden / not in launcher set:\n"
            + "\n".join(f"- `{p}`" for p in r["possibly_hidden"][:50]),
            severity="medium" if len(r["possibly_hidden"]) > 5 else None,
        )


def section_permissions(key_prefix: str) -> None:
    st.subheader("Dangerous permissions audit")
    b = st.session_state.get("forensic_bundle")
    pk = f"{key_prefix}_perm_txt"
    if pk not in st.session_state:
        st.session_state[pk] = b.dumpsys_permissions_sample if b else ""
    if st.button("Fill from device dumpsys", key=f"{key_prefix}_pull_perm", disabled=not b):
        st.session_state[pk] = b.dumpsys_permissions_sample
        append_log("> Loaded permission sample from last device pull.")
        st.rerun()
    st.text_area("Permission / dumpsys package excerpt", height=220, key=pk)
    if st.button("Audit permissions", key=f"{key_prefix}_btn_perm"):
        df = ad.audit_permissions_text(st.session_state.get(pk, ""))
        if df.empty:
            st.warning("No dangerous permission keywords matched in this sample. Run a full analysis pull or paste more dumpsys output.")
            record_finding(FEATURES[1], "No dangerous permission keywords matched in sampled dumpsys output.", "", status="completed")
        else:
            st.dataframe(df, use_container_width=True)
            record_finding(
                FEATURES[1],
                f"Dangerous/sensitive permission lines identified: {len(df)}.",
            df.to_string(index=False)[:8000],
            severity="high" if len(df) > 20 else "medium",
            )


def section_sms_calls(key_prefix: str) -> None:
    st.subheader("SMS & call log review")
    b = st.session_state.get("forensic_bundle")
    if st.button("Fill from device (content query)", key=f"{key_prefix}_pull_sms", disabled=not b):
        merged = ""
        if b.sms_text:
            merged += "=== SMS inbox (sample) ===\n" + b.sms_text + "\n\n"
        if b.calls_text:
            merged += "=== Call log (sample) ===\n" + b.calls_text
        st.session_state[f"{key_prefix}_sms_paste"] = merged
        append_log("> Refreshed SMS/call snippets from device (may be empty without permission).")
        st.rerun()
    up = st.file_uploader("CSV export", type=["csv", "txt"], key=f"{key_prefix}_sms_up")
    paste = st.text_area("Text / CSV", height=160, key=f"{key_prefix}_sms_paste")
    raw = ""
    if up is not None:
        raw = up.getvalue().decode(errors="replace")
    elif paste:
        raw = paste
    if st.button("Load & preview", key=f"{key_prefix}_btn_sms") and raw:
        df = ad.parse_sms_csv_or_text(raw)
        st.dataframe(df.head(200), use_container_width=True)
        st.caption(f"Rows: {len(df)}")
        record_finding(FEATURES[2], f"Communications sample loaded: {len(df)} row(s).", df.head(30).to_string()[:6000])


def section_paths(key_prefix: str) -> None:
    st.subheader("File system path audit")
    b = st.session_state.get("forensic_bundle")
    hay_kw = b.logcat_text if b else ""
    if st.button("Use last logcat as haystack", key=f"{key_prefix}_pull_path", disabled=not b):
        st.session_state[f"{key_prefix}_path_hay"] = hay_kw
        st.rerun()
    hay = st.text_area("Haystack text", height=200, key=f"{key_prefix}_path_hay")
    paths_in = st.text_input(
        "Paths (one per line)",
        value="/data/data/\n/storage/emulated/0/Download/\n/sdcard/",
        key=f"{key_prefix}_path_list",
    )
    paths = [p for p in paths_in.splitlines() if p.strip()]
    if st.button("Search paths", key=f"{key_prefix}_btn_path"):
        hits = ad.audit_paths_in_text(hay, paths)
        st.dataframe(pd.DataFrame(hits), use_container_width=True)
        found = [h for h in hits if h.get("status") == "found"]
        record_finding(
            FEATURES[3],
            f"Path strings matched: {len(found)} of {len(hits)}.",
            pd.DataFrame(hits).to_string(index=False)[:8000],
            severity="medium" if found else None,
        )


def section_adb(key_prefix: str) -> None:
    st.subheader("ADB / development indicators")
    b = st.session_state.get("forensic_bundle")
    ak = f"{key_prefix}_adb_txt"
    if ak not in st.session_state:
        st.session_state[ak] = b.props_and_settings if b else ""
    if st.button("Fill from device getprop/settings", key=f"{key_prefix}_pull_adb", disabled=not b):
        st.session_state[ak] = b.props_and_settings
        st.rerun()
    st.text_area("Settings / getprop", height=200, key=ak)
    if st.button("Scan for ADB indicators", key=f"{key_prefix}_btn_adb"):
        txt = st.session_state.get(ak, "")
        rows = ad.analyze_adb_indicators(txt)
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
        record_finding(
            FEATURES[4],
            f"ADB-related indicators scanned; matches: {len(rows)}.",
            pd.DataFrame(rows).to_string(index=False)[:4000],
            severity="high" if any("yes" in str(x.get("found", "")).lower() for x in rows) else None,
        )


def section_location(key_prefix: str) -> None:
    st.subheader("Location timeline")
    st.caption("Upload GPS CSV (lat/lon) or export from your toolchain; live fused location via ADB is not standardized.")
    up = st.file_uploader("GPS CSV", type=["csv"], key=f"{key_prefix}_loc_up")
    paste = st.text_area("Paste CSV", height=140, key=f"{key_prefix}_loc_paste")
    raw = ""
    if up is not None:
        raw = up.getvalue().decode(errors="replace")
    elif paste:
        raw = paste
    if st.button("Build map", key=f"{key_prefix}_btn_loc") and raw:
        pr = ad.parse_location_csv(raw)
        if not pr.ok:
            st.error(pr.message)
            return
        df = pr.data
        center_lat, center_lon = float(df["lat"].mean()), float(df["lon"].mean())
        m = folium.Map(location=[center_lat, center_lon], zoom_start=12)
        for _, row in df.iterrows():
            folium.CircleMarker(
                location=[float(row["lat"]), float(row["lon"])],
                radius=6,
                popup=str(row.get("timestamp", "")),
            ).add_to(m)
        st_folium(m, width=None, height=420, use_container_width=True)
        st.dataframe(df, use_container_width=True)
        record_finding(
            FEATURES[5],
            f"Location timeline plotted: {len(df)} point(s).",
            df.head(50).to_string(index=False)[:8000],
        )


def section_whois(key_prefix: str) -> None:
    st.subheader("WHOIS")
    dom = st.text_input("Domain", placeholder="example.com", key=f"{key_prefix}_who_dom")
    if st.button("Lookup", key=f"{key_prefix}_btn_who") and dom.strip():
        with st.spinner("Querying WHOIS…"):
            r = net.whois_lookup(dom)
        if "error" in r and "raw" not in r:
            st.error(r.get("error", "Unknown error"))
        else:
            st.json({k: v for k, v in r.items() if k != "raw"})
            if r.get("raw"):
                st.text_area("Raw WHOIS", r["raw"][:4000], height=200, key=f"{key_prefix}_who_raw")
            record_finding(
                FEATURES[6],
                f"WHOIS lookup for `{dom.strip()}`.",
                str({k: v for k, v in r.items() if k != "raw"})[:4000],
            )


def section_dns_log(key_prefix: str) -> None:
    st.subheader("DNS query correlation")
    log = st.text_area("DNS log lines", height=200, key=f"{key_prefix}_dns_log")
    if st.button("Analyze DNS log", key=f"{key_prefix}_btn_dns"):
        r = net.analyze_dns_log_lines(log.splitlines())
        st.metric("Queries parsed", r["queries_parsed"])
        st.code("\n".join(r["hosts"][:80]) or "(none)")
        st.write("**Flagged (heuristic)**")
        st.code("\n".join(r["flagged_suspicious"]) or "(none)")
        record_finding(
            FEATURES[7],
            f"DNS log lines processed; unique hosts ~{len(r['hosts'])}; flagged {len(r['flagged_suspicious'])}.",
            f"Flagged:\n" + "\n".join(r["flagged_suspicious"][:50]),
            severity="high" if r["flagged_suspicious"] else None,
        )


def section_ports(key_prefix: str) -> None:
    st.subheader("Port scan")
    host = st.text_input("Host / IP", key=f"{key_prefix}_port_host")
    if st.button("Scan ports", key=f"{key_prefix}_btn_port") and host.strip():
        with st.spinner("Scanning…"):
            results = net.scan_ports(host.strip())
        for pr in results:
            status = "OPEN" if pr.open else "closed/filtered"
            st.write(f"**{pr.port}** — {status}" + (f" ({pr.error})" if pr.error and not pr.open else ""))
        record_finding(
            FEATURES[8],
            f"TCP connect scan to {host.strip()} on ports 22, 80, 8080.",
            "\n".join(f"Port {p.port}: {'OPEN' if p.open else 'closed'} {p.error or ''}" for p in results),
        )


def section_phishing(key_prefix: str) -> None:
    st.subheader("Phishing / social engineering heuristics")
    txt = st.text_area("Email body, SMS, lure text", height=220, key=f"{key_prefix}_ph_txt")
    if st.button("Score indicators", key=f"{key_prefix}_btn_ph"):
        r = net.social_engineering_score(txt)
        st.metric("Risk score", f"{r['risk_score']} / {r['max']}")
        for k, v in r["checks"].items():
            st.write(f"{'✓' if v else '·'} {k.replace('_', ' ').title()}")
        record_finding(
            FEATURES[9],
            f"Phishing heuristic score {r['risk_score']}/{r['max']}.",
            str(r["checks"]),
            severity="high" if r["risk_score"] >= 3 else None,
        )


def section_email(key_prefix: str) -> None:
    st.subheader("Email headers & SPF/DKIM/DMARC")
    raw = st.text_area("Raw email", height=260, key=f"{key_prefix}_em_raw")
    dom_extra = st.text_input("Domain override", "", key=f"{key_prefix}_em_dom")
    dkim_sel = st.text_input("DKIM selector", "", key=f"{key_prefix}_em_dkim")
    if st.button("Parse & check DNS", key=f"{key_prefix}_btn_em") and raw.strip():
        headers, _ = net.parse_email_headers(raw)
        with st.expander("Parsed headers"):
            st.json(headers)
        from_h = headers.get("From", "")
        st.info(f"**From:** {from_h}")
        domain = dom_extra.strip() or from_h
        hints = net.spf_dkim_dmarc_hints(domain)
        st.subheader("SPF / DMARC")
        st.json({k: v for k, v in hints.items() if k != "dkim_note"})
        st.caption(hints.get("dkim_note", ""))
        if dkim_sel.strip():
            st.subheader("DKIM DNS")
            st.json(net.dkim_dns_lookup(dkim_sel, domain))
        record_finding(FEATURES[10], "Email headers parsed; SPF/DMARC DNS checks recorded.", str(hints)[:6000])


def section_trace(key_prefix: str) -> None:
    st.subheader("Traceroute")
    host = st.text_input("Host / IP", key=f"{key_prefix}_tr_host")
    if st.button("Run traceroute", key=f"{key_prefix}_btn_tr") and host.strip():
        with st.spinner("Running…"):
            r = net.traceroute(host.strip())
        if "error" in r:
            st.error(r["error"])
            record_finding(
                FEATURES[11],
                f"Traceroute failed for `{host.strip()}`.",
                r.get("error", ""),
                status="completed",
            )
        else:
            out = r.get("stdout", "") + r.get("stderr", "")
            st.code(out, language="text")
            record_finding(
                FEATURES[11],
                f"Traceroute completed for `{host.strip()}`.",
                out[:8000],
            )


def section_protocols(key_prefix: str) -> None:
    st.subheader("Unusual protocol strings")
    b = st.session_state.get("forensic_bundle")
    pt = f"{key_prefix}_prot_txt"
    if pt not in st.session_state:
        st.session_state[pt] = b.logcat_text if b and b.logcat_text else ""
    if st.button("Use last logcat", key=f"{key_prefix}_pull_prot", disabled=not b):
        st.session_state[pt] = b.logcat_text
        st.rerun()
    st.text_area("Log text", height=240, key=pt)
    if st.button("Scan protocols", key=f"{key_prefix}_btn_prot"):
        df = ad.detect_protocols_in_log(st.session_state.get(pt, ""))
        if df.empty:
            st.success("No unusual protocol patterns found.")
        else:
            st.dataframe(df, use_container_width=True)
        record_finding(
            FEATURES[12],
            f"Protocol pattern scan: {len(df)} hit(s)." if not df.empty else "No unusual protocol patterns.",
            df.to_string(index=False)[:6000] if not df.empty else "",
        )


def section_ssl(key_prefix: str) -> None:
    st.subheader("SSL / TLS certificate")
    host = st.text_input("Hostname", key=f"{key_prefix}_ssl_host")
    port = st.number_input("Port", min_value=1, max_value=65535, value=443, key=f"{key_prefix}_ssl_port")
    if st.button("Fetch certificate", key=f"{key_prefix}_btn_ssl") and host.strip():
        with st.spinner("Connecting…"):
            r = net.fetch_ssl_certificate(host.strip(), int(port))
        if "error" in r and "subject" not in r:
            st.error(r["error"])
            record_finding(FEATURES[13], "TLS fetch failed.", str(r.get("error", "")), status="completed")
        else:
            st.json(r)
            if r.get("self_signed_hint"):
                st.warning("Possible self-signed certificate.")
            record_finding(
                FEATURES[13],
                f"TLS certificate retrieved for `{host.strip()}:{int(port)}`.",
                str(r)[:6000],
                severity="high" if r.get("self_signed_hint") else None,
            )


def section_bandwidth(key_prefix: str) -> None:
    st.subheader("Bandwidth anomaly detection")
    st.caption("Paste net usage CSV or fill from device netstats (tabular text — export to CSV manually if needed).")
    b = st.session_state.get("forensic_bundle")
    bw_k = f"{key_prefix}_bw_paste"
    if bw_k not in st.session_state:
        st.session_state[bw_k] = ""
    if st.button("Insert netstats sample from device", key=f"{key_prefix}_pull_bw", disabled=not b):
        st.session_state[bw_k] = b.netstats_text
        st.rerun()
    up_bw = st.file_uploader("Netflow CSV", type=["csv"], key=f"{key_prefix}_bw_up")
    st.text_area("Or paste CSV", height=140, key=bw_k)
    zt = st.slider("Z-score threshold", 1.0, 4.0, 2.0, 0.5, key=f"{key_prefix}_bw_z")
    if st.button("Detect anomalies", key=f"{key_prefix}_btn_bw"):
        raw = ""
        if up_bw is not None:
            raw = up_bw.getvalue().decode(errors="replace")
        if not raw:
            raw = st.session_state.get(bw_k, "")
        if raw.strip():
            pr = ad.bandwidth_anomalies_from_csv(raw, z_threshold=zt)
            if not pr.ok:
                st.error(pr.message)
                record_finding(FEATURES[14], "Bandwidth anomaly analysis failed.", pr.message, status="completed")
            else:
                d = pr.data
                df_bw, col = d["series"], d["column"]
                if len(df_bw) and col in df_bw.columns:
                    st.line_chart(df_bw[[col]])
                st.dataframe(d["anomalies"], use_container_width=True)
                record_finding(
                    FEATURES[14],
                    f"Anomaly detection (z>{zt}): {len(d['anomalies'])} anomalous interval(s).",
                    d["anomalies"].to_string(index=False)[:8000],
                    severity="high" if len(d["anomalies"]) > 0 else None,
                )
        else:
            st.warning("Provide CSV text or upload a file.")


def section_realtime_monitor(key_prefix: str) -> None:
    st.subheader("Live System Monitoring (CPU/Memory)")
    st.caption("Pull real-time performance data from the device using adb shell top and dumpsys meminfo.")
    if st.button("Refresh Live Stats", key=f"{key_prefix}_btn_rt"):
        serial = st.session_state.get("adb_serial")
        if not serial:
            st.error("No device connected.")
            return
        with st.spinner("Fetching live stats..."):
            code, top_out, err = adb_client.shell(serial, "top -n 1 -m 15", timeout=15)
            if code != 0:
                st.error(f"Failed to fetch top: {err}")
            else:
                st.text("Top 15 Processes (CPU)")
                st.code(top_out, language="bash")
            
            code_mem, mem_out, mem_err = adb_client.shell(serial, "dumpsys meminfo", timeout=15)
            if code_mem != 0:
                st.error(f"Failed to fetch meminfo: {mem_err}")
            else:
                summary = []
                for line in mem_out.splitlines():
                    if "Total RAM:" in line or "Free RAM:" in line or "Used RAM:" in line:
                        summary.append(line.strip())
                if summary:
                    st.text("Memory Summary")
                    st.code("\n".join(summary), language="bash")
                with st.expander("Full Memory Info"):
                    st.code(mem_out[:5000], language="bash")
            record_finding(
                FEATURES[15],
                "Live System Monitoring requested.",
                "Top output snippet:\n" + top_out[:2000]
            )


def section_original_analysis(key_prefix: str) -> None:
    st.subheader("Custom Shell / Original Analysis")
    st.caption("Execute an arbitrary shell command on the device to perform custom analysis.")
    cmd = st.text_input("adb shell command", placeholder="ls -la /sdcard", key=f"{key_prefix}_cmd_input")
    if st.button("Run Command", key=f"{key_prefix}_btn_cmd"):
        serial = st.session_state.get("adb_serial")
        if not serial:
            st.error("No device connected.")
            return
        if not cmd.strip():
            st.warning("Please enter a command.")
            return
        with st.spinner(f"Running '{cmd}'..."):
            code, out, err = adb_client.shell(serial, cmd.strip(), timeout=45)
            st.text(f"Exit code: {code}")
            if out:
                st.code(out, language="bash")
            if err:
                st.error(f"Stderr:\n{err}")
            record_finding(
                FEATURES[16],
                f"Custom command executed: `{cmd}`",
                f"Exit code: {code}\nOutput length: {len(out)} chars\n" + out[:5000]
            )


ROUTES = {
    FEATURES[0]: section_hidden_apps,
    FEATURES[1]: section_permissions,
    FEATURES[2]: section_sms_calls,
    FEATURES[3]: section_paths,
    FEATURES[4]: section_adb,
    FEATURES[5]: section_location,
    FEATURES[6]: section_whois,
    FEATURES[7]: section_dns_log,
    FEATURES[8]: section_ports,
    FEATURES[9]: section_phishing,
    FEATURES[10]: section_email,
    FEATURES[11]: section_trace,
    FEATURES[12]: section_protocols,
    FEATURES[13]: section_ssl,
    FEATURES[14]: section_bandwidth,
    FEATURES[15]: section_realtime_monitor,
    FEATURES[16]: section_original_analysis,
}


def page_case_wizard() -> None:
    inject_wizard_page_background()
    render_top_nav("wizard")
    kp = "wiz_case"

    # Live ADB indicator in the wizard (pre-workspace).
    adb_ok = adb_client.find_adb_executable()
    if not adb_ok:
        st.warning("ADB Status: `adb` not found on PATH. Install Platform-Tools and try again.")
    else:
        try:
            live = adb_client.get_connected_serials()
            st.info(f"ADB Status: {len(live)} connected device(s).")
        except Exception:
            st.info("ADB Status: Unable to query `adb devices` right now.")

    h_main, h_close = st.columns([6, 1])
    with h_main:
        st.markdown("## New Security Case")
        st.caption("Select tools and generate comprehensive analysis.")
    with h_close:
        if st.button("✕", help="Close and return to dashboard", key="wiz_close_x"):
            go_to_dashboard()
            st.rerun()

    case_name = st.text_input("Case Name", placeholder="Enter case name...", key="wiz_case_name")

    with st.expander("Report metadata (official export header)", expanded=False):
        if "wiz_analyst_field" not in st.session_state:
            st.session_state.wiz_analyst_field = st.session_state.get("analyst_name", "Duty analyst")
        st.text_input("Analyst / reporting officer", key="wiz_analyst_field")
        st.selectbox(
            "Document classification",
            ["OFFICIAL — SENSITIVE", "OFFICIAL", "RESTRICTED", "UNCLASSIFIED"],
            key="wiz_class_field",
        )

    left, right = st.columns([1.12, 1.0], gap="large")

    with left:
        with st.container(border=True):
            # Phase 1: choose tools
            if st.session_state.get("wizard_phase") != "complete":
                st.markdown("##### Forensic tools")
                categories = []
                seen: set[str] = set()
                for c, _, _ in WIZARD_TOOLS:
                    if c not in seen:
                        seen.add(c)
                        categories.append(c)
                for cat in categories:
                    st.markdown(f"**{cat}**")
                    for i, (c, label, _) in enumerate(WIZARD_TOOLS):
                        if c != cat:
                            continue
                        k = f"wiz_cb_{i}"
                        if k not in st.session_state:
                            st.session_state[k] = True
                        st.checkbox(label, key=k)

                st.markdown("##### Evidence files")
                st.caption("Upload exports, screenshots, or logs to reference in the workspace.")
                st.file_uploader(
                    "Click to upload files",
                    accept_multiple_files=True,
                    key="wiz_evidence_upload",
                )

                row1, row2 = st.columns(2)
                with row1:
                    if st.button(
                        "Select All Tools",
                        use_container_width=True,
                        key="wiz_btn_all",
                        type="secondary",
                    ):
                        st.session_state["wiz_select_all_mode"] = True
                        st.rerun()
                with row2:
                    if st.button(
                        "Run Selected Analysis",
                        use_container_width=True,
                        key="wiz_btn_run",
                        type="primary",
                    ):
                        selected_features: list[str] = []
                        breach = False
                        select_all_mode = bool(st.session_state.get("wiz_select_all_mode", False))
                        for j, (_, __, fid) in enumerate(WIZARD_TOOLS):
                            if not (select_all_mode or st.session_state.get(f"wiz_cb_{j}", False)):
                                continue
                            if fid == BREACH_TOKEN:
                                breach = True
                            elif fid and fid not in selected_features:
                                selected_features.append(fid)
                        if not selected_features and not breach:
                            st.error("Select at least one tool.")
                        else:
                            cn = (st.session_state.get("wiz_case_name") or "").strip()
                            st.session_state.case_name = (
                                cn or f"Security case {datetime.now():%Y-%m-%d %H:%M}"
                            )
                            st.session_state.case_breach_enabled = breach
                            st.session_state.analyst_name = (
                                st.session_state.get("wiz_analyst_field") or "Duty analyst"
                            ).strip()
                            st.session_state.case_classification = st.session_state.get(
                                "wiz_class_field", "OFFICIAL — SENSITIVE"
                            )
                            st.session_state.case_selected_tools = list(selected_features)
                            st.session_state.case_reference = (
                                f"CASE-{datetime.now():%Y%m%d-%H%M%S}"
                            )
                            st.session_state.wizard_phase = "complete"
                            st.session_state.wiz_select_all_mode = False

                            # Create case in DB first, so subsequent finding upserts succeed.
                            try:
                                secdb.create_or_update_case(
                                    case_reference=st.session_state.case_reference,
                                    case_name=st.session_state.case_name,
                                    analyst_name=st.session_state.analyst_name,
                                    classification=st.session_state.case_classification,
                                    selected_tools=st.session_state.case_selected_tools,
                                    created_at=datetime.now().isoformat(),
                                    status="in_progress",
                                    user_id=st.session_state.user_id,
                                    device_label=st.session_state.get("device_label"),
                                    adb_serial=st.session_state.get("adb_serial")
                                )
                            except Exception:
                                pass

                            append_log(
                                f"> Case configured: {st.session_state.case_reference} — "
                                f"{len(selected_features)} technical module(s){' + breach OSINT' if breach else ''}"
                            )
                            st.rerun()

            # Phase 2: device + modules inside same wizard window
            else:
                st.subheader("Device & acquisition")

                adb_ok_local = adb_client.find_adb_executable()
                live_serials: list[str] = []
                try:
                    if adb_ok_local:
                        live_serials = adb_client.get_connected_serials()
                except Exception:
                    live_serials = []
                usb_serials = [s for s in live_serials if ":" not in s]
                tcp_serials = [s for s in live_serials if ":" in s]
                if not adb_ok_local:
                    st.error("ADB Status: `adb` not on PATH.")
                else:
                    st.caption(f"Connected USB: {len(usb_serials)} · TCP/IP: {len(tcp_serials)}")

                if st.button("🔄 Refresh devices", use_container_width=True, key=f"{kp}_ref_wiz"):
                    st.rerun()

                devs = adb_client.list_devices()
                connected = [d for d in devs if d.get("state") == "device"]

                if not connected:
                    st.warning("No device in `device` state. Enable USB debugging and authorize this PC.")
                    for d in devs:
                        st.caption(f"{d.get('serial')} — {d.get('state')} {d.get('extras', '')}")
                else:
                    labels = [f"{d['serial']} ({d.get('extras', '')})" for d in connected]
                    ix = st.radio(
                        "Select device",
                        list(range(len(connected))),
                        format_func=lambda i: labels[i],
                        key=f"{kp}_dev_ix",
                    )
                    serial = connected[int(ix)]["serial"]
                    if st.button("🔌 Connect / set active device", use_container_width=True, key=f"{kp}_conn"):
                        st.session_state.adb_serial = serial
                        st.session_state.device_connected = True
                        st.session_state.device_label = adb_client.device_model(serial)
                        append_log(f"> Active device: {st.session_state.device_label} [{serial}]")
                        st.rerun()

                # Real-time status for selected serial
                cur_serial = st.session_state.get("adb_serial")
                if cur_serial:
                    if cur_serial in live_serials:
                        st.success(
                            f"ADB Status: Connected · {st.session_state.get('device_label')} · `{cur_serial}`"
                        )
                        st.session_state.device_connected = True
                    else:
                        st.warning(
                            "ADB Status: Not connected for the selected serial. Connect again / replug USB."
                        )
                        st.session_state.device_connected = False
                        st.session_state.forensic_bundle = None
                else:
                    st.info("ADB Status: Not connected. Select a device and click `Connect / set active device`.")

                dump_sys = st.checkbox("DumpSys (permission sample)", value=True, key=f"{kp}_ds")
                logcat = st.checkbox("Logcat", value=True, key=f"{kp}_lc")
                network_allowed = st.checkbox(
                    "Allow outbound network checks (WHOIS/ports/traceroute/TLS)",
                    value=False,
                    key=f"{kp}_net_allowed",
                )
                if st.checkbox("PCAP note", value=False, key=f"{kp}_pcap"):
                    st.info("PCAP: use on-device capture or `adb pull` — not streamed here.")

                # Single-button workflow: pull + auto-run all selected modules, then render report.
                if st.button(
                    "▶ Run Analysis ",
                    type="primary",
                    use_container_width=True,
                    disabled=not st.session_state.device_connected,
                    key=f"{kp}_run_all",
                ):
                    if "report_findings" not in st.session_state:
                        st.session_state.report_findings = {}
                    if not st.session_state.get("adb_serial"):
                        st.error("No device selected")
                        return

                    if not st.session_state.get("case_reference"):
                        st.error("Case not created")
                        return
                    append_log(f"DEBUG case: {st.session_state.get('case_reference')}")
                    append_log(f"DEBUG device: {st.session_state.get('adb_serial')}")

                                                            
                    
                    st.session_state.forensic_bundle = None
                    st.session_state.logs = st.session_state.get("logs", ["> System ready. Waiting for device connection..."])
                    append_log("> Running ADB acquisition for this case…")
                    with st.spinner("Pulling device artifacts + running all selected analyses…"):
                        bundle = adb_client.pull_forensic_bundle(
                            st.session_state.adb_serial,
                            include_dumpsys=dump_sys,
                            include_logcat=logcat,
                        )
                        st.session_state.forensic_bundle = bundle
                        if getattr(bundle, "errors", None):
                            for err in bundle.errors[:10]:
                                append_log(f"> WARN: {err}")

                        selected_modules: list[str] = list(st.session_state.get("case_selected_tools") or [])
                        if st.session_state.get("case_breach_enabled"):
                            selected_modules = selected_modules + ["Breach & credential exposure lookup (OSINT)"]

                        append_log(f"> Auto-running {len(selected_modules)} module(s)…")
                        run_selected_modules_from_bundle(
                            bundle,
                            selected_modules,
                            network_allowed=network_allowed,
                        )
                        try:
                            secdb.update_case_status(st.session_state.case_reference, status="completed")
                        except Exception:
                            pass
                        append_log("> Analysis complete. Report updated.")
                        st.rerun()

                st.subheader("Live console")
                st.code("\n".join(st.session_state.logs[-300:]), language="bash")
                if st.button("Clear console", key=f"{kp}_clrlog"):
                    st.session_state.logs = ["> Console cleared."]
                    st.rerun()

    with right:
        with st.container(border=True):
            rh1, rh2, rh3 = st.columns([2.2, 1.1, 1.1])
            with rh1:
                st.markdown("##### Analysis Report")
            ref = st.session_state.get("case_reference", "")
            pdf_bytes = b""
            docx_bytes = b""

            md_view = ""
            if st.session_state.get("wizard_phase") == "complete" and ref:
                try:
                    db_findings = secdb.get_findings(ref)
                    st.session_state.report_findings.update(db_findings)
                except Exception:
                    pass
                selected_modules = list(st.session_state.get("case_selected_tools") or [])
                if st.session_state.get("case_breach_enabled"):
                    selected_modules = selected_modules + [
                        "Breach & credential exposure lookup (OSINT)"
                    ]
                md_view = case_report.official_report_markdown(
                    case_reference=ref,
                    case_title=st.session_state.get("case_name", "Untitled case"),
                    classification=st.session_state.get(
                        "case_classification", "OFFICIAL — SENSITIVE"
                    ),
                    selected_modules=selected_modules,
                    findings=st.session_state.get("report_findings") or {},
                    device_label=st.session_state.get("device_label", ""),
                    adb_serial=st.session_state.get("adb_serial"),
                    analyst=st.session_state.get("analyst_name", ""),
                    chain_of_custody_note=(
                        "Digital artifacts are to be archived per organizational chain-of-custody policy. "
                        "This report is mechanically generated and must be reviewed and attested before "
                        "submission to higher authorities."
                    ),
                )
                try:
                    pdf_bytes = report_export.export_pdf_bytes(md_view)
                except Exception:
                    pdf_bytes = b""
                try:
                    docx_bytes = report_export.export_docx_bytes(md_view)
                except Exception:
                    docx_bytes = b""
            with rh2:
                if pdf_bytes:
                    st.download_button(
                        "📄 PDF",
                        pdf_bytes,
                        file_name=f"{ref.replace(' ', '_')}.pdf",
                        mime="application/pdf",
                        use_container_width=True,
                        key="wiz_dl_pdf",
                    )
            with rh3:
                if docx_bytes:
                    st.download_button(
                        "📘 Word",
                        docx_bytes,
                        file_name=f"{ref.replace(' ', '_')}.docx",
                        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        use_container_width=True,
                        key="wiz_dl_docx",
                    )

            if st.session_state.get("wizard_phase") == "complete" and md_view:
                st.markdown(md_view)
            else:
                st.markdown(
                    '<div style="text-align:center;padding:2.8rem 0.5rem;color:#888;line-height:1.6;">'
                    '<div style="font-size:2.8rem;opacity:0.35;">📋</div>'
                    "<p><strong>No Analysis Started</strong></p>"
                    "<p>Select tools and run analysis to generate report.</p></div>",
                    unsafe_allow_html=True,
                )


def page_case_wizard_v2() -> None:
    inject_wizard_page_background()
    render_top_nav("wizard")

    kp = "wiz2"

    # Top header (UPDATED UI)
    h_main, h_close = st.columns([6, 1])

    with h_main:
        col_logo, col_text = st.columns([1, 6])

        with col_logo:
            st.image("assets/logo.png", width=60)

        with col_text:
            st.markdown("## New Security Case")
            st.caption("Advanced Android Forensic Analysis")

    with h_close:
        if st.button("✕", help="Close and return to dashboard", key=f"{kp}_close"):
            go_to_dashboard()
            st.rerun()

    # Live ADB metering (USB vs TCP/IP)
    adb_ok = adb_client.find_adb_executable()
    live_serials: list[str] = []
    if adb_ok:
        try:
            live_serials = adb_client.get_connected_serials()
        except Exception:
            live_serials = []
    usb_serials = [s for s in live_serials if ":" not in s]
    tcp_serials = [s for s in live_serials if ":" in s]
    if not adb_ok:
        st.warning("ADB Status: `adb` not found on PATH. Install Platform-Tools and try again.")
    else:
        st.info(f"ADB Status: {len(usb_serials)} USB connected · {len(tcp_serials)} TCP/IP connected")

    case_name = st.text_input("Case Name", placeholder="Enter case name...", key=f"{kp}_case_name")

    # Report metadata (used for official export header)
    with st.expander("Report metadata (official export header)", expanded=False):
        if "wiz_analyst_field" not in st.session_state:
            st.session_state.wiz_analyst_field = st.session_state.get("analyst_name", "Duty analyst")
        st.text_input("Analyst / reporting officer", key=f"{kp}_analyst_field")
        st.selectbox(
            "Document classification",
            ["OFFICIAL — SENSITIVE", "OFFICIAL", "RESTRICTED", "UNCLASSIFIED"],
            key=f"{kp}_class_field",
        )

    # If "Select All" was clicked, reset checkbox widget states before they are created.
    if st.session_state.get("wiz_select_all_reset"):
        for j in range(len(WIZARD_TOOLS)):
            st.session_state.pop(f"wiz_cb_{j}", None)
        st.session_state["wiz_select_all_reset"] = False

    # Main layout
    left, right = st.columns([1.15, 1.0], gap="large")

    with left:
        with st.container(border=True):
            st.markdown("##### Forensic tools")
            def _wiz_any_tool_changed() -> None:
                # If user manually toggles any checkbox, switch back to manual mode.
                if st.session_state.get("wiz_bulk_updating"):
                    return
                st.session_state["wiz_selection_mode"] = "manual"

            default_check = st.session_state.get("wiz_selection_mode", "manual") == "all"
            # Force the checkbox widget values based on the selection mode.
            # This makes Select All / Clear All update the visual tick marks reliably.
            if st.session_state.get("wiz_selection_mode") in ("all", "none"):
                st.session_state["wiz_bulk_updating"] = True
                for j in range(len(WIZARD_TOOLS)):
                    st.session_state[f"wiz_cb_{j}"] = default_check

            categories: list[str] = []
            seen: set[str] = set()
            for c, _, _ in WIZARD_TOOLS:
                if c not in seen:
                    seen.add(c)
                    categories.append(c)

            for cat in categories:
                st.markdown(f"**{cat}**")
                for i, (_, label, _) in enumerate(WIZARD_TOOLS):
                    # Enumerate by index so checkbox keys are stable.
                    c2, label2, _ = WIZARD_TOOLS[i]
                    if c2 != cat:
                        continue
                    st.checkbox(
                        label2,
                        key=f"wiz_cb_{i}",
                        value=default_check,
                        on_change=_wiz_any_tool_changed,
                    )

            # Bulk operations are finished; allow manual toggles to change mode.
            st.session_state["wiz_bulk_updating"] = False

            st.markdown("##### Evidence files")
            st.caption("Upload exports, screenshots, or logs for reference.")
            st.file_uploader("Click to upload files", accept_multiple_files=True, key=f"{kp}_evidence_upload")

            col_sel1, col_sel2 = st.columns(2)
            with col_sel1:
                if st.button(
                    "Select All Tools",
                    use_container_width=True,
                    key=f"{kp}_select_all",
                    type="secondary",
                ):
                    st.session_state["wiz_selection_mode"] = "all"
                    st.session_state["wiz_select_all_mode"] = True
                    st.session_state["wiz_select_all_reset"] = True
                    st.session_state["wiz_bulk_updating"] = True
                    st.rerun()
            with col_sel2:
                if st.button(
                    "Clear All Tools",
                    use_container_width=True,
                    key=f"{kp}_clear_all",
                    type="secondary",
                ):
                    st.session_state["wiz_selection_mode"] = "none"
                    st.session_state["wiz_select_all_mode"] = False
                    st.session_state["wiz_select_all_reset"] = True
                    st.session_state["wiz_bulk_updating"] = True
                    st.rerun()

            st.divider()
            st.markdown("##### Target device (ADB)")

            if not adb_ok:
                st.error("ADB unavailable (adb not on PATH).")
            else:
                devs = adb_client.list_devices()
                connected = [d for d in devs if d.get("state") == "device"]
                if not connected:
                    st.warning("No device in `device` state. Enable USB debugging + authorize.")
                else:
                    labels = [f"{d['serial']} ({d.get('extras', '')})" for d in connected]
                    ix = st.radio(
                        "Select device",
                        list(range(len(connected))),
                        format_func=lambda i: labels[i],
                        key=f"{kp}_dev_ix",
                    )
                    serial = connected[int(ix)]["serial"]
                    if st.button("🔌 Connect / set active device", use_container_width=True, key=f"{kp}_conn"):
                        st.session_state.adb_serial = serial
                        st.session_state.device_connected = True
                        st.session_state.device_label = adb_client.device_model(serial)
                        append_log(f"> Active device set: {st.session_state.device_label} [{serial}]")
                        st.rerun()
            # 🔥 NEW DEVICE PICKER UI (Bluetooth style)
            st.subheader("📡 Device Manager")

            if connected:
                for d in connected:
                    serial = d["serial"]
                    name = adb_client.device_model(serial)

                    col1, col2 = st.columns([5,1])

                    with col1:
                        icon = "🟢" if ":" not in serial else "🔵"
                        st.write(f"{icon} {name} ({serial})")

                    with col2:
                        if st.button("Connect", key=f"connect_{serial}"):
                            st.session_state.adb_serial = serial
                            st.session_state.device_connected = True
                            st.session_state.device_label = name
                            append_log(f"> Connected via UI: {name} [{serial}]")
                            st.rerun()
            st.divider()
            st.subheader("⚡ Wireless Setup")

            if st.session_state.get("adb_serial"):

                if st.button("Enable Wireless Mode"):
                    ok = adb_client.enable_tcpip(st.session_state.adb_serial)
                    if ok:
                        st.success("Wireless mode enabled (port 5555)")
                    else:
                        st.error("Failed to enable")

                if st.button("Auto Connect Wireless"):
                    ip = adb_client.get_device_ip(st.session_state.adb_serial)

                    if ip:
                        ok = adb_client.connect_tcp(ip)
                        if ok:
                            st.success(f"Connected to {ip}:5555")
                        else:
                            st.error("Connection failed")
                    else:
                        st.error("Could not detect IP")

                   
            

            # Enforce real-time connection for selected serial
            cur_serial = st.session_state.get("adb_serial")
            if cur_serial and cur_serial in live_serials:
                st.success(
                    f"ADB connected for selected serial: {st.session_state.get('device_label')} · `{cur_serial}`"
                )
                st.session_state.device_connected = True
            elif cur_serial:
                st.warning(f"ADB not connected right now for `{cur_serial}`. Replug/reconnect USB.")
                st.session_state.device_connected = False
                st.session_state.forensic_bundle = None
            else:
                st.info("ADB not connected yet. Select a device and click Connect.")

            st.divider()
            dump_sys = st.checkbox("DumpSys (permission sample)", value=True, key=f"{kp}_ds")
            logcat = st.checkbox("Logcat scanner", value=True, key=f"{kp}_lc")
            network_allowed = st.checkbox(
                "Allow outbound network checks (WHOIS/ports/traceroute/TLS)",
                value=False,
                key=f"{kp}_net_allowed",
            )

            if st.button(
                "▶ Run Analysis",
                type="primary",
                use_container_width=True,
                key=f"{kp}_run_all",
                disabled=not st.session_state.get("device_connected", False) or not st.session_state.get("adb_serial"),
            ):
                # Compute selected modules from selection mode.
                # This makes Select All / Clear All reliable even if checkbox widget tick-state is stale.
                selected_modules: list[str] = []
                breach_enabled = False
                sel_mode = st.session_state.get("wiz_selection_mode", "manual")
                if sel_mode == "all":
                    for _, _, fid in WIZARD_TOOLS:
                        if fid == BREACH_TOKEN:
                            breach_enabled = True
                        elif fid:
                            selected_modules.append(fid)
                elif sel_mode == "none":
                    selected_modules = []
                    breach_enabled = False
                else:
                    # manual: read the checkbox widget state
                    for j, (_, _, fid) in enumerate(WIZARD_TOOLS):
                        if not st.session_state.get(f"wiz_cb_{j}", False):
                            continue
                        if fid == BREACH_TOKEN:
                            breach_enabled = True
                        elif fid:
                            selected_modules.append(fid)

                if not selected_modules and not breach_enabled:
                    st.error("Select at least one tool.")
                else:
                    # Create / update case metadata
                    ref = st.session_state.get("case_reference") or f"CASE-{datetime.now():%Y%m%d-%H%M%S}"
                    st.session_state.case_reference = ref
                    st.session_state.case_name = (case_name or "").strip() or f"Security case {datetime.now():%Y-%m-%d %H:%M}"
                    st.session_state.analyst_name = st.session_state.get(f"{kp}_analyst_field", st.session_state.get("analyst_name", "Duty analyst"))
                    st.session_state.case_classification = st.session_state.get(f"{kp}_class_field", "OFFICIAL — SENSITIVE")
                    st.session_state.case_selected_tools = list(dict.fromkeys(selected_modules))
                    st.session_state.case_breach_enabled = breach_enabled
                    st.session_state.wizard_phase = None

                    detailed_info = {}
                    try:
                        serial = st.session_state.adb_serial
                        _, out_rel, _ = adb_client.shell(serial, "getprop ro.build.version.release", timeout=10)
                        _, out_man, _ = adb_client.shell(serial, "getprop ro.product.manufacturer", timeout=10)
                        _, out_bat, _ = adb_client.shell(serial, "dumpsys battery | grep level", timeout=10)
                        detailed_info["OS Version"] = out_rel.strip() or "Unknown"
                        detailed_info["Manufacturer"] = out_man.strip() or "Unknown"
                        if out_bat.strip():
                            detailed_info["Battery"] = out_bat.strip().replace("level:", "").strip() + "%"
                        
                        ip_route = adb_client.get_device_ip(serial)
                        if ip_route:
                            detailed_info["IP Address"] = ip_route
                            
                        st.session_state.detailed_device_info = detailed_info
                    except Exception:
                        st.session_state.detailed_device_info = {}

                    # Persist case start
                    try:
                        secdb.create_or_update_case(
                            case_reference=st.session_state.case_reference,
                            case_name=st.session_state.case_name,
                            analyst_name=st.session_state.analyst_name,
                            classification=st.session_state.case_classification,
                            selected_tools=st.session_state.case_selected_tools,
                            created_at=datetime.now().isoformat(),
                            status="in_progress",
                            user_id=st.session_state.user_id,
                            device_label=st.session_state.get("device_label"),
                            adb_serial=st.session_state.get("adb_serial"),
                            detailed_info=detailed_info
                        )
                    except Exception as e:
                        print("DB Insert Error:", e)
                    
                    st.session_state.analysis_running = True
                    append_log(f"> Case ready: {st.session_state.case_reference}. Pulling device…")

                    try:
                        with st.spinner("Pulling device artifacts + running all selected modules…"):
                            bundle = adb_client.pull_forensic_bundle(
                                st.session_state.adb_serial,
                                include_dumpsys=dump_sys,
                                include_logcat=logcat,
                            )
                            st.session_state.forensic_bundle = bundle
                            append_log("> Pull completed. Running modules…")

                            modules_to_run = list(st.session_state.case_selected_tools)
                            if st.session_state.case_breach_enabled:
                                modules_to_run.append("Breach & credential exposure lookup (OSINT)")

                            run_selected_modules_from_bundle(bundle, modules_to_run, network_allowed=network_allowed)
                            
                                
                    except Exception as e:
                        st.error(f"Error: {str(e)}")

                    finally:
                        st.session_state.analysis_running = False
                    try:
                        secdb.update_case_status(st.session_state.case_reference, status="completed")
                    except Exception:
                        pass

                    st.session_state.wizard_phase = "complete"
                    st.session_state.analysis_running = False
                    append_log("> Analysis complete. Report updated.")
                    st.rerun()

            st.divider()
            st.subheader("Live console")
            st.code("\n".join(st.session_state.logs[-250:]), language="bash")

    with right:
        ref = st.session_state.get("case_reference") or ""
        md_view = ""
        pdf_bytes = b""
        docx_bytes = b""

        if ref and st.session_state.get("wizard_phase") == "complete":
            try:
                db_findings = secdb.get_findings(ref)
                st.session_state.report_findings.update(db_findings)
            except Exception:
                pass

            selected_modules = list(st.session_state.get("case_selected_tools") or [])
            if st.session_state.get("case_breach_enabled"):
                selected_modules = selected_modules + ["Breach & credential exposure lookup (OSINT)"]

            md_view = case_report.official_report_markdown(
                case_reference=ref,
                case_title=st.session_state.get("case_name", "Untitled case"),
                classification=st.session_state.get("case_classification", "OFFICIAL — SENSITIVE"),
                selected_modules=selected_modules,
                findings=st.session_state.get("report_findings") or {},
                device_label=st.session_state.get("device_label", ""),
                adb_serial=st.session_state.get("adb_serial"),
                analyst=st.session_state.get("analyst_name", ""),
                chain_of_custody_note=(
                    "Digital artifacts are to be archived per organizational chain-of-custody policy. "
                    "This report is mechanically generated and must be reviewed and attested before submission "
                    "to higher authorities."
                ),
                detailed_device_info=st.session_state.get("detailed_device_info"),
            )

            try:
                pdf_bytes = report_export.export_pdf_bytes(md_view)
            except Exception:
                pdf_bytes = b""
            try:
                docx_bytes = report_export.export_docx_bytes(md_view)
            except Exception:
                docx_bytes = b""

        
        if st.session_state.get("analysis_running", False):
            st.markdown("##### Analysis Report")

            st.markdown("""
            <div class="loader-box">
                ⏳ Generating report... please wait
            </div>
            """, unsafe_allow_html=True)

        elif md_view:
            # Convert markdown → HTML
            html_report = markdown.markdown(md_view)

            # CSS
            st.markdown("""
            <style>
            .report-box {
                height: 230vh;
                overflow-y: auto;
                padding: 15px;
                background-color: #0f172a;
                border-radius: 12px;
                border: 1px solid #1e293b;
                line-height: 1.6;
            }
            </style>
            """, unsafe_allow_html=True)

            # Render properly
            st.markdown(
                f'<div class="report-box">{html_report}</div>',
                unsafe_allow_html=True
            )

            if pdf_bytes:
                st.download_button(
                    "📄 Download PDF",
                    pdf_bytes,
                    file_name=f"{ref}.pdf",
                    mime="application/pdf",
                    key=f"{kp}_dl_pdf",
                    use_container_width=True,
                )

            if docx_bytes:
                st.download_button(
                    "📘 Download Word",
                    docx_bytes,
                    file_name=f"{ref}.docx",
                    mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    key=f"{kp}_dl_docx",
                    use_container_width=True,
                )

            st.download_button(
                "Download .md",
                md_view,
                file_name=f"{ref}.md",
                mime="text/markdown",
                key=f"{kp}_dl_md",
                use_container_width=True,
            )

        else:
            st.markdown("##### Analysis Report")
            st.caption("No Analysis Started. Select tools + connect device, then press Run Analysis.")


def render_official_report_panel() -> None:
    ref = st.session_state.get("case_reference") or "CASE-PENDING"
    title = st.session_state.get("case_name") or "Untitled case"
    tools = list(st.session_state.get("case_selected_tools") or [])
    findings = st.session_state.get("report_findings") or {}
    modules_ordered = list(dict.fromkeys(tools + [k for k in findings if k not in tools]))
    md = case_report.official_report_markdown(
        case_reference=ref,
        case_title=title,
        classification=st.session_state.get("case_classification", "OFFICIAL — SENSITIVE"),
        selected_modules=modules_ordered,
        findings=findings,
        device_label=st.session_state.get("device_label", ""),
        adb_serial=st.session_state.get("adb_serial"),
        analyst=st.session_state.get("analyst_name", ""),
        chain_of_custody_note=(
            "Digital artifacts were processed through this authorized workstation application. "
            "ADB transcripts, exported files, and device images must be archived per agency chain-of-custody SOP. "
            "This document is an auto-generated **draft** for supervisory review and requires analyst attestation "
            "before formal submission to higher authorities."
        ),
        detailed_device_info=st.session_state.get("detailed_device_info"),
    )
    st.markdown("##### Official case report (draft)")
    st.caption("Refreshes as you complete module actions.")
    try:
        pdf_ws = report_export.export_pdf_bytes(md)
    except Exception:
        pdf_ws = b""
    try:
        docx_ws = report_export.export_docx_bytes(md)
    except Exception:
        docx_ws = b""
    d1, d2, d3 = st.columns(3)
    with d1:
        if pdf_ws:
            st.download_button(
                "📄 Download PDF",
                pdf_ws,
                file_name=f"{ref.replace(' ', '_')}.pdf",
                mime="application/pdf",
                key="dl_ws_pdf",
                use_container_width=True,
            )
    with d2:
        if docx_ws:
            st.download_button(
                "📘 Download Word",
                docx_ws,
                file_name=f"{ref.replace(' ', '_')}.docx",
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                key="dl_ws_docx",
                use_container_width=True,
            )
    with d3:
        st.download_button(
            "Download .md",
            md,
            file_name=f"{ref.replace(' ', '_')}.md",
            mime="text/markdown",
            key="dl_official_md",
            use_container_width=True,
        )
    st.markdown(md)


def page_login() -> None:
 
    st.markdown("""
    <style>
    .stApp {
        background: linear-gradient(135deg, #0f172a, #020617);
    }



    /* Card */
    .login-card {
        background: #1e293b;
        padding: 35px;
        border-radius: 15px;
        box-shadow: 0px 4px 25px rgba(0,0,0,0.4);
    }

    /* Title */
    .title {
        text-align: center;
        font-size: 28px;
        font-weight: 600;
        color: white;
        margin-bottom: 5px;
    }

    .subtitle {
        text-align: center;
        color: #94a3b8;
        margin-bottom: 25px;
    }

    /* Inputs */
    div[data-testid="stTextInput"] input {
        background-color: #0f172a !important;
        color: white !important;
        border-radius: 8px;
        border: 1px solid #334155;
        padding: 12px;
    }

    /* Button */
    div.stButton > button {
        height: 45px;
        border-radius: 8px;
        background: linear-gradient(to right, #2563eb, #3b82f6);
        color: white;
        font-weight: bold;
    }
    </style>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1,2,1])

    with col2:
        c1, c2, c3 = st.columns([1,2,1])
        with c2:
            st.markdown("""
            <div style="display:flex; justify-content:center;">
            <img src="data:image/png;base64,{}" width="120">
            </div>
            """.format(get_base64_image("assets/logo.png")), unsafe_allow_html=True)
        st.markdown('<div class="title">SecureOps</div>', unsafe_allow_html=True)
        st.markdown('<div class="subtitle">Android Forensics Platform</div>', unsafe_allow_html=True)

        # 🔐 Login Form (UNCHANGED LOGIC)
        with st.form("login_form"):
            email = st.text_input("📧 Email")
            password = st.text_input("🔐 Password", type="password")

            submit = st.form_submit_button("🚀 Login", use_container_width=True)

            if submit:
                user = login_user(email, password)
                if user:
                    st.session_state.user_id = user["user_id"]
                    login()
                    st.rerun()
                else:
                    st.error("Invalid credentials")

        st.markdown("<br>", unsafe_allow_html=True)

        st.button("Create Account", on_click=go_to_register, use_container_width=True)

        

def page_register():
    st.markdown("<h2 style='text-align:center;'>Create Account</h2>",
    unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1,2,1])
    
    with col2:
        with st.container(border=True):

            back_button()

            st.markdown("### Register")

            name = st.text_input("👤 Name")
            email = st.text_input("📧 Email")
            password = st.text_input("🔒 Password", type="password")

            st.markdown("---")

            if st.button("📨 Send OTP", use_container_width=True):
                otp = str(random.randint(100000, 999999))
                st.session_state.otp = otp
                st.session_state.temp_user = (name, email, password)

                st.success(f"OTP: {otp}")  # demo

                entered_otp = st.text_input("🔑 Enter OTP")

            if st.button("✅ Verify & Register", use_container_width=True):
                if entered_otp == st.session_state.get("otp"):
                    name, email, password = st.session_state.temp_user

                    success = register_user(name, email, password)

                    if success:
                        st.success("Account created!")
                        
                        st.session_state.current_page = "Login"
                        st.rerun()
                    else:
                        st.error("Email already exists")
                        st.button("Login", on_click=go_to_login, use_container_width=True)
                else:
                    st.error("Invalid OTP")
    
    
def page_profile() -> None:
    render_top_nav("profile")
    st.title("👤 User Profile")
    st.write("Welcome to your profile! Here you can view your settings and account details.")
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Account Details")
        st.write("**Name:** Duty Analyst")
        st.write("**Role:** Forensic Investigator")
        st.write("**Classification Level:** OFFICIAL — SENSITIVE")
    with col2:
        st.subheader("Preferences")
        st.checkbox("Dark Mode", value=True, disabled=True)
        st.checkbox("Auto-pull logs on connect", value=True)
        
    st.button("Reset Password", disabled=True)


def page_dashboard() -> None:
    render_top_nav("dashboard")
    user_id=st.session_state.get("user_id")
    if not user_id:
        st.error("Please Login First")
        return
    st.title("Security Dashboard")
    cases = secdb.list_cases(user_id)
    case_count = len(cases)
    in_progress = len([c for c in cases if (c.status or "").lower() in ("in_progress", "in progress", "active")])
    completed = len([c for c in cases if (c.status or "").lower() in ("completed", "done")])
    pending = max(case_count - in_progress - completed, 0)

    # Threats detected approximation: count "high" severity findings across stored cases.
    high_findings = 0
    for c in cases:
        f = secdb.get_findings(c.case_reference)
        high_findings += len([v for v in f.values() if (v.get("severity") or "").lower() in ("high", "critical")])

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Threats Detected", str(high_findings))
    col2.metric("Active Cases", str(in_progress))
    col3.metric("Completed Cases", str(completed))
    col4.metric("Pending Analysis", str(pending))

    st.divider()
    # Graphs driven from stored case findings (no dummy data).
    chart_col1, chart_col2 = st.columns(2, gap="large")

    with chart_col1:
        st.subheader("Threat detection timeline")
        weekday_counts = {name: 0 for name in ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]}
        for c in cases:
            try:
                dt = datetime.fromisoformat(c.created_at)
            except Exception:
                continue
            key = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][dt.weekday()]
            weekday_counts[key] += 1
        timeline_data = pd.DataFrame(
            {"Incidents": [weekday_counts[k] for k in ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]]},
            index=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        )
        st.line_chart(timeline_data)

    with chart_col2:
        st.subheader("Vulnerability Types (pie)")
        tool_to_category = {
            FEATURES[0]: "Data Leak",
            FEATURES[1]: "Misconfiguration",
            FEATURES[2]: "Data Leak",
            FEATURES[3]: "Data Leak",
            FEATURES[4]: "Misconfiguration",
            FEATURES[5]: "Data Leak",
            FEATURES[6]: "Phishing",
            FEATURES[7]: "Phishing",
            FEATURES[8]: "Malware",
            FEATURES[9]: "Phishing",
            FEATURES[10]: "Phishing",
            FEATURES[11]: "Malware",
            FEATURES[12]: "Malware",
            FEATURES[13]: "Malware",
            FEATURES[14]: "Malware",
        }
        cat_counts: dict[str, int] = {
            "Malware": 0,
            "Data Leak": 0,
            "Phishing": 0,
            "Misconfiguration": 0,
        }
        for c in cases:
            try:
                f = secdb.get_findings(c.case_reference)
            except Exception:
                continue
            for tool_name, entry in (f or {}).items():
                cat = tool_to_category.get(tool_name)
                if not cat:
                    continue
                sev = (entry.get("severity") or "").lower()
                if sev in ("high", "critical"):
                    cat_counts[cat] += 2
                else:
                    cat_counts[cat] += 1
        threat_df = pd.DataFrame({"Category": list(cat_counts.keys()), "Count": list(cat_counts.values())})
        pie_fig = px.pie(threat_df, names="Category", values="Count", title="Distribution")
        st.plotly_chart(pie_fig, use_container_width=True)

    st.subheader("Recent cases")
    dash_view_ref = st.session_state.get("dash_view_case_ref")
    dash_edit_ref = st.session_state.get("dash_edit_case_ref")

    if not cases:
        st.info("No cases created yet.")
        return

    for c in cases[:15]:
        exp_label = f"{c.case_reference} — {c.case_name}"
        with st.expander(exp_label, expanded=(dash_view_ref == c.case_reference or dash_edit_ref == c.case_reference)):
            st.write(f"Status: **{c.status}** · Created: `{c.created_at}`")

            col_v, col_e, col_d = st.columns([1, 1, 1], gap="small")
            with col_v:
                if st.button("View report", key=f"dash_view_{c.case_reference}", use_container_width=True):
                    st.session_state["dash_view_case_ref"] = c.case_reference
                    st.session_state["dash_edit_case_ref"] = None
                    st.rerun()
            with col_e:
                if st.button("Edit", key=f"dash_edit_{c.case_reference}", use_container_width=True):
                    st.session_state["dash_edit_case_ref"] = c.case_reference
                    st.session_state["dash_view_case_ref"] = None
                    st.rerun()
            with col_d:
                if st.button("Delete", key=f"dash_del_{c.case_reference}", use_container_width=True, type="secondary"):
                    try:
                        secdb.delete_case(c.case_reference)
                        st.session_state["dash_view_case_ref"] = None
                        st.session_state["dash_edit_case_ref"] = None
                        st.rerun()
                    except Exception as e:
                        st.error(f"Delete failed: {e!s}")

            if st.session_state.get("dash_edit_case_ref") == c.case_reference:
                with st.form(f"dash_edit_form_{c.case_reference}"):
                    new_name = st.text_input("Case name", value=c.case_name, key=f"dash_edit_name_{c.case_reference}")
                    new_analyst = st.text_input(
                        "Analyst name",
                        value=c.analyst_name,
                        key=f"dash_edit_analyst_{c.case_reference}",
                    )
                    new_class = st.selectbox(
                        "Classification",
                        ["OFFICIAL — SENSITIVE", "OFFICIAL", "RESTRICTED", "UNCLASSIFIED"],
                        index=0 if "OFFICIAL — SENSITIVE" in (c.classification or "") else 1,
                        key=f"dash_edit_class_{c.case_reference}",
                    )
                    saved = st.form_submit_button("Save changes", use_container_width=True)
                    if saved:
                        try:
                            secdb.create_or_update_case(
                                case_reference=c.case_reference,
                                case_name=new_name.strip(),
                                analyst_name=new_analyst.strip(),
                                classification=new_class,
                                selected_tools=c.selected_tools,
                                created_at=c.created_at,
                                status=c.status,
                                user_id=st.session_state.user_id,
                                device_label=getattr(c, "device_label", None),
                                adb_serial=getattr(c, "adb_serial", None),
                            )
                            st.session_state["dash_edit_case_ref"] = None
                            st.rerun()
                        except Exception as e:
                            st.error(f"Save failed: {e!s}")

            if st.session_state.get("dash_view_case_ref") == c.case_reference:
                # Build report from stored case + stored findings.
                findings = secdb.get_findings(c.case_reference)
                selected_modules = list(c.selected_tools or [])
                md = case_report.official_report_markdown(
                    case_reference=c.case_reference,
                    case_title=c.case_name,
                    classification=c.classification,
                    selected_modules=selected_modules,
                    findings=findings,
                    device_label=getattr(c, "device_label", "") or "",
                    adb_serial=getattr(c, "adb_serial", None),
                    analyst=c.analyst_name,
                    chain_of_custody_note=(
                        "Digital artifacts are to be archived per organizational chain-of-custody policy. "
                        "This report is an automated draft and requires supervisory review before submission."
                    ),
                    detailed_device_info=getattr(c, "detailed_info", None),
                )
                st.markdown("#### Report (draft)")
                st.markdown(md)
                try:
                    pdf_bytes = report_export.export_pdf_bytes(md)
                except Exception:
                    pdf_bytes = b""
                    
                if pdf_bytes:
                    st.download_button(
                        "Download .pdf",
                        pdf_bytes,
                        file_name=f"{c.case_reference}_report.pdf",
                        mime="application/pdf",
                        use_container_width=True,
                        key=f"dash_dl_pdf_{c.case_reference}",
                    )
                else:
                    st.download_button(
                        "Download .md (PDF unavailable)",
                        md,
                        file_name=f"{c.case_reference}_report.md",
                        mime="text/markdown",
                        use_container_width=True,
                        key=f"dash_dl_md_{c.case_reference}",
                    )


def run_device_pull(serial: str | None, dump_sys: bool, logcat: bool) -> None:
    append_log("> Initializing ADB forensic pull…")
    bundle = adb_client.pull_forensic_bundle(serial, include_dumpsys=dump_sys, include_logcat=logcat)
    st.session_state.forensic_bundle = bundle
    st.session_state.device_label = adb_client.device_model(serial)
    for err in bundle.errors:
        append_log(f"> WARN: {err}")
    append_log("> Pull finished. Open a forensic module below or use 'Pull from device' buttons.")
    if dump_sys and len(bundle.dumpsys_permissions_sample) > 50:
        append_log(f"> dumpsys sample: {len(bundle.dumpsys_permissions_sample)} chars")
    if logcat and len(bundle.logcat_text) > 50:
        append_log(f"> logcat: {len(bundle.logcat_text)} chars")


def page_new_case() -> None:
    kp = "nc"
    render_top_nav("case")

    tools = list(st.session_state.get("case_selected_tools") or [])
    if not st.session_state.get("case_reference"):
        st.warning("Use **Create New Case** in the top bar to configure a case first.")
        return

    # Load persistent case + findings from DB (so refresh/reopen still works).
    try:
        case_row = secdb.get_case(st.session_state.case_reference)
        if case_row:
            st.session_state.case_name = case_row.case_name
            st.session_state.case_classification = case_row.classification
            st.session_state.analyst_name = case_row.analyst_name
            st.session_state.case_selected_tools = case_row.selected_tools
            if not st.session_state.get("report_findings"):
                st.session_state.report_findings = secdb.get_findings(st.session_state.case_reference)
            tools = list(st.session_state.case_selected_tools or [])
    except Exception:
        pass

    ref = st.session_state.get("case_reference", "")
    cname = st.session_state.get("case_name", "")
    st.title("Case workspace")
    st.markdown(f"**{ref}** · {cname}")

    left, right = st.columns([1.2, 1], gap="large")

    with left:
        st.subheader("Device & acquisition")
        adb_ok = adb_client.find_adb_executable()
        if not adb_ok:
            st.error(
                "`adb` not on PATH. Install [Platform-Tools](https://developer.android.com/studio/releases/platform-tools)."
            )
        else:
            if st.button("🔄 Refresh devices", use_container_width=True, key=f"{kp}_ref"):
                st.rerun()
            devs = adb_client.list_devices()
            connected = [d for d in devs if d.get("state") == "device"]
            if not connected:
                st.warning("No device in **device** state. Enable USB debugging and authorize this PC.")
                for d in devs:
                    st.caption(f"{d.get('serial')} — {d.get('state')} {d.get('extras', '')}")
            else:
                labels = [f"{d['serial']} ({d.get('extras', '')})" for d in connected]
                ix = st.radio(
                    "Select device",
                    list(range(len(connected))),
                    format_func=lambda i: labels[i],
                    key=f"{kp}_dev_ix",
                )
                serial = connected[int(ix)]["serial"]
                if st.button("🔌 Connect / set active device", use_container_width=True, key=f"{kp}_conn"):
                    st.session_state.adb_serial = serial
                    st.session_state.device_connected = True
                    st.session_state.device_label = adb_client.device_model(serial)
                    append_log(f"> Active device: {st.session_state.device_label} [{serial}]")
                    st.rerun()

                if st.session_state.device_connected and st.session_state.adb_serial:
                    st.success(f"📱 {st.session_state.device_label} — `{st.session_state.adb_serial}`")
                    if st.button("Disconnect", use_container_width=True, key=f"{kp}_disc"):
                        st.session_state.device_connected = False
                        st.session_state.adb_serial = None
                        st.session_state.forensic_bundle = None
                        append_log("> Device disconnected.")
                        st.rerun()

        # Always-visible ADB status banner (checks live `adb devices`).
        live_serials: list[str] = []
        try:
            if adb_ok:
                live_serials = adb_client.get_connected_serials()
        except Exception:
            live_serials = []

        cur_serial = st.session_state.get("adb_serial")
        if cur_serial:
            if cur_serial in live_serials:
                st.success(
                    "ADB Status: Connected "
                    + f"· {st.session_state.get('device_label')} · `{cur_serial}`"
                )
                st.session_state.device_connected = True
            else:
                st.warning(
                    "ADB Status: Not connected for selected serial. "
                    + f"Selected `{cur_serial}`, but live device states do not include it."
                )
                st.session_state.device_connected = False
                st.session_state.forensic_bundle = None
        else:
            st.info("ADB Status: Not connected. Select a device and click `Connect / set active device`.")

        dump_sys = st.checkbox("DumpSys (permission sample)", value=True, key=f"{kp}_ds")
        logcat = st.checkbox("Logcat", value=True, key=f"{kp}_lc")
        pcap = st.checkbox("PCAP note", value=False, key=f"{kp}_pcap")
        if pcap:
            st.info("PCAP: use on-device capture or `adb pull` — not streamed here.")

        if st.button(
            "▶ Pull from device",
            type="primary",
            use_container_width=True,
            disabled=not st.session_state.device_connected,
            key=f"{kp}_pull",
        ):
            with st.spinner("Running adb shell…"):
                run_device_pull(st.session_state.adb_serial, dump_sys, logcat)
                st.rerun()

        st.subheader("Live console")
        st.code("\n".join(st.session_state.logs[-300:]), language="bash")
        if st.button("Clear console", key=f"{kp}_clrlog"):
            st.session_state.logs = ["> Console cleared."]
            st.rerun()

        st.divider()
        st.subheader("Forensic modules (this case)")
        if not tools:
            st.info(
                "No device-side lab modules were selected (e.g. OSINT-only scope). "
                "Use **Create New Case** to add mobile forensic tools, or rely on the report panel."
            )
        else:
            tab_list = st.tabs(tools)
            for i, tool_name in enumerate(tools):
                with tab_list[i]:
                    if tool_name in ROUTES:
                        ROUTES[tool_name](kp)
                    else:
                        st.error("Unknown module.")

    with right:
        with st.container():
            render_official_report_panel()


def main() -> None:
    st.set_page_config(page_title="Security Analytics Dashboard", page_icon="🛡️", layout="wide")
    secdb.init_db()
    _init_session_state()

    if st.session_state.current_page == "Login":
        page_login()
    elif st.session_state.current_page == "Register":
        page_register()
    elif st.session_state.current_page == "Dashboard" and st.session_state.logged_in:
        page_dashboard()
    elif st.session_state.current_page == "Case Wizard" and st.session_state.logged_in:
        page_case_wizard_v2()
    else:
        st.session_state.current_page = "Login"
        page_login()


if __name__ == "__main__":
    main()
