"""Official-style case report text (markdown) for supervisory review."""

from __future__ import annotations

from datetime import datetime
from typing import Any


def official_report_markdown(
    *,
    case_reference: str,
    case_title: str,
    classification: str,
    selected_modules: list[str],
    findings: dict[str, dict[str, Any]],
    device_label: str,
    adb_serial: str | None,
    analyst: str,
    chain_of_custody_note: str,
    detailed_device_info: dict[str, str] = None,
) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "---",
        f"**DOCUMENT CLASSIFICATION:** {classification}",
        f"**REFERENCE:** {case_reference}",
        f"**TITLE:** {case_title}",
        f"**GENERATED:** {now}",
        "---",
        "",
        "### 1. Distribution & handling",
        "This report is prepared for supervisory and authorized investigative review only. "
        "Handle per organizational policy for sensitive digital evidence.",
        "",
        "### 2. Executive summary",
        _exec_summary(selected_modules, findings),
        "",
        "### 3. Scope of examination",
        f"- **Analyst / operator:** {analyst}",
        f"- **Target device (ADB):** {device_label or 'Not connected'}",
        f"- **ADB serial:** `{adb_serial or 'N/A'}`",
    ]
    if detailed_device_info:
        for k, v in detailed_device_info.items():
            lines.append(f"  - **{k}:** {v}")
    
    lines.extend([
        f"- **Modules invoked for this case:** {len(selected_modules)}",
        "",
        _modules_list(selected_modules),
        "",
        "### 4. Findings by module",
        _findings_body(findings, selected_modules),
        "",
        "### 5. Chain of custody & integrity",
        chain_of_custody_note,
        "",
        "### 6. Conclusion & recommendations",
        _conclusion(findings, selected_modules),
        "",
        "---",
        "*End of automated case report draft — review, sign, and file per SOP.*",
    ])
    return "\n".join(lines)


def _exec_summary(modules: list[str], findings: dict[str, dict[str, Any]]) -> str:
    if not modules:
        return "No examination modules were selected; no technical findings recorded."
    n_done = len([v for v in findings.values() if v.get("status") == "completed"])
    n_any = len(findings)
    if n_any == 0:
        return (
            f"Examination scope lists **{len(modules)}** module(s). "
            "No findings logged yet — run analyses in the workspace."
        )
    if n_done == 0:
        return (
            f"Examination scope lists **{len(modules)}** module(s). "
            f"**{n_any}** module section(s) are initialized (pending detailed technical results)."
        )
    return (
        f"Examination scope lists **{len(modules)}** module(s). "
        f"**{n_done}** section(s) contain completed analytical results for review."
    )


def _modules_list(modules: list[str]) -> str:
    if not modules:
        return "*No modules listed.*"
    return "<br>".join(f"{i+1}) {m}" for i, m in enumerate(list(modules)))


FRIENDLY_MAPPINGS = {
    " Hidden apps detection": (
        "We checked your device for applications that are installed but hidden from your home screen. Hidden apps are often used by spyware to operate unnoticed.",
        "If unfamiliar hidden apps were found, immediately uninstall them from your device settings (Settings -> Apps -> See all apps)."
    ),
    " Dangerous permissions audit": (
        "We reviewed applications that have requested high-risk permissions, such as access to your camera, microphone, or location.",
        "Review the listed apps. If an app you don't trust has access to your camera or microphone, revoke that permission immediately in your settings."
    ),
    " SMS & call log review": (
        "We scanned your text messages and call history for signs of phishing links, malicious commands, or unauthorized communication.",
        "Do not click on any suspicious links in your text messages. If suspicious messages were found, delete them and block the sender."
    ),
    " File system path audit": (
        "We checked your phone's internal storage for folders and files commonly created by malware or unauthorized tracking software.",
        "If malicious files are detected, a factory reset may be required to guarantee complete removal."
    ),
    " ADB usage indicators": (
        "We checked if your device has 'Developer Options' and 'USB Debugging' enabled. These settings allow computers to deeply interact with your phone.",
        "Unless you are actively using Developer Options, turn them off in your device settings to prevent unauthorized access if plugged into a compromised computer/charger."
    ),
    " Location timeline map": (
        "We extracted the last known location stored in your device's memory to see if any apps have been tracking your whereabouts.",
        "If location tracking is active when you didn't expect it, review which apps have the 'Location' permission and restrict them to 'Allow only while using the app'."
    ),
    " WHOIS lookup": (
        "We looked up the ownership records for suspicious websites that your phone tried to connect to.",
        "If your phone is communicating with known malicious domains, it may be infected. Consider installing a reputable mobile antivirus and reviewing recently installed apps."
    ),
    " DNS query correlation": (
        "We analyzed the web addresses your phone has been communicating with in the background to detect spyware 'command and control' servers.",
        "If malicious hosts are flagged, your device may be compromised. Disconnect from the internet and seek professional forensic assistance."
    ),
    " Port scan (22, 80, 8080)": (
        "We checked if any malicious servers your phone contacted are open for hacking or data exfiltration.",
        "No direct action required on the phone, but this confirms the severity of the suspicious servers your device contacted."
    ),
    " Social engineering / phishing heuristics": (
        "We analyzed text from logs to see if you have received messages using high-pressure tactics (like 'Urgent!' or 'Account Suspended') typical of scams.",
        "Never share your passwords, OTPs (One Time Passwords), or click links from urgent or threatening messages."
    ),
    " Email header & SPF/DKIM/DMARC": (
        "We checked the security signatures of emails to verify if they genuinely came from the claimed sender or if they were spoofed (faked).",
        "If an email fails these checks, it is likely a scam or phishing attempt. Do not reply or click any links within it."
    ),
    " Traceroute": (
        "We traced the network path your phone takes to reach suspicious servers to see where in the world your data might be going.",
        "This is informational for the investigator. If data is routing to unexpected countries, it strengthens the likelihood of a compromise."
    ),
    " Unusual protocol detection": (
        "We looked for apps communicating using non-standard or hidden network methods often used by sophisticated malware.",
        "If found, identify the app responsible for the unusual traffic and uninstall it immediately."
    ),
    " SSL certificate inspection": (
        "We verified if the encryption certificates for suspicious servers are valid or if they are self-signed (often used by hackers to hide their identity).",
        "If self-signed certificates are detected, it means the server is trying to hide its true identity. Do not trust any communication with it."
    ),
    " Bandwidth anomaly detection": (
        "We analyzed your internet usage over time to find sudden, unexplained spikes in data transfer, which could indicate a hidden app stealing your files or photos.",
        "Check your device's data usage settings to see which app consumed the most data during the spike, and uninstall it if it looks suspicious."
    ),
    " Live System Monitoring": (
        "We took a live snapshot of your phone's processor and memory usage to see if any hidden apps are secretly running in the background.",
        "If an unfamiliar app is using a large amount of CPU or Memory, force stop it and uninstall it."
    ),
    " Custom Original Analysis": (
        "We extracted basic fingerprinting details about your operating system and checked your total storage usage.",
        "Ensure your device is running the latest official security update from your manufacturer."
    ),
    "Breach & credential exposure lookup (OSINT)": (
        "We checked public databases to see if any of the domains associated with your device have been part of a known data breach.",
        "If your credentials are part of a breach, change your passwords immediately and enable Two-Factor Authentication (2FA) on your accounts."
    )
}

def _findings_body(findings: dict[str, dict[str, Any]], selected: list[str]) -> str:
    chunks: list[str] = []
    for m in selected:
        entry = findings.get(m)
        if not entry:
            chunks.append(f"#### {m}\n*Pending — no recorded result for this module.*\n")
            continue
        status = entry.get("status", "pending")
        summary = entry.get("summary", "")
        detail = entry.get("detail", "")
        severity = entry.get("severity", "")
        
        if detail and "```" not in detail:
            detail = f"```\n{detail}\n```"
            
        explainer, recommendation = FRIENDLY_MAPPINGS.get(m, (
            "We executed technical forensic checks on this module.",
            "Review findings with a security professional."
        ))
        
        chunk = f"#### {m}\n"
        chunk += f"**What this means:** {explainer}\n\n"
        
        # Only show solution if there is an explicit threat detected
        if severity in ("high", "critical"):
            chunk += f"**Solution:** {recommendation}\n\n"
            
        chunk += f"- **Status:** {status}\n"
        chunk += f"- **Summary:** {summary or '—'}\n\n"
        chunk += f"{detail}\n"
        
        chunks.append(chunk)
        
    return "\n".join(chunks) if chunks else "*No findings recorded.*"


def _conclusion(findings: dict[str, dict[str, Any]], selected: list[str]) -> str:
    completed = [k for k in selected if findings.get(k, {}).get("status") == "completed"]
    flagged = [k for k in selected if findings.get(k, {}).get("severity") in ("high", "medium")]
    parts = []
    if completed:
        parts.append(f"Technical runs completed for: **{', '.join(completed[:8])}**" + (" …" if len(completed) > 8 else "") + ".")
    if flagged:
        parts.append(f"Items flagged for follow-up: **{', '.join(flagged)}**.")
    if not parts:
        return "Complete prioritized module runs and document any anomalies before supervisory submission."
    parts.append("Recommend independent validation of critical findings and preservation of source artifacts.")
    return " ".join(parts)
