"""Network OSINT: WHOIS, DNS, ports, traceroute, SSL, email authentication."""

from __future__ import annotations

import email
import re
import socket
import ssl
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

import dns.resolver
import whois

# Lightweight static list for demo DNS correlation (extend in production)
KNOWN_MALICIOUS_DOMAINS = frozenset(
    {
        "malware.example.com",
        "badc2.net",
        "phish-login.xyz",
    }
)


@dataclass
class PortResult:
    port: int
    open: bool
    error: str | None = None


def whois_lookup(domain: str) -> dict[str, Any]:
    domain = domain.strip().lower()
    if not domain:
        return {"error": "Empty domain"}
    try:
        w = whois.whois(domain)
        if w is None:
            return {"domain": domain, "raw": "No data"}
        if isinstance(w, list):
            w = w[0]
        text = w.text if hasattr(w, "text") else str(w)
        out: dict[str, Any] = {"domain": domain, "raw": text[:8000]}
        for attr in ("registrar", "creation_date", "expiration_date", "name_servers", "emails"):
            if hasattr(w, attr):
                out[attr] = getattr(w, attr)
        return out
    except Exception as e:
        return {"domain": domain, "error": str(e)}


def dns_resolve_records(host: str) -> dict[str, Any]:
    host = host.strip().lower()
    out: dict[str, Any] = {"host": host, "a": [], "aaaa": [], "mx": [], "txt": []}
    for rtype, key in [("A", "a"), ("AAAA", "aaaa"), ("MX", "mx"), ("TXT", "txt")]:
        try:
            ans = dns.resolver.resolve(host, rtype, lifetime=5)
            out[key] = [str(r) for r in ans]
        except Exception:
            pass
    return out


def analyze_dns_log_lines(lines: list[str]) -> dict[str, Any]:
    """Extract hostnames from pasted DNS log text; flag matches to known-bad set."""
    host_pat = re.compile(
        r"(?:query|qname|name)[:=\s]+([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)",
        re.I,
    )
    found: list[str] = []
    for ln in lines:
        m = host_pat.search(ln)
        if m:
            found.append(m.group(1).lower().rstrip("."))
    flagged = [h for h in found if h in KNOWN_MALICIOUS_DOMAINS or any(bad in h for bad in ("phish", "malware", "c2"))]
    return {"queries_parsed": len(found), "hosts": list(dict.fromkeys(found)), "flagged_suspicious": list(dict.fromkeys(flagged))}


def scan_ports(host: str, ports: tuple[int, ...] = (22, 80, 8080), timeout: float = 1.5) -> list[PortResult]:
    host = host.strip()
    results: list[PortResult] = []
    for p in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            err = sock.connect_ex((host, p))
            results.append(PortResult(port=p, open=(err == 0), error=None if err == 0 else f"code {err}"))
        except socket.gaierror as e:
            results.append(PortResult(port=p, open=False, error=str(e)))
        except Exception as e:
            results.append(PortResult(port=p, open=False, error=str(e)))
        finally:
            sock.close()
    return results


def social_engineering_score(text: str) -> dict[str, Any]:
    """Heuristic phishing indicator checklist (educational)."""
    t = text.lower()
    checks = {
        "urgency_language": bool(re.search(r"\b(urgent|immediately|within\s+\d+\s*(hour|minute)|suspend)\b", t)),
        "credential_request": bool(re.search(r"\b(verify\s+your\s+account|confirm\s+password|click\s+here\s+to\s+log)\b", t)),
        "suspicious_link": bool(re.search(r"https?://\S{1,200}[.-](?:tk|ml|ga|cf|gq|xyz)\b", t)),
        "mismatched_brand": bool(re.search(r"(paypal|microsoft|google).{0,40}@(?!paypal|microsoft|google)", t)),
        "shortened_url": bool(re.search(r"\b(bit\.ly|tinyurl|t\.co|goo\.gl)/", t)),
    }
    score = sum(1 for v in checks.values() if v)
    return {"checks": checks, "risk_score": score, "max": len(checks)}


def parse_email_headers(raw: str) -> tuple[dict[str, str], str | None]:
    msg = email.message_from_string(raw)
    headers = {k: v for k, v in msg.items()}
    body = None
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True)
                if body:
                    body = body.decode(errors="replace")
                break
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode(errors="replace")
    return headers, body


def spf_dkim_dmarc_hints(domain_from: str) -> dict[str, Any]:
    """DNS lookups for SPF/DMARC; DKIM is per-selector and shown as guidance only."""
    domain = domain_from.strip().lower()
    if "@" in domain:
        domain = domain.split("@", 1)[-1]
    out: dict[str, Any] = {"domain": domain}
    try:
        txt = dns.resolver.resolve(domain, "TXT", lifetime=5)
        spf = [str(r) for r in txt if "v=spf1" in str(r).lower()]
        out["spf_records"] = spf
    except Exception as e:
        out["spf_error"] = str(e)
    d = domain
    try:
        dm = dns.resolver.resolve(f"_dmarc.{d}", "TXT", lifetime=5)
        out["dmarc"] = [str(r) for r in dm]
    except Exception as e:
        out["dmarc_error"] = str(e)
    out["dkim_note"] = (
        "DKIM uses the selector from DKIM-Signature (s=...); DNS TXT at {selector}._domainkey.%s" % d
    )
    return out


def dkim_dns_lookup(selector: str, domain: str) -> dict[str, Any]:
    selector = selector.strip()
    domain = domain.strip().lower()
    if "@" in domain:
        domain = domain.split("@", 1)[-1]
    name = f"{selector}._domainkey.{domain}"
    try:
        txt = dns.resolver.resolve(name, "TXT", lifetime=5)
        return {"query": name, "records": [str(r) for r in txt]}
    except Exception as e:
        return {"query": name, "error": str(e)}


def traceroute(host: str, max_hops: int = 20) -> dict[str, Any]:
    host = host.strip()
    # Validate host to prevent command injection: allow only hostnames, IPs, and domains
    if not re.match(r"^[A-Za-z0-9.\-]+$", host):
        return {"error": "Invalid host: only alphanumeric characters, dots, and hyphens are allowed"}
    if sys.platform == "win32":
        cmd = ["tracert", "-d", "-h", str(max_hops), host]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {"stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode}
    except subprocess.TimeoutExpired:
        return {"error": "Traceroute timed out"}
    except FileNotFoundError:
        return {"error": "tracert/traceroute not found on PATH"}


def fetch_ssl_certificate(host: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    host = host.strip()
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                subject = dict(x[0] for x in cert.get("subject", ()))
                return {
                    "host": host,
                    "port": port,
                    "subject": subject,
                    "issuer": issuer,
                    "version": cert.get("version"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": cert.get("subjectAltName"),
                    "self_signed_hint": issuer == subject and bool(issuer),
                }
    except Exception as e:
        return {"host": host, "port": port, "error": str(e)}
