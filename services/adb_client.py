"""Android Debug Bridge (ADB) helpers for live device forensics."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any


def find_adb_executable() -> str | None:
    """Return 'adb' if on PATH, else None."""
    return shutil.which("adb")


def run_adb(
    args: list[str],
    *,
    timeout: int = 120,
    serial: str | None = None,
) -> tuple[int, str, str]:
    exe = find_adb_executable()
    if not exe:
        return -1, "", "adb not found on PATH. Install Android SDK Platform-Tools and add to PATH."
    cmd = [exe]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(args)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"adb timed out after {timeout}s"
    except OSError as e:
        return -1, "", str(e)
    except Exception as e:
        return -1, "", str(e)


def list_devices() -> list[dict[str, str]]:
    code, out, err = run_adb(["devices", "-l"], timeout=30)
    if code != 0:
        return [{"serial": "error", "state": err or out or "adb failed"}]
    devices: list[dict[str, str]] = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("List of devices"):
            continue
        parts = ln.split()
        if len(parts) >= 2:
            serial, state = parts[0], parts[1]
            extras = " ".join(parts[2:]) if len(parts) > 2 else ""
            devices.append({"serial": serial, "state": state, "extras": extras})
    return devices

def get_devices_for_ui() -> list[dict[str, str]]:
    devices = list_devices()

    formatted = []
    for d in devices:
        serial = d.get("serial", "")
        state = d.get("state", "")

        if state != "device":
            continue

        if ":" in serial:
            dtype = "wifi"
        else:
            dtype = "usb"

        formatted.append({
            "id": serial,
            "type": dtype,
            "name": device_model(serial)
        })

    return formatted


def get_connected_serials() -> list[str]:
    return [d["serial"] for d in list_devices() if d.get("state") == "device"]


def device_model(serial: str | None) -> str:
    _, out_err, err = run_adb(["shell", "getprop", "ro.product.model"], serial=serial, timeout=15)
    if err:
        return "Unknown device"
    return (out_err or "").strip() or "Unknown device"


def shell(serial: str | None, shell_command: str, timeout: int = 180) -> tuple[int, str, str]:
    return run_adb(["shell", shell_command], serial=serial, timeout=timeout)


@dataclass
class DevicePullBundle:
    packages_text: str
    launcher_text: str
    props_and_settings: str
    logcat_text: str
    dumpsys_permissions_sample: str
    sms_text: str
    calls_text: str
    netstats_text: str
    errors: list[str]


def pull_forensic_bundle(
    serial: str | None,
    logcat_lines: int = 800,
    *,
    include_dumpsys: bool = True,
    include_logcat: bool = True,
) -> DevicePullBundle:
    errors: list[str] = []

    def _do(label: str, fn) -> str:
        try:
            code, out, err = fn()
            if code != 0 and err:
                errors.append(f"{label}: {err.strip()[:200]}")
            return out or ""
        except Exception as e:
            errors.append(f"{label}: {e!s}")
            return ""

    pkgs = _do(
        "pm_list",
        lambda: shell(serial, "pm list packages -f", timeout=120),
    )
    launcher = _do(
        "launcher_query",
        lambda: shell(
            serial,
            "cmd package query-activities -a android.intent.action.MAIN "
            "-c android.intent.category.LAUNCHER 2>/dev/null | head -n 500",
            timeout=60,
        ),
    )
    if not launcher.strip():
        launcher = _do(
            "launcher_fallback",
            lambda: shell(
                serial,
                "pm list packages -3",
                timeout=60,
            ),
        )

    props = _do(
        "props",
        lambda: shell(
            serial,
            "echo '=== getprop (adb related) ===' && getprop | grep -i adb ; "
            "echo '=== settings global ===' ; settings get global adb_enabled 2>/dev/null ; "
            "settings get global development_settings_enabled 2>/dev/null ; "
            "settings get secure adb_wifi_enabled 2>/dev/null",
            timeout=30,
        ),
    )

    if include_logcat:
        logcat = _do(
            "logcat",
            lambda: shell(serial, f"logcat -d -t {logcat_lines}", timeout=120),
        )
    else:
        logcat = ""

    if include_dumpsys:
        dumpsys = _do(
            "dumpsys_pkg",
            lambda: shell(
                serial,
                "dumpsys package | grep -E 'Package \\[|permission\\.android\\.' | head -n 2000",
                timeout=180,
            ),
        )
    else:
        dumpsys = ""

    sms = _do(
        "sms",
        lambda: shell(
            serial,
            "content query --uri content://sms/inbox --projection address,body,date 2>/dev/null | head -n 100",
            timeout=45,
        ),
    )

    calls = _do(
        "calls",
        lambda: shell(
            serial,
            "content query --uri content://call_log/calls --projection number,type,date 2>/dev/null | head -n 100",
            timeout=45,
        ),
    )

    netstats = _do(
        "netstats",
        lambda: shell(
            serial,
            "dumpsys netstats | head -n 400",
            timeout=60,
        ),
    )

    return DevicePullBundle(
        packages_text=pkgs,
        launcher_text=launcher,
        props_and_settings=props,
        logcat_text=logcat,
        dumpsys_permissions_sample=dumpsys,
        sms_text=sms,
        calls_text=calls,
        netstats_text=netstats,
        errors=errors,
    )


def launcher_packages_from_query(launcher_dump: str) -> str:
    """Normalize launcher query / pm output into 'package:... launcher' lines for diffing."""
    pkgs: set[str] = set()
    for m in re.finditer(r"ComponentInfo\{([^/:\s]+)/", launcher_dump):
        pkgs.add(m.group(1).strip())
    for m in re.finditer(r"package:([^\s]+)", launcher_dump):
        pkgs.add(m.group(1).strip())
    return "\n".join(f"package:{p} launcher" for p in sorted(pkgs))

# ==============================
# 🔌 Wireless ADB (TCP/IP)
# ==============================

def enable_tcpip(serial: str, port: int = 5555) -> bool:
    code, out, err = run_adb(["tcpip", str(port)], serial=serial, timeout=30)
    return code == 0


def get_device_ip(serial: str) -> str | None:
    code, out, err = run_adb(["shell", "ip route"], serial=serial, timeout=15)
    if code != 0:
        return None

    for part in out.split():
        if part.count(".") == 3:
            return part
    return None


def connect_tcp(ip: str, port: int = 5555) -> bool:
    code, out, err = run_adb(["connect", f"{ip}:{port}"], timeout=20)
    return code == 0

