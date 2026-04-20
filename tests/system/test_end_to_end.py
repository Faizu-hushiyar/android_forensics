import sys
import types
import datetime
import pytest
from unittest import mock
from services import db, case_report, report_export

@pytest.fixture
def mock_streamlit(monkeypatch):
    # Create a dummy streamlit module
    dummy = types.ModuleType('streamlit')
    dummy.some_func = mock.MagicMock()
    # Insert dummy into sys.modules so imports resolve
    monkeypatch.setitem(sys.modules, 'streamlit', dummy)
    return dummy

def test_system_flow(mock_streamlit):
    # Simulate creating a case, adding a finding, and generating a PDF report
    # Ensure a user exists for the case
    db.register_user(name="sys_tester", email="sys_tester@example.com", password="pwd")
    conn = db.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM users WHERE email=?", ("sys_tester@example.com",))
    user_id = cur.fetchone()["user_id"]
    conn.close()

    ref = "SYS-TEST-001"
    db.create_or_update_case(
        case_reference=ref,
        case_name="System Test Case",
        analyst_name="sys_tester",
        classification="OFFICIAL",
        selected_tools=[],
        created_at=datetime.datetime.utcnow().isoformat(),
        status="open",
        user_id=user_id,
        device_label="SysDevice",
        adb_serial="SYS123",
        detailed_info=None,
    )
    db.upsert_finding(
        case_reference=ref,
        tool_name="Hidden apps detection",
        summary="No hidden apps",
        detail="",
        status="completed",
        severity=None,
        recorded_at="2026-01-01T00:00:00",
    )
    findings = db.get_findings(ref)
    md = case_report.official_report_markdown(
        case_reference=ref,
        case_title="System Test Case",
        classification="OFFICIAL",
        selected_modules=[" Hidden apps detection"],
        findings=findings,
        device_label="SysDevice",
        adb_serial="SYS123",
        analyst="sys_tester",
        chain_of_custody_note="System test note",
        detailed_device_info=None,
    )
    pdf = report_export.export_pdf_bytes(md)
    assert isinstance(pdf, bytes) and len(pdf) > 0
