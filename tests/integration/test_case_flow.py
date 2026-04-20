import pytest
from services import db, case_report, report_export
from datetime import datetime

@pytest.fixture
def fresh_case():
    # Ensure a user exists
    db.register_user(name="tester", email="tester@example.com", password="pwd")
    # Retrieve the user_id
    conn = db.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM users WHERE email=?", ("tester@example.com",))
    user_id = cur.fetchone()["user_id"]
    conn.close()

    case_ref = f"TEST-{datetime.utcnow().timestamp()}"
    db.create_or_update_case(
        case_reference=case_ref,
        case_name="Test Case",
        analyst_name="tester",
        classification="OFFICIAL",
        selected_tools=[],
        created_at=datetime.utcnow().isoformat(),
        status="open",
        user_id=user_id,
        device_label="TestDevice",
        adb_serial="ABC123",
        detailed_info=None,
    )
    # Record a fake finding
    db.upsert_finding(
        case_reference=case_ref,
        tool_name="Hidden apps detection",
        summary="No hidden apps detected",
        detail="",
        status="completed",
        severity=None,
        recorded_at=datetime.utcnow().isoformat(),
    )
    return case_ref

def test_end_to_end_report(fresh_case):
    # Pull findings from DB
    findings = db.get_findings(fresh_case)
    md = case_report.official_report_markdown(
        case_reference=fresh_case,
        case_title="Test Case",
        classification="OFFICIAL",
        selected_modules=[" Hidden apps detection"],
        findings=findings,
        device_label="TestDevice",
        adb_serial="ABC123",
        analyst="tester",
        chain_of_custody_note="Test note",
        detailed_device_info=None,
    )
    assert "Hidden apps detection" in md
    pdf_bytes = report_export.export_pdf_bytes(md)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0
