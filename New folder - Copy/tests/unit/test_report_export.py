import pytest
from services import report_export

def test_export_pdf_bytes_nonempty():
    sample_md = "# Title\n\nThis is a test report.\n\n---\n"
    pdf_bytes = report_export.export_pdf_bytes(sample_md)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0

def test_export_docx_bytes_nonempty():
    sample_md = "# Title\n\nThis is a test report."
    docx_bytes = report_export.export_docx_bytes(sample_md)
    assert isinstance(docx_bytes, bytes)
    assert len(docx_bytes) > 0
