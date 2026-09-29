from pathlib import Path
from aegis.ingestion import ingest_file
from aegis.models import InputSource


def test_eml_file(tmp_path: Path):
    path = tmp_path / "mail.eml"
    path.write_text("From: a@example.com\nTo: b@example.com\nSubject: Hi\n\nBody", encoding="utf-8")
    doc = ingest_file(path)
    assert doc.source_type == InputSource.EMAIL
    assert "Body" in doc.raw_text
