from aegis.ingestion import ingest_payload
from aegis.models import InputSource

RAW_EMAIL = """From: sender@example.com
To: receiver@example.com
Subject: Test mail
Content-Type: multipart/alternative; boundary=abc

--abc
Content-Type: text/plain; charset=utf-8

Plain body
--abc
Content-Type: text/html; charset=utf-8

<html><body><p>HTML body</p></body></html>
--abc--
"""


def test_email_extracts_subject_and_bodies():
    doc = ingest_payload(RAW_EMAIL, InputSource.EMAIL)
    assert "Test mail" in doc.raw_text
    assert "Plain body" in doc.raw_text
    assert "HTML body" in doc.raw_text
