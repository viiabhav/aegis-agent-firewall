from aegis.ingestion import ingest_payload
from aegis.models import InputSource


def test_user_message_round_trip():
    doc = ingest_payload("hello", InputSource.USER_MESSAGE)
    assert doc.raw_text == "hello"
    assert doc.normalized.canonical_text == "hello"


def test_html_extracts_visible_and_metadata_content():
    html = '<html><head><meta content="meta value"></head><body><!-- hidden note --><img alt="image alt"><p>Hello</p></body></html>'
    doc = ingest_payload(html, InputSource.HTML)
    assert "Hello" in doc.raw_text
    assert "hidden note" in doc.raw_text
    assert "image alt" in doc.raw_text
    assert "meta value" in doc.raw_text


def test_api_response_is_stable_json():
    doc = ingest_payload({"b": 2, "a": 1}, InputSource.API_RESPONSE)
    assert doc.source_type == InputSource.API_RESPONSE
    assert '"a": 1' in doc.raw_text
