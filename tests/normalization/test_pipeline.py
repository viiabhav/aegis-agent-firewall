import base64
import codecs

from aegis.normalization import normalize_text


def test_removes_zero_width_and_folds_homoglyphs():
    result = normalize_text("p\u200bаss")  # second visible 'a' is Cyrillic
    assert result.canonical_text == "pass"


def test_reveals_url_encoded_text():
    result = normalize_text("hello%20world")
    assert any(a.codec == "url" and a.decoded_text == "hello world" for a in result.decoded_artifacts)


def test_reveals_base64_token():
    encoded = base64.b64encode(b"plain text payload").decode()
    result = normalize_text(f"value={encoded}")
    assert any(a.codec == "base64" and a.decoded_text == "plain text payload" for a in result.decoded_artifacts)


def test_reveals_hex_token():
    encoded = "plain text payload".encode().hex()
    result = normalize_text(encoded)
    assert any(a.codec == "hex" and a.decoded_text == "plain text payload" for a in result.decoded_artifacts)


def test_reveals_rot13_when_language_improves():
    original = codecs.encode("this is the text and it is for you", "rot_13")
    result = normalize_text(original)
    assert any(a.codec == "rot13" and "this is the text" in a.decoded_text for a in result.decoded_artifacts)
