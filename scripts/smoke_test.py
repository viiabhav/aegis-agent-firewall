from aegis.ingestion import ingest_payload
from aegis.models import InputSource


def main() -> None:
    sample = "See%20this and U29tZSBwbGFpbiB0ZXh0"
    doc = ingest_payload(sample, InputSource.USER_MESSAGE)
    print("source:", doc.source_type)
    print("canonical:", doc.normalized.canonical_text)
    print("decoded:", [(x.codec, x.decoded_text) for x in doc.normalized.decoded_artifacts])
    print("scan_text:", doc.normalized.scan_text)


if __name__ == "__main__":
    main()
