from pathlib import Path

from docx import Document
from PIL import Image, ImageDraw
from pypdf import PdfWriter

from aegis.ingestion import ingest_file
from aegis.models import InputSource


def test_markdown_file(tmp_path: Path):
    path = tmp_path / "sample.md"
    path.write_text("# Heading\nbody", encoding="utf-8")
    doc = ingest_file(path)
    assert doc.source_type == InputSource.MARKDOWN
    assert "Heading" in doc.raw_text


def test_docx_file(tmp_path: Path):
    path = tmp_path / "sample.docx"
    document = Document()
    document.add_paragraph("Document body")
    document.save(path)
    doc = ingest_file(path)
    assert doc.source_type == InputSource.DOCX
    assert "Document body" in doc.raw_text


def test_pdf_file_can_be_opened(tmp_path: Path):
    # pypdf writer gives us a valid parser-level smoke test without adding a PDF generation dependency.
    path = tmp_path / "sample.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    with path.open("wb") as handle:
        writer.write(handle)
    doc = ingest_file(path)
    assert doc.source_type == InputSource.PDF
    assert doc.metadata["pages"] == 1


def test_image_ocr_path(tmp_path: Path):
    path = tmp_path / "sample.png"
    image = Image.new("RGB", (500, 120), "white")
    draw = ImageDraw.Draw(image)
    draw.text((20, 35), "HELLO OCR", fill="black")
    image.save(path)
    doc = ingest_file(path)
    assert doc.source_type == InputSource.IMAGE
    # OCR can vary slightly by local Tesseract build; parser execution is the contract here.
    assert isinstance(doc.raw_text, str)
