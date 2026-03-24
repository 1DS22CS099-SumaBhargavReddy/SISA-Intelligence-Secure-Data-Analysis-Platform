"""
File Parser — Multi-format file content extraction.
Supports PDF, DOC/DOCX, TXT, and LOG files.
"""

import io
from typing import Optional


def extract_text_from_pdf(file_bytes: bytes) -> str:
    """Extract text from a PDF file."""
    try:
        from PyPDF2 import PdfReader
        reader = PdfReader(io.BytesIO(file_bytes))
        pages = []
        for page in reader.pages:
            text = page.extract_text()
            if text:
                pages.append(text)
        return "\n\n".join(pages)
    except Exception as e:
        return f"[Error extracting PDF: {e}]"


def extract_text_from_docx(file_bytes: bytes) -> str:
    """Extract text from a DOCX file."""
    try:
        from docx import Document
        doc = Document(io.BytesIO(file_bytes))
        paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
        return "\n".join(paragraphs)
    except Exception as e:
        return f"[Error extracting DOCX: {e}]"


def extract_text_from_plain(file_bytes: bytes) -> str:
    """Extract text from a plain text or log file."""
    try:
        return file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return file_bytes.decode("latin-1")
        except Exception:
            return file_bytes.decode("utf-8", errors="replace")


def parse_file(filename: str, file_bytes: bytes) -> dict:
    """
    Parse a file based on extension and return extracted text + metadata.
    Returns dict with 'content', 'content_type', 'filename', 'size'.
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    extractors = {
        "pdf": ("document", extract_text_from_pdf),
        "doc": ("document", extract_text_from_docx),
        "docx": ("document", extract_text_from_docx),
        "txt": ("text", extract_text_from_plain),
        "log": ("logs", extract_text_from_plain),
    }

    if ext not in extractors:
        return {
            "content": extract_text_from_plain(file_bytes),
            "content_type": "text",
            "filename": filename,
            "size": len(file_bytes),
            "error": f"Unsupported file extension: .{ext}",
        }

    content_type, extractor = extractors[ext]
    content = extractor(file_bytes)

    return {
        "content": content,
        "content_type": content_type,
        "filename": filename,
        "size": len(file_bytes),
    }


def detect_input_type(filename: str) -> str:
    """Infer input_type from filename extension."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext == "log":
        return "log"
    if ext in ("sql",):
        return "sql"
    if ext in ("pdf", "doc", "docx"):
        return "file"
    return "text"
