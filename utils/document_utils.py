"""
Document text extraction and preprocessing utilities.
Handles PDF, DOCX, and related formats with normalization and cleaning.
When documents contain images, Tesseract OCR is used to extract text from those images (if available).
"""
import io
import re
import zipfile
import unicodedata
from pathlib import Path
from typing import BinaryIO, Iterator, Optional, Union

from pypdf import PdfReader
from docx import Document

try:
    import pytesseract
    from PIL import Image
    _OCR_AVAILABLE = True
except ImportError:
    _OCR_AVAILABLE = False
    pytesseract = None
    Image = None


# --- Supported file extensions ---
SUPPORTED_PDF_EXTENSIONS = {".pdf"}
SUPPORTED_DOCX_EXTENSIONS = {".docx"}


# --- Unicode categories to strip (control, format, surrogate, private-use) ---
_CATEGORIES_TO_STRIP = ("Cc", "Cf", "Cs", "Co", "Cn")


def _ocr_image(image_input: Union["Image.Image", bytes], tesseract_cmd: Optional[str] = None) -> str:
    """
    Run Tesseract OCR on a single image. Returns extracted text or empty string if OCR is unavailable or fails.
    """
    if not _OCR_AVAILABLE or not pytesseract or not Image:
        return ""
    try:
        if tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd
        if isinstance(image_input, bytes):
            img = Image.open(io.BytesIO(image_input))
        else:
            img = image_input
        if img.mode not in ("L", "RGB", "RGBA"):
            img = img.convert("RGB")
        text = pytesseract.image_to_string(img)
        return (text or "").strip()
    except Exception:
        return ""


def _iter_pdf_images(reader: PdfReader) -> Iterator[Union["Image.Image", bytes]]:
    """Yield PIL Images or raw bytes for each embedded image in the PDF (for OCR). Skips images that fail to decode (e.g. invalid lookup table, unsupported color space)."""
    if not _OCR_AVAILABLE or not Image:
        return
    for page in reader.pages:
        images_container = getattr(page, "images", None)
        if images_container is None:
            continue
        # pypdf: iterate by key so one bad image doesn't break the whole page (see pypdf docs on error handling)
        keys = getattr(images_container, "keys", None)
        if keys is not None:
            names = list(keys())
        else:
            try:
                names = list(range(len(images_container)))
            except Exception:
                continue
        for name in names:
            try:
                img_obj = images_container[name]
            except Exception:
                continue
            try:
                pil_img = getattr(img_obj, "image", None)
                if pil_img is not None:
                    yield pil_img
                    continue
                data = getattr(img_obj, "data", None)
                if data:
                    yield Image.open(io.BytesIO(data))
            except Exception:
                # Skip images that fail to decode (e.g. Invalid Lookup Table, unsupported color space)
                continue


def _iter_docx_images(source: Union[str, Path, bytes, BinaryIO]) -> Iterator[bytes]:
    """Yield raw image bytes for each embedded image in the DOCX (e.g. word/media/*)."""
    if isinstance(source, (str, Path)):
        fp = open(source, "rb")
        try:
            z = zipfile.ZipFile(fp, "r")
        except zipfile.BadZipFile:
            fp.close()
            return
    elif isinstance(source, bytes):
        z = zipfile.ZipFile(io.BytesIO(source), "r")
        fp = None
    elif hasattr(source, "read"):
        try:
            source.seek(0)
            z = zipfile.ZipFile(io.BytesIO(source.read()), "r")
        except Exception:
            return
        fp = None
    else:
        return
    try:
        for name in z.namelist():
            if name.startswith("word/media/") and name.rstrip("/") != "word/media":
                try:
                    yield z.read(name)
                except Exception:
                    continue
    finally:
        z.close()
        if fp is not None:
            fp.close()


def extract_text_from_pdf(
    source: Union[str, Path, bytes, BinaryIO],
    password: Optional[str] = None,
    tesseract_cmd: Optional[str] = None,
) -> str:
    """
    Extract raw text from a PDF file. When the PDF contains embedded images,
    Tesseract OCR is used to extract text from those images (if available).

    Args:
        source: File path, bytes, or file-like object.
        password: Optional password for protected PDFs.
        tesseract_cmd: Optional path to tesseract executable (e.g. on Windows). If None, system PATH is used.

    Returns:
        Extracted text as a single string.
    """
    if isinstance(source, (str, Path)):
        reader = PdfReader(str(source))
    elif isinstance(source, bytes):
        reader = PdfReader(io.BytesIO(source))
    elif hasattr(source, "read"):
        reader = PdfReader(source)
    else:
        raise TypeError("source must be path, bytes, or file-like object")

    parts = []
    for page in reader.pages:
        text = page.extract_text()
        if text:
            parts.append(text)

    # OCR text from embedded images when Tesseract is available (skip images that fail to decode)
    if _OCR_AVAILABLE:
        for img in _iter_pdf_images(reader):
            try:
                ocr_text = _ocr_image(img, tesseract_cmd)
                if ocr_text:
                    parts.append(ocr_text)
            except Exception:
                continue

    raw = "\n".join(parts)
    return raw if raw else ""


def extract_text_from_docx(
    source: Union[str, Path, bytes, BinaryIO],
    tesseract_cmd: Optional[str] = None,
) -> str:
    """
    Extract raw text from a DOCX file. When the document contains embedded images,
    Tesseract OCR is used to extract text from those images (if available).

    Args:
        source: File path, bytes, or file-like object.
        tesseract_cmd: Optional path to tesseract executable. If None, system PATH is used.

    Returns:
        Extracted text as a single string.
    """
    if isinstance(source, (str, Path)):
        doc = Document(str(source))
        source_for_images = source
    elif isinstance(source, bytes):
        doc = Document(io.BytesIO(source))
        source_for_images = source
    elif hasattr(source, "read"):
        data = source.read()
        doc = Document(io.BytesIO(data))
        source_for_images = data
    else:
        raise TypeError("source must be path, bytes, or file-like object")

    parts = []
    for para in doc.paragraphs:
        if para.text:
            parts.append(para.text)

    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                if cell.text:
                    parts.append(cell.text)

    # OCR text from embedded images when Tesseract is available
    if _OCR_AVAILABLE:
        for img_bytes in _iter_docx_images(source_for_images):
            ocr_text = _ocr_image(img_bytes, tesseract_cmd)
            if ocr_text:
                parts.append(ocr_text)

    raw = "\n".join(parts)
    return raw if raw else ""


def remove_control_and_special_chars(text: str) -> str:
    """
    Remove control characters, formatting chars, and other problematic Unicode.
    """
    if not text:
        return ""
    return "".join(c for c in text if unicodedata.category(c) not in _CATEGORIES_TO_STRIP)


def remove_extra_whitespace(text: str) -> str:
    """Collapse multiple spaces/newlines and strip edges."""
    if not text:
        return ""
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def remove_page_numbers(text: str) -> str:
    """
    Remove common page number patterns (e.g. "Page 1 of 10", "- 5 -", "5" on its own line).
    """
    if not text:
        return ""
    patterns = [
        r"\b[Pp]age\s+\d+\s+[Oo]f\s+\d+\b",
        r"\b\d+\s+[Oo]f\s+\d+\b",
        r"^\s*[-–—]\s*\d+\s*[-–—]\s*$",
        r"^\s*\d+\s*$",
    ]
    lines = text.split("\n")
    cleaned = []
    for line in lines:
        for pat in patterns:
            line = re.sub(pat, "", line, flags=re.IGNORECASE)
        line = line.strip()
        if line:
            cleaned.append(line)
    return "\n".join(cleaned)


def remove_repeated_sentences(text: str) -> str:
    """
    Remove consecutive duplicate lines/sentences (common OCR artifact).
    """
    if not text:
        return ""
    lines = text.split("\n")
    result = []
    prev = None
    for line in lines:
        line_stripped = line.strip()
        if line_stripped and line_stripped != prev:
            result.append(line)
            prev = line_stripped
    return "\n".join(result)


def remove_ocr_noise(text: str) -> str:
    """
    Remove typical OCR artifacts: stray punctuation, repeated chars, etc.
    """
    if not text:
        return ""
    # Replace repeated non-word chars (e.g. "...", "---")
    text = re.sub(r"([^\w\s])\1{2,}", r"\1", text)
    # Remove single stray punctuation on its own
    text = re.sub(r"\n\s*[^\w\s]\s*\n", "\n", text)
    return text


def remove_headers_footers(text: str) -> str:
    """
    Heuristic: remove lines that look like headers/footers (short, repeated, or
    containing typical header/footer keywords).
    """
    if not text:
        return ""
    lines = text.split("\n")
    header_footer_keywords = {
        "confidential", "draft", "copyright", "©", "page", "©",
        "all rights reserved", "proprietary", "internal use only",
    }
    result = []
    for line in lines:
        s = line.strip().lower()
        if len(s) < 3:
            continue
        if any(kw in s for kw in header_footer_keywords) and len(s) < 80:
            continue
        result.append(line)
    return "\n".join(result)


def normalize_unicode(text: str) -> str:
    """
    Normalize Unicode (e.g. NFD → NFC) for consistent handling.
    """
    if not text:
        return ""
    return unicodedata.normalize("NFKC", text)


def preprocess_text(
    text: str,
    remove_control_chars: bool = True,
    normalize_unicode_text: bool = True,
    collapse_whitespace: bool = True,
    remove_page_nums: bool = True,
    remove_duplicate_lines: bool = True,
    remove_ocr_artifacts: bool = True,
    remove_header_footer: bool = False,
) -> str:
    """
    Preprocess extracted text: clean and normalize.

    Args:
        text: Raw extracted text.
        remove_control_chars: Strip control/format/special Unicode.
        normalize_unicode_text: NFKC normalization.
        collapse_whitespace: Collapse multiple spaces/newlines.
        remove_page_nums: Remove page number patterns.
        remove_duplicate_lines: Remove consecutive duplicate lines.
        remove_ocr_artifacts: Remove OCR noise patterns.
        remove_header_footer: Heuristic removal of header/footer lines.

    Returns:
        Cleaned and normalized text.
    """
    if not text:
        return ""

    if remove_control_chars:
        text = remove_control_and_special_chars(text)
    if normalize_unicode_text:
        text = normalize_unicode(text)
    if remove_page_nums:
        text = remove_page_numbers(text)
    if remove_duplicate_lines:
        text = remove_repeated_sentences(text)
    if remove_ocr_artifacts:
        text = remove_ocr_noise(text)
    if remove_header_footer:
        text = remove_headers_footers(text)
    if collapse_whitespace:
        text = remove_extra_whitespace(text)

    return text


def extract_and_preprocess(
    source: Union[str, Path, bytes, BinaryIO],
    file_ext: Optional[str] = None,
    password: Optional[str] = None,
    preprocess: bool = True,
    tesseract_cmd: Optional[str] = None,
    **preprocess_kwargs,
) -> str:
    """
    Extract text from a document and optionally preprocess it.
    When the document contains images, Tesseract OCR is used to extract text from them (if available).

    Args:
        source: File path, bytes, or file-like object.
        file_ext: Extension (e.g. '.pdf', '.docx'). Inferred from path if possible.
        password: Optional PDF password.
        preprocess: Whether to run preprocessing.
        tesseract_cmd: Optional path to tesseract executable (e.g. Windows: r'C:\\Program Files\\Tesseract-OCR\\tesseract.exe'). On production (e.g. Render) leave unset to use system tesseract from PATH.
        **preprocess_kwargs: Passed to preprocess_text().

    Returns:
        Extracted (and optionally preprocessed) text.
    """
    if file_ext is None and isinstance(source, (str, Path)):
        file_ext = Path(source).suffix.lower()
    if file_ext is None and hasattr(source, "name"):
        file_ext = Path(getattr(source, "name", "") or "").suffix.lower()
    if not file_ext:
        file_ext = ".pdf"  # fallback

    file_ext = file_ext.lower() if file_ext.startswith(".") else f".{file_ext}".lower()

    if file_ext in SUPPORTED_PDF_EXTENSIONS:
        raw = extract_text_from_pdf(source, password=password, tesseract_cmd=tesseract_cmd)
    elif file_ext in SUPPORTED_DOCX_EXTENSIONS:
        raw = extract_text_from_docx(source, tesseract_cmd=tesseract_cmd)
    else:
        raise ValueError(f"Unsupported file type: {file_ext}. Supported: PDF, DOCX")

    if preprocess:
        return preprocess_text(raw, **preprocess_kwargs)
    return raw


def get_supported_extensions() -> set:
    """Return all supported file extensions for extraction."""
    return SUPPORTED_PDF_EXTENSIONS | SUPPORTED_DOCX_EXTENSIONS


def is_supported(filename_or_ext: str) -> bool:
    """Check if the given filename or extension is supported."""
    ext = filename_or_ext.lower()
    if not ext.startswith("."):
        ext = Path(ext).suffix.lower() if "." in ext else f".{ext}"
    return ext in get_supported_extensions()


# --- Recursive text chunking ---
DEFAULT_CHUNK_SIZE = 2000
DEFAULT_CHUNK_OVERLAP = 200
DEFAULT_SEPARATORS = ["\n\n", "\n", ". ", ", ", " ", ""]


def recursive_chunk(
    text: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    chunk_overlap: int = DEFAULT_CHUNK_OVERLAP,
    separators: Optional[list] = None,
) -> list[str]:
    """
    Split text into chunks using recursive splitting with overlap.

    Tries separators in order (paragraph → line → sentence → word → char).
    If a piece exceeds chunk_size, recursively splits it with the next separator.
    Overlap is applied between consecutive chunks.

    Args:
        text: Text to split.
        chunk_size: Target max characters per chunk.
        chunk_overlap: Character overlap between consecutive chunks.
        separators: List of separator strings (tried in order).

    Returns:
        List of chunk strings.
    """
    if not text or not text.strip():
        return []

    if separators is None:
        separators = list(DEFAULT_SEPARATORS)
    overlap = min(max(0, chunk_overlap), chunk_size - 1)

    def _split_recursive(t: str, sep_idx: int) -> list[str]:
        sep = separators[sep_idx] if sep_idx < len(separators) else ""
        if sep:
            raw = t.split(sep)
            parts = [p.strip() for p in raw if p.strip()]
        else:
            parts = list(t)

        chunks = []
        current = ""
        for part in parts:
            if not part:
                continue
            sep_str = sep if current and sep else ""
            candidate = (current + sep_str + part) if current else part

            if len(candidate) <= chunk_size:
                current = candidate
            else:
                if current:
                    chunks.append(current)
                if len(part) > chunk_size:
                    sub = _split_recursive(part, sep_idx + 1) if sep_idx + 1 < len(separators) else _split_by_char(part)
                    for i, c in enumerate(sub):
                        if i == 0 and overlap and chunks:
                            c = chunks[-1][-overlap:] + c
                        chunks.append(c)
                    current = ""
                else:
                    overlap_str = current[-overlap:] if len(current) >= overlap else current
                    current = overlap_str + sep_str + part

        if current:
            chunks.append(current)
        return chunks

    def _split_by_char(s: str) -> list[str]:
        out = []
        start = 0
        while start < len(s):
            end = min(start + chunk_size, len(s))
            out.append(s[start:end])
            start = end - overlap if end < len(s) else len(s)
        return out

    return _split_recursive(text.strip(), 0)
