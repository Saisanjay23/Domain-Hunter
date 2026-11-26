import base64
import codecs
import hashlib
import re
from io import BytesIO
from typing import Dict, Any, Optional
import warnings
import mmh3
from PIL import Image
import imagehash


# Magic-byte signatures of image formats browsers accept as favicons / logos.
_MAGIC_SIGNATURES = (
    (b"\x00\x00\x01\x00", "ICO"),
    (b"\x00\x00\x02\x00", "CUR"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"BM", "BMP"),
)


def mmh3_hash(content: bytes) -> int:
    """
    Computes Shodan / FOFA / ZoomEye compatible favicon hash:
    signed 32-bit MurmurHash3 of the RFC 2045 base64 encoding of the raw bytes
    (newline every 76 chars and a trailing newline, i.e. Python's base64.encodebytes).
    """
    b64 = codecs.encode(content, "base64")
    return mmh3.hash(b64)


def md5_hash(content: bytes) -> str:
    """Computes MD5 hexdigest."""
    return hashlib.md5(content).hexdigest()


def sha256_hash(content: bytes) -> str:
    """Computes SHA256 hexdigest."""
    return hashlib.sha256(content).hexdigest()


def is_svg(content: bytes) -> bool:
    """
    True if the bytes are an SVG document. Looks for an <svg root element in the first
    4 KB (skipping XML prologue, comments and doctype) - a bare <?xml prologue is NOT
    enough, since XML error pages (e.g. S3 AccessDenied) also start with it.
    """
    head = content[:4096].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    return b"<svg" in head and not head.startswith((b"<!doctype html", b"<html"))


def sniff_image_format(content: bytes) -> Optional[str]:
    """Identifies the image format from magic bytes. Returns None if not an image."""
    if not content:
        return None
    for sig, fmt in _MAGIC_SIGNATURES:
        if content.startswith(sig):
            return fmt
    if content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        return "WEBP"
    if content[4:12] in (b"ftypavif", b"ftypavis"):
        return "AVIF"
    if is_svg(content):
        return "SVG"
    return None


def is_image_bytes(content: bytes) -> bool:
    """True if content is a real image (magic bytes, SVG, or anything Pillow can parse)."""
    if not content:
        return False
    if sniff_image_format(content):
        return True
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            Image.open(BytesIO(content)).verify()
        return True
    except Exception:
        return False


def phash_hash(content: bytes) -> Optional[str]:
    """
    Computes perceptual hash (pHash) using ImageHash & Pillow.
    Transparent images are flattened onto white first so that the same logo shipped as
    a transparent PNG and as a JPEG on a white background produce comparable hashes.
    Returns hex string or None if unparseable (e.g. raw SVG).
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            img = Image.open(BytesIO(content))
            img.load()
            if img.mode in ("P", "PA", "LA", "RGBA", "La") or "transparency" in img.info:
                rgba = img.convert("RGBA")
                background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
                img = Image.alpha_composite(background, rgba).convert("RGB")
            return str(imagehash.phash(img))
    except Exception:
        return None


def _svg_dimensions(content: bytes):
    text = content[:8192].decode("utf-8", errors="ignore")
    root = re.search(r"<svg\b[^>]*>", text, re.I | re.S)
    tag = root.group(0) if root else text
    w_match = re.search(r'\bwidth=["\']\s*([0-9.]+)\s*(?:px)?["\']', tag, re.I)
    h_match = re.search(r'\bheight=["\']\s*([0-9.]+)\s*(?:px)?["\']', tag, re.I)
    if w_match and h_match:
        return int(float(w_match.group(1))), int(float(h_match.group(1)))
    vb_match = re.search(r'\bviewBox=["\']\s*([0-9.\-]+)[\s,]+([0-9.\-]+)[\s,]+([0-9.]+)[\s,]+([0-9.]+)\s*["\']', tag, re.I)
    if vb_match:
        return int(float(vb_match.group(3))), int(float(vb_match.group(4)))
    return None, None


def get_image_metadata(content: bytes) -> Dict[str, Any]:
    """
    Attempts to read image format and dimensions (width, height).
    """
    meta: Dict[str, Any] = {
        "format": None,
        "width": None,
        "height": None,
        "size_bytes": len(content),
    }
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            img = Image.open(BytesIO(content))
            meta["format"] = img.format
            meta["width"] = img.width
            meta["height"] = img.height
    except Exception:
        fmt = sniff_image_format(content)
        meta["format"] = fmt
        if fmt == "SVG":
            try:
                meta["width"], meta["height"] = _svg_dimensions(content)
            except Exception:
                pass
    return meta


_MIME_BY_FORMAT = {
    "ICO": "image/x-icon",
    "CUR": "image/x-icon",
    "PNG": "image/png",
    "GIF": "image/gif",
    "JPEG": "image/jpeg",
    "MPO": "image/jpeg",
    "BMP": "image/bmp",
    "WEBP": "image/webp",
    "SVG": "image/svg+xml",
    "AVIF": "image/avif",
}


def make_preview_data_uri(content: bytes, fmt: Optional[str] = None, max_bytes: int = 512 * 1024) -> Optional[str]:
    """Encodes image bytes as a safe data: URI so the UI never hotlinks suspect hosts."""
    if not content or len(content) > max_bytes:
        return None
    detected = (fmt or sniff_image_format(content) or "").upper()
    mime = _MIME_BY_FORMAT.get(detected)
    if not mime:
        return None
    return f"data:{mime};base64,{base64.b64encode(content).decode('ascii')}"


def analyze_icon_bytes(content: bytes) -> Dict[str, Any]:
    """
    Calculates all cryptographic and visual hashes along with image metadata.
    """
    meta = get_image_metadata(content)
    return {
        "mmh3": mmh3_hash(content),
        "md5": md5_hash(content),
        "sha256": sha256_hash(content),
        "phash": phash_hash(content),
        "format": meta["format"],
        "dimensions": f"{meta['width']}x{meta['height']}" if meta["width"] and meta["height"] else None,
        "size_bytes": meta["size_bytes"],
    }
