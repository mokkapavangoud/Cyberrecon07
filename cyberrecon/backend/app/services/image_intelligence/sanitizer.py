"""Metadata sanitisation.

Strategy
--------
JPEG / PNG / WebP are stripped at the container level: metadata segments are removed and every other byte
(including the compressed pixel data) is copied verbatim, so there is no re-compression and no quality loss.
Data appended after the image end marker is dropped. GIF / BMP / TIFF (and any case where the lossless path
fails verification) are re-encoded through Pillow from decoded pixels only.

Every output is re-inspected; the sanitiser refuses to return a file that still carries metadata.
"""
from __future__ import annotations

import hashlib
import io
import struct
from dataclasses import dataclass, field

import piexif
from PIL import Image, ImageChops, ImageOps

from .inspector import FORMAT_EXT, FORMAT_MIME, ImageValidationError, inspect_image, open_validated, safe_stem

PNG_KEEP = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"sBIT", b"pHYs", b"bKGD", b"hIST"}


@dataclass
class SanitizeResult:
    data: bytes
    filename: str
    mime_type: str
    sha256: str
    method: str  # lossless-strip | re-encode
    removed: list[str]
    retained: list[str]
    before: dict
    after: dict
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- JPEG
def _jfif_header(seg: bytes) -> bytes:
    """Rebuild a minimal JFIF APP0 (drops any embedded thumbnail, keeps version/density)."""
    ver = seg[5:7] if len(seg) >= 7 else b"\x01\x01"
    units = seg[7:8] if len(seg) >= 8 else b"\x00"
    dens = seg[8:12] if len(seg) >= 12 else b"\x00\x01\x00\x01"
    payload = b"JFIF\x00" + ver + units + dens + b"\x00\x00"
    return b"\xff\xe0" + struct.pack(">H", len(payload) + 2) + payload


def _orientation_exif(orientation: int) -> bytes:
    blob = piexif.dump({"0th": {piexif.ImageIFD.Orientation: orientation}, "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None})
    return b"\xff\xe1" + struct.pack(">H", len(blob) + 2) + blob


def strip_jpeg(data: bytes, *, keep_icc: bool, orientation: int | None) -> tuple[bytes, list[str]]:
    if data[:2] != b"\xff\xd8":
        raise ValueError("not a JPEG")
    out = bytearray(b"\xff\xd8")
    retained: list[str] = []
    n, i = len(data), 2
    orient_written = not (orientation and orientation != 1)

    def maybe_orientation():
        nonlocal orient_written
        if not orient_written:
            out.extend(_orientation_exif(orientation))
            retained.append("EXIF Orientation tag only (needed to display the image the right way up)")
            orient_written = True

    while i < n:
        if data[i] != 0xFF:
            raise ValueError("corrupt JPEG marker alignment")
        while i < n and data[i] == 0xFF:
            i += 1
        marker = data[i]
        i += 1
        if marker == 0xD9:  # EOI – everything after is discarded
            maybe_orientation()
            out.extend(b"\xff\xd9")
            return bytes(out), retained
        if marker == 0x01 or 0xD0 <= marker <= 0xD8:
            out.extend(bytes([0xFF, marker]))
            continue
        length = struct.unpack(">H", data[i:i + 2])[0]
        if length < 2 or i + length > n:
            raise ValueError("corrupt JPEG segment")
        seg = data[i + 2: i + length]
        raw_seg = data[i: i + length]
        i += length

        keep = True
        if marker == 0xE0:
            if seg.startswith(b"JFIF\x00"):
                out.extend(_jfif_header(seg))
                maybe_orientation()
            keep = False
        elif marker == 0xE2 and seg.startswith(b"ICC_PROFILE\x00"):
            keep = keep_icc
            if keep:
                retained.append("ICC colour profile (kept for colour accuracy)")
        elif marker == 0xEE and seg.startswith(b"Adobe"):
            keep = True  # colour-transform flag needed to decode some CMYK/YCCK files
        elif 0xE0 <= marker <= 0xEF or marker == 0xFE:
            keep = False  # EXIF/XMP (APP1), IPTC (APP13), MPF, comments, other APPn
        else:
            maybe_orientation()
        if keep:
            out.extend(bytes([0xFF, marker]) + raw_seg)
        if marker == 0xDA:  # scan data follows until the next real marker
            j = i
            while j < n:
                if data[j] == 0xFF:
                    nxt = data[j + 1] if j + 1 < n else None
                    if nxt == 0x00 or (nxt is not None and 0xD0 <= nxt <= 0xD7):
                        j += 2
                        continue
                    if nxt == 0xFF:
                        j += 1
                        continue
                    break
                j += 1
            out.extend(data[i:j])
            i = j
    raise ValueError("JPEG has no EOI marker")


# --------------------------------------------------------------------------- PNG
def strip_png(data: bytes, *, keep_icc: bool) -> bytes:
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    out = bytearray(data[:8])
    pos, n = 8, len(data)
    while pos + 8 <= n:
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8]
        end = pos + 12 + length
        if end > n:
            raise ValueError("truncated PNG chunk")
        if ctype in (b"acTL", b"fcTL", b"fdAT"):
            raise ValueError("animated PNG")
        if ctype in PNG_KEEP or (ctype == b"iCCP" and keep_icc):
            out.extend(data[pos:end])
        if ctype == b"IEND":
            return bytes(out)
        pos = end
    raise ValueError("PNG has no IEND")


# --------------------------------------------------------------------------- WebP
def strip_webp(data: bytes, *, keep_icc: bool) -> bytes:
    if data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        raise ValueError("not a WebP")
    chunks: list[tuple[bytes, bytes]] = []
    pos = 12
    while pos + 8 <= len(data):
        fourcc, size = data[pos:pos + 4], struct.unpack("<I", data[pos + 4:pos + 8])[0]
        payload = data[pos + 8: pos + 8 + size]
        if len(payload) != size:
            raise ValueError("truncated WebP chunk")
        if fourcc in (b"ANIM", b"ANMF"):
            raise ValueError("animated WebP")
        chunks.append((fourcc, payload))
        pos += 8 + size + (size & 1)
    drop = {b"EXIF", b"XMP "} | (set() if keep_icc else {b"ICCP"})
    body = bytearray(b"WEBP")
    for fourcc, payload in chunks:
        if fourcc in drop:
            continue
        if fourcc == b"VP8X" and payload:
            flags = payload[0] & ~(0x08 | 0x04)
            if not keep_icc:
                flags &= ~0x20
            payload = bytes([flags]) + payload[1:]
        body.extend(fourcc + struct.pack("<I", len(payload)) + payload + (b"\x00" if len(payload) & 1 else b""))
    return b"RIFF" + struct.pack("<I", len(body)) + bytes(body)


# --------------------------------------------------------------------------- re-encode fallback
def reencode(opened_img: Image.Image, fmt: str) -> bytes:
    img = ImageOps.exif_transpose(opened_img)  # bake orientation into pixels before dropping the tag
    if img.mode == "P":
        img = img.convert("RGBA" if "transparency" in img.info else "RGB")
    if fmt == "JPEG" and img.mode not in ("RGB", "L", "CMYK"):
        img = img.convert("RGB")
    clean = Image.frombytes(img.mode, img.size, img.tobytes())
    buf = io.BytesIO()
    if fmt == "JPEG":
        clean.save(buf, "JPEG", quality=95, optimize=True)
    elif fmt == "PNG":
        clean.save(buf, "PNG", optimize=True)
    elif fmt == "WEBP":
        clean.save(buf, "WEBP", lossless=True, exact=True)
    elif fmt == "GIF":
        clean.save(buf, "GIF")
    elif fmt == "BMP":
        clean.save(buf, "BMP")
    elif fmt == "TIFF":
        clean.save(buf, "TIFF", compression="tiff_lzw")
    else:  # pragma: no cover
        raise ValueError(fmt)
    return buf.getvalue()


# --------------------------------------------------------------------------- verification
def _residual_metadata(analysis: dict, *, allow_orientation_only: bool) -> list[str]:
    md = analysis["metadata"]
    left = []
    if md["gps"]["present"]:
        left.append("GPS")
    exif_fields = set(md["exif"]["fields"].keys())
    if md["exif"]["present"] and not (allow_orientation_only and exif_fields <= {"Orientation"}):
        left.append("EXIF")
    for key, label in (("xmp", "XMP"), ("iptc", "IPTC")):
        if md[key]["present"]:
            left.append(label)
    if md["text_chunks"]["present"]:
        left.append("text chunks")
    if md["comment"]["present"]:
        left.append("comment")
    return left


def _pixels_equal(a: bytes, b: bytes) -> bool:
    ia, ib = Image.open(io.BytesIO(a)), Image.open(io.BytesIO(b))
    ia.load(), ib.load()
    if ia.size != ib.size:
        return False
    if ia.mode != ib.mode:
        ia, ib = ia.convert("RGBA"), ib.convert("RGBA")
    return ImageChops.difference(ia, ib).getbbox() is None


def sanitize_image(data: bytes, filename: str, *, max_bytes: int, max_pixels: int, keep_icc: bool = True) -> SanitizeResult:
    before = inspect_image(data, filename, max_bytes=max_bytes, max_pixels=max_pixels)
    fmt = before["file"]["detected_format"]
    if before["file"]["animated"]:
        raise ImageValidationError("animated_unsupported", "Animated images cannot be sanitised in this version (it would flatten them to a single frame).")
    opened = open_validated(data, max_bytes=max_bytes, max_pixels=max_pixels)
    orientation = before["metadata"]["exif"].get("orientation")
    needs_rotation = bool(orientation and orientation != 1)

    out: bytes | None = None
    method, retained, notes = "re-encode", [], []
    try:
        if fmt == "JPEG":
            out, retained = strip_jpeg(data, keep_icc=keep_icc, orientation=orientation)
        elif fmt == "PNG" and not needs_rotation:
            out = strip_png(data, keep_icc=keep_icc)
            if keep_icc and before["metadata"]["icc_profile"]["present"]:
                retained.append("ICC colour profile (kept for colour accuracy)")
        elif fmt == "WEBP" and not needs_rotation:
            out = strip_webp(data, keep_icc=keep_icc)
            if keep_icc and before["metadata"]["icc_profile"]["present"]:
                retained.append("ICC colour profile (kept for colour accuracy)")
        if out is not None:
            after_try = inspect_image(out, filename, max_bytes=max_bytes * 2, max_pixels=max_pixels)
            if _residual_metadata(after_try, allow_orientation_only=True) or not _pixels_equal(data, out):
                out = None
            else:
                method = "lossless-strip"
    except Exception:
        out = None
        retained = []

    if out is None:
        out = reencode(opened.image, fmt)
        retained = []
        method = "re-encode"
        notes.append("Pixels were re-encoded" + (" (JPEG quality 95)" if fmt == "JPEG" else "") + ", so the file is not byte-identical in its image data.")
    after = inspect_image(out, filename, max_bytes=max_bytes * 2, max_pixels=max_pixels)
    leftovers = _residual_metadata(after, allow_orientation_only=method == "lossless-strip")
    if leftovers:
        raise ImageValidationError("sanitize_failed", f"Sanitisation could not remove: {', '.join(leftovers)}. No file was produced.")
    if method == "lossless-strip":
        notes.append("Metadata segments were removed without re-compressing the image; pixel data is unchanged.")
    if fmt == "JPEG" and before["metadata"]["icc_profile"]["present"] and not keep_icc:
        notes.append("The ICC colour profile was removed; colours may look slightly different in colour-managed viewers.")
    if len(out) < len(data) and len(data) - len(out) > 0:
        notes.append(f"Output is {len(data) - len(out):,} bytes smaller than the original.")

    md = before["metadata"]
    removed = []
    if md["exif"]["present"]:
        removed.append("EXIF")
    if md["gps"]["present"]:
        removed.append("GPS location")
    if md["xmp"]["present"]:
        removed.append("XMP")
    if md["iptc"]["present"]:
        removed.append("IPTC")
    if md["text_chunks"]["present"]:
        removed.append("text chunks")
    if md["comment"]["present"]:
        removed.append("comment")
    if md["icc_profile"]["present"] and (not keep_icc or method == "re-encode"):
        removed.append("ICC profile")
    ext = FORMAT_EXT[fmt]
    return SanitizeResult(
        data=out, filename=f"{safe_stem(filename)}-sanitized.{ext}", mime_type=FORMAT_MIME[fmt],
        sha256=hashlib.sha256(out).hexdigest(), method=method, removed=removed, retained=retained,
        before=before, after=after, notes=notes,
    )
