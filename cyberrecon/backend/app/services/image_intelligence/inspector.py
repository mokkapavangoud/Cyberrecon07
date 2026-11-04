"""Image validation and metadata extraction (local only; nothing is sent to third parties)."""
from __future__ import annotations

import hashlib
import io
import re
import unicodedata
import warnings
from dataclasses import dataclass
from fractions import Fraction

from PIL import ExifTags, Image, ImageCms, IptcImagePlugin

ALLOWED_FORMATS = {"JPEG", "PNG", "WEBP", "GIF", "BMP", "TIFF"}
FORMAT_MIME = {"JPEG": "image/jpeg", "PNG": "image/png", "WEBP": "image/webp", "GIF": "image/gif", "BMP": "image/bmp", "TIFF": "image/tiff"}
FORMAT_EXT = {"JPEG": "jpg", "PNG": "png", "WEBP": "webp", "GIF": "gif", "BMP": "bmp", "TIFF": "tiff"}
EXT_FORMAT = {"jpg": "JPEG", "jpeg": "JPEG", "jpe": "JPEG", "png": "PNG", "webp": "WEBP", "gif": "GIF", "bmp": "BMP", "tif": "TIFF", "tiff": "TIFF"}

_MAGIC = [
    (b"\xff\xd8\xff", "JPEG"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"BM", "BMP"),
    (b"II*\x00", "TIFF"),
    (b"MM\x00*", "TIFF"),
]

SENSITIVE_EXIF_NAMES = {
    "BodySerialNumber": "device serial number",
    "CameraOwnerName": "camera owner name",
    "LensSerialNumber": "lens serial number",
    "SerialNumber": "device serial number",
    "Artist": "author / artist name",
    "HostComputer": "host computer name",
    "ImageUniqueID": "unique image identifier",
}
IPTC_NAMES = {
    (2, 5): "object_name", (2, 25): "keywords", (2, 80): "byline", (2, 90): "city", (2, 92): "sublocation",
    (2, 95): "province_state", (2, 101): "country", (2, 105): "headline", (2, 110): "credit", (2, 115): "source",
    (2, 116): "copyright", (2, 120): "caption",
}


class ImageValidationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def safe_display_name(name: str | None, limit: int = 120) -> str:
    """Never used as a filesystem path. Strips directories, control chars and bidi-override characters."""
    name = (name or "image").replace("\\", "/").split("/")[-1]
    name = "".join(c for c in name if unicodedata.category(c) not in ("Cc", "Cf", "Cs", "Co"))
    name = name.strip().strip(".") or "image"
    return name[:limit]


def safe_stem(name: str) -> str:
    stem = re.sub(r"\.[A-Za-z0-9]{1,5}$", "", safe_display_name(name))
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._-") or "image"
    return stem[:60]


def sniff_format(data: bytes) -> str | None:
    for magic, fmt in _MAGIC:
        if data.startswith(magic):
            return fmt
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "WEBP"
    return None


@dataclass
class OpenedImage:
    image: Image.Image
    format: str
    sniffed: str


def open_validated(data: bytes, *, max_bytes: int, max_pixels: int) -> OpenedImage:
    """Inspect content (not the extension) and fully validate the image."""
    if not data:
        raise ImageValidationError("empty_file", "The uploaded file is empty.")
    if len(data) > max_bytes:
        raise ImageValidationError("file_too_large", f"The file exceeds the {max_bytes // (1024 * 1024)} MB upload limit.")
    sniffed = sniff_format(data)
    if sniffed is None:
        head = data[:512].lstrip().lower()
        if head.startswith((b"<svg", b"<?xml", b"<!doctype", b"<html")) or b"<svg" in head:
            raise ImageValidationError("unsupported_type", "SVG and other markup-based images are not accepted (script injection risk).")
        raise ImageValidationError("unsupported_type", "The file content is not a supported image (JPEG, PNG, WebP, GIF, BMP or TIFF).")
    old = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = max_pixels
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            try:
                probe = Image.open(io.BytesIO(data))
                fmt = probe.format
                if fmt not in ALLOWED_FORMATS:
                    raise ImageValidationError("unsupported_type", f"Image format {fmt} is not supported.")
                probe.verify()  # structural check; invalidates the object
                img = Image.open(io.BytesIO(data))
                img.load()  # full decode catches truncated / corrupt pixel data
            except (Image.DecompressionBombError, Image.DecompressionBombWarning):
                raise ImageValidationError("image_too_large", f"The image exceeds the {max_pixels:,} pixel limit.")
            except ImageValidationError:
                raise
            except Exception as exc:
                raise ImageValidationError("corrupt_image", f"The image could not be decoded: {type(exc).__name__}.") from exc
    finally:
        Image.MAX_IMAGE_PIXELS = old
    return OpenedImage(image=img, format=fmt, sniffed=sniffed)


# --------------------------------------------------------------------------- value helpers
def _to_float(v):
    try:
        return float(v)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _stringify(v, limit=200):
    if isinstance(v, bytes):
        txt = v.rstrip(b"\x00")
        if txt and all(32 <= b < 127 for b in txt) and len(txt) <= limit:
            return txt.decode("ascii")
        return f"<binary data, {len(v)} bytes>"
    if isinstance(v, (bool, int)):  # must precede the rational check: int also has .numerator/.denominator
        return v
    if isinstance(v, (tuple, list)):
        return [_stringify(x, limit) for x in v[:16]]
    if isinstance(v, float):
        return round(v, 6)
    if hasattr(v, "numerator") and hasattr(v, "denominator"):
        f = _to_float(v)
        return round(f, 6) if f is not None else None
    s = str(v).replace("\x00", "")
    return s[:limit]


def _dms_to_deg(dms, ref) -> float | None:
    try:
        d, m, s = (float(x) for x in dms)
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    deg = d + m / 60 + s / 3600
    if isinstance(ref, bytes):
        ref = ref.decode("ascii", "ignore")
    if str(ref).upper() in ("S", "W"):
        deg = -deg
    return round(deg, 6)


def extract_exif(img: Image.Image) -> dict:
    out = {"present": False, "camera": {}, "capture": {}, "exposure": {}, "orientation": None, "fields": {}, "sensitive": []}
    try:
        exif = img.getexif()
    except Exception:
        return out
    if not exif:
        return out
    fields: dict[str, object] = {}
    merged = dict(exif.items())
    for ifd_id in (ExifTags.IFD.Exif, ExifTags.IFD.Interop):
        try:
            merged.update(exif.get_ifd(ifd_id))
        except Exception:
            pass
    for tag_id, value in merged.items():
        name = ExifTags.TAGS.get(tag_id, f"Tag{tag_id}")
        if name in ("GPSInfo", "ExifOffset", "InteroperabilityOffset"):
            continue
        fields[name] = _stringify(value) if name != "MakerNote" else f"<binary data, {len(value) if hasattr(value, '__len__') else '?'} bytes>"
    if not fields and not _gps_ifd(exif):
        return out
    out["present"] = bool(fields) or bool(_gps_ifd(exif))
    out["fields"] = dict(list(fields.items())[:150])
    pick = lambda *names: {n: fields[n] for n in names if n in fields}  # noqa: E731
    out["camera"] = pick("Make", "Model", "LensMake", "LensModel", "Software", "BodySerialNumber", "LensSerialNumber", "CameraOwnerName", "Artist", "Copyright", "HostComputer")
    out["capture"] = pick("DateTimeOriginal", "DateTimeDigitized", "DateTime", "OffsetTime", "OffsetTimeOriginal", "SubsecTimeOriginal")
    out["exposure"] = pick("ExposureTime", "FNumber", "ISOSpeedRatings", "PhotographicSensitivity", "FocalLength", "FocalLengthIn35mmFilm", "Flash", "WhiteBalance", "ExposureProgram", "MeteringMode")
    o = fields.get("Orientation")
    out["orientation"] = o if isinstance(o, int) else None
    out["sensitive"] = [label for name, label in SENSITIVE_EXIF_NAMES.items() if name in fields]
    return out


def _gps_ifd(exif) -> dict:
    try:
        return dict(exif.get_ifd(ExifTags.IFD.GPSInfo))
    except Exception:
        return {}


def extract_gps(img: Image.Image) -> dict:
    gps = {"present": False, "latitude": None, "longitude": None, "altitude_m": None, "timestamp": None, "fields": [], "redacted": False}
    try:
        raw = _gps_ifd(img.getexif())
    except Exception:
        return gps
    if not raw:
        return gps
    named = {ExifTags.GPSTAGS.get(k, f"Tag{k}"): v for k, v in raw.items()}
    gps["present"] = True
    gps["fields"] = sorted(named.keys())[:30]
    if "GPSLatitude" in named and "GPSLongitude" in named:
        lat = _dms_to_deg(named["GPSLatitude"], named.get("GPSLatitudeRef", "N"))
        lon = _dms_to_deg(named["GPSLongitude"], named.get("GPSLongitudeRef", "E"))
        if lat is not None and lon is not None and -90 <= lat <= 90 and -180 <= lon <= 180:
            gps["latitude"], gps["longitude"] = lat, lon
    alt = _to_float(named.get("GPSAltitude"))
    if alt is not None:
        ref = named.get("GPSAltitudeRef", 0)
        gps["altitude_m"] = round(-alt if ref in (1, b"\x01") else alt, 2)
    stamp = named.get("GPSDateStamp")
    if stamp:
        gps["timestamp"] = str(stamp)[:20]
    return gps


def extract_containers(img: Image.Image, data: bytes, fmt: str) -> dict:
    info = img.info or {}
    out: dict = {}

    xmp_raw = info.get("xmp") or info.get("XML:com.adobe.xmp")
    if xmp_raw is None and fmt in ("JPEG", "PNG", "WEBP", "TIFF"):
        m = re.search(rb"<x:xmpmeta", data)
        if m:
            end = data.find(b"</x:xmpmeta>", m.start())
            xmp_raw = data[m.start(): end + 12] if end != -1 else data[m.start(): m.start() + 4096]
    if xmp_raw:
        raw = xmp_raw if isinstance(xmp_raw, bytes) else str(xmp_raw).encode("utf-8", "ignore")
        prefixes = sorted(set(re.findall(rb'xmlns:([A-Za-z0-9_]+)=', raw)))
        out["xmp"] = {"present": True, "size_bytes": len(raw), "namespaces": [p.decode("ascii", "ignore") for p in prefixes][:20]}
    else:
        out["xmp"] = {"present": False}

    iptc = {}
    try:
        iptc_raw = IptcImagePlugin.getiptcinfo(img) if fmt in ("JPEG", "TIFF") else None
    except Exception:
        iptc_raw = None
    if iptc_raw:
        for key, val in iptc_raw.items():
            name = IPTC_NAMES.get(key)
            if name:
                vals = val if isinstance(val, list) else [val]
                iptc[name] = [v.decode("utf-8", "replace")[:200] if isinstance(v, bytes) else str(v)[:200] for v in vals][:10]
        out["iptc"] = {"present": True, "record_count": len(iptc_raw), "fields": iptc}
    else:
        out["iptc"] = {"present": False}

    icc = info.get("icc_profile")
    if icc:
        desc = None
        try:
            desc = ImageCms.getProfileDescription(ImageCms.ImageCmsProfile(io.BytesIO(icc))).strip()[:120]
        except Exception:
            pass
        out["icc_profile"] = {"present": True, "size_bytes": len(icc), "description": desc}
    else:
        out["icc_profile"] = {"present": False}

    text = {}
    for k, v in (getattr(img, "text", None) or {}).items():
        if k.lower() in ("raw profile type exif", "xml:com.adobe.xmp"):
            text[k[:60]] = f"<embedded profile, {len(str(v))} chars>"
        else:
            text[k[:60]] = str(v)[:300]
    out["text_chunks"] = {"present": bool(text), "entries": dict(list(text.items())[:30])}

    comment = info.get("comment")
    if comment:
        out["comment"] = {"present": True, "value": (comment.decode("utf-8", "replace") if isinstance(comment, bytes) else str(comment))[:300]}
    else:
        out["comment"] = {"present": False}
    return out


def inspect_image(data: bytes, filename: str, *, max_bytes: int, max_pixels: int) -> dict:
    """Return a complete, JSON-serialisable analysis of an image."""
    opened = open_validated(data, max_bytes=max_bytes, max_pixels=max_pixels)
    img, fmt = opened.image, opened.format
    frames = getattr(img, "n_frames", 1)
    display = safe_display_name(filename)
    ext = display.rsplit(".", 1)[-1].lower() if "." in display else ""
    expected = EXT_FORMAT.get(ext)
    dpi = img.info.get("dpi")

    exif = extract_exif(img)
    gps = extract_gps(img)
    containers = extract_containers(img, data, fmt)

    sensitive = []
    if gps["present"]:
        sensitive.append("GPS location data")
    sensitive += [s for s in exif["sensitive"]]
    if containers["iptc"]["present"] and containers["iptc"].get("fields"):
        sensitive.append("IPTC descriptive fields (author, location, caption)")
    if containers["xmp"]["present"]:
        sensitive.append("XMP metadata block")
    if exif["capture"]:
        sensitive.append("capture date/time")
    if exif["camera"].get("Software"):
        sensitive.append("editing/camera software")
    if containers["text_chunks"]["present"]:
        sensitive.append("text chunks")
    if containers["comment"]["present"]:
        sensitive.append("embedded comment")

    any_meta = bool(exif["present"] or gps["present"] or containers["xmp"]["present"] or containers["iptc"]["present"]
                    or containers["text_chunks"]["present"] or containers["comment"]["present"])
    return {
        "file": {
            "display_name": display,
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "mime_type": FORMAT_MIME[fmt],
            "detected_format": fmt,
            "extension": ext or None,
            "extension_matches_content": (expected == fmt) if expected else None,
            "width": img.width,
            "height": img.height,
            "megapixels": round(img.width * img.height / 1_000_000, 2),
            "color_mode": img.mode,
            "frames": frames,
            "animated": frames > 1,
            "dpi": [round(float(dpi[0]), 1), round(float(dpi[1]), 1)] if isinstance(dpi, tuple) and len(dpi) == 2 else None,
        },
        "metadata": {"exif": exif, "gps": gps, **containers, "any_embedded_metadata": any_meta},
        "privacy_summary": {
            "sensitive_present": sensitive,
            "no_embedded_metadata": not any_meta,
            "notes": (
                ["No EXIF, XMP, IPTC, text or comment metadata was found. This is consistent with metadata having been removed "
                 "(many messaging apps and social platforms strip it), but it says nothing about where the image came from."]
                if not any_meta else
                ["Embedded metadata is self-reported by whatever created or edited the file. It can be edited, copied or fabricated."]
            ),
        },
    }
