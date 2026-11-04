import io
import struct
import zlib

import piexif
import pytest
from PIL import Image, ImageChops, ImageOps, PngImagePlugin

from app.services.common import RunContext, StepTracker
from app.services.image_intelligence import analyzer
from app.services.image_intelligence.inspector import ImageValidationError, inspect_image, safe_display_name, safe_stem
from app.services.image_intelligence.sanitizer import sanitize_image

LIMITS = dict(max_bytes=5_000_000, max_pixels=20_000_000)


def _pixels(w=64, h=48):
    img = Image.new("RGB", (w, h))
    img.putdata([(x * 4 % 256, y * 5 % 256, (x + y) % 256) for y in range(h) for x in range(w)])
    return img


def make_exif(orientation=1, gps=True):
    zeroth = {
        piexif.ImageIFD.Make: b"AcmeCam", piexif.ImageIFD.Model: b"X100", piexif.ImageIFD.Software: b"EditPro 2",
        piexif.ImageIFD.Artist: b"Jane Doe", piexif.ImageIFD.Orientation: orientation,
    }
    exif = {piexif.ExifIFD.DateTimeOriginal: b"2024:05:01 10:20:30", piexif.ExifIFD.BodySerialNumber: b"SN12345"}
    g = {}
    if gps:
        g = {
            piexif.GPSIFD.GPSLatitudeRef: b"N", piexif.GPSIFD.GPSLatitude: ((12, 1), (34, 1), (56, 1)),
            piexif.GPSIFD.GPSLongitudeRef: b"E", piexif.GPSIFD.GPSLongitude: ((77, 1), (35, 1), (0, 1)),
            piexif.GPSIFD.GPSAltitude: (9200, 10), piexif.GPSIFD.GPSAltitudeRef: 0,
        }
    return piexif.dump({"0th": zeroth, "Exif": exif, "GPS": g, "1st": {}, "thumbnail": None})


def seg(marker: int, payload: bytes) -> bytes:
    return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload


def make_jpeg(*, orientation=1, gps=True, xmp=True, comment=True, trailer=True) -> bytes:
    buf = io.BytesIO()
    _pixels().save(buf, "JPEG", quality=90, exif=make_exif(orientation, gps))
    data = buf.getvalue()
    extra = b""
    if xmp:
        extra += seg(0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + b'<x:xmpmeta xmlns:x="adobe:ns:meta/" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Jane</dc:creator></x:xmpmeta>')
    if comment:
        extra += seg(0xFE, b"hidden comment")
    data = data[:2] + extra + data[2:]
    if trailer:
        data += b"TRAILING-SECRET-DATA" * 5
    return data


def make_png(*, text=True, trailer=True) -> bytes:
    info = PngImagePlugin.PngInfo()
    if text:
        info.add_text("Author", "Jane Doe")
        info.add_itxt("Description", "secret description")
    buf = io.BytesIO()
    _pixels().save(buf, "PNG", pnginfo=info)
    return buf.getvalue() + (b"TRAILER" * 10 if trailer else b"")


def make_webp(*, lossless=True) -> bytes:
    buf = io.BytesIO()
    _pixels().save(buf, "WEBP", lossless=lossless, exif=make_exif(1, True), xmp=b'<x:xmpmeta xmlns:x="adobe:ns:meta/"></x:xmpmeta>')
    return buf.getvalue()


def make_gif(*, animated=False) -> bytes:
    buf = io.BytesIO()
    frames = [Image.new("RGB", (20, 20), c) for c in ((255, 0, 0), (0, 255, 0), (0, 0, 255))]
    if animated:
        frames[0].save(buf, "GIF", save_all=True, append_images=frames[1:], duration=50, loop=0)
    else:
        frames[0].save(buf, "GIF", comment=b"secret gif comment")
    return buf.getvalue()


def same_pixels(a: bytes, b: bytes) -> bool:
    ia, ib = Image.open(io.BytesIO(a)), Image.open(io.BytesIO(b))
    return ia.size == ib.size and ImageChops.difference(ia.convert("RGB"), ib.convert("RGB")).getbbox() is None


# ------------------------------------------------------------------ inspection
def test_jpeg_metadata_extracted_accurately():
    a = inspect_image(make_jpeg(), "holiday.jpg", **LIMITS)
    f, md = a["file"], a["metadata"]
    assert (f["detected_format"], f["mime_type"], f["width"], f["height"]) == ("JPEG", "image/jpeg", 64, 48)
    assert f["extension_matches_content"] is True
    gps = md["gps"]
    assert gps["present"] and gps["latitude"] == pytest.approx(12.582222, abs=1e-5) and gps["longitude"] == pytest.approx(77.583333, abs=1e-5)
    assert gps["altitude_m"] == 920.0
    assert md["exif"]["camera"]["Make"] == "AcmeCam" and md["exif"]["camera"]["Model"] == "X100"
    assert md["exif"]["capture"]["DateTimeOriginal"] == "2024:05:01 10:20:30"
    assert "device serial number" in a["privacy_summary"]["sensitive_present"]
    assert md["xmp"]["present"] and "dc" in md["xmp"]["namespaces"]
    assert not a["privacy_summary"]["no_embedded_metadata"]


def test_gps_is_never_invented_when_absent():
    a = inspect_image(make_jpeg(gps=False, xmp=False, comment=False), "x.jpg", **LIMITS)
    gps = a["metadata"]["gps"]
    assert gps["present"] is False and gps["latitude"] is None and gps["longitude"] is None


def test_image_without_metadata_is_labelled_not_assumed():
    buf = io.BytesIO()
    _pixels().save(buf, "PNG")
    a = inspect_image(buf.getvalue(), "plain.png", **LIMITS)
    assert a["privacy_summary"]["no_embedded_metadata"] is True
    assert "says nothing" in a["privacy_summary"]["notes"][0]


def test_png_text_chunks_detected():
    a = inspect_image(make_png(), "a.png", **LIMITS)
    assert a["metadata"]["text_chunks"]["present"]
    assert set(a["metadata"]["text_chunks"]["entries"]) == {"Author", "Description"}


def test_extension_mismatch_flagged_by_content_not_name():
    a = inspect_image(make_png(text=False), "totally-a-photo.jpg", **LIMITS)
    assert a["file"]["detected_format"] == "PNG" and a["file"]["extension_matches_content"] is False


# ------------------------------------------------------------------ upload validation
@pytest.mark.parametrize(
    "payload,code",
    [
        (b"", "empty_file"),
        (b"hello world, definitely not an image", "unsupported_type"),
        (b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "unsupported_type"),
        (b"<?xml version='1.0'?><svg/>", "unsupported_type"),
        (b"<!DOCTYPE html><html></html>", "unsupported_type"),
        (b"MZ\x90\x00this is an exe", "unsupported_type"),
        (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00truncated-garbage", "corrupt_image"),
    ],
)
def test_rejects_bad_uploads(payload, code):
    with pytest.raises(ImageValidationError) as e:
        inspect_image(payload, "evil.jpg", **LIMITS)
    assert e.value.code == code


def test_rejects_oversized_file():
    with pytest.raises(ImageValidationError) as e:
        inspect_image(make_jpeg(), "x.jpg", max_bytes=100, max_pixels=1_000_000)
    assert e.value.code == "file_too_large"


def test_rejects_decompression_bomb():
    buf = io.BytesIO()
    Image.new("1", (12_000, 12_000)).save(buf, "PNG")  # tiny file, 144 megapixels
    assert len(buf.getvalue()) < 1_000_000
    with pytest.raises(ImageValidationError) as e:
        inspect_image(buf.getvalue(), "bomb.png", max_bytes=5_000_000, max_pixels=10_000_000)
    assert e.value.code == "image_too_large"


def test_polyglot_with_wrong_extension_is_judged_by_content():
    with pytest.raises(ImageValidationError):
        inspect_image(b"<html><script>alert(1)</script></html>", "innocent.png", **LIMITS)


def test_display_names_are_safe():
    assert safe_display_name("../../etc/passwd") == "passwd"
    assert safe_display_name("C:\\Users\\me\\pic.jpg") == "pic.jpg"
    assert "\u202e" not in safe_display_name("photo\u202egpj.exe")
    assert safe_stem("../../we ird name!!.jpg") == "we_ird_name"
    assert safe_stem("....") == "image"


# ------------------------------------------------------------------ sanitisation
def test_sanitize_jpeg_is_lossless_and_removes_everything():
    original = make_jpeg()
    r = sanitize_image(original, "holiday.jpg", **LIMITS)
    assert r.method == "lossless-strip"
    assert r.filename == "holiday-sanitized.jpg"
    md = r.after["metadata"]
    assert not md["gps"]["present"] and not md["exif"]["present"] and not md["xmp"]["present"]
    assert same_pixels(original, r.data)  # decoded pixels identical -> no recompression loss
    assert b"TRAILING-SECRET" not in r.data and b"hidden comment" not in r.data and b"Jane" not in r.data and b"SN12345" not in r.data
    assert {"EXIF", "GPS location", "XMP"} <= set(r.removed)
    Image.open(io.BytesIO(r.data)).load()


def test_sanitize_preserves_visual_orientation_with_orientation_tag_only():
    original = make_jpeg(orientation=6)
    r = sanitize_image(original, "rot.jpg", **LIMITS)
    assert r.method == "lossless-strip"
    assert r.after["metadata"]["exif"]["fields"] == {"Orientation": 6}
    assert not r.after["metadata"]["gps"]["present"]
    a = ImageOps.exif_transpose(Image.open(io.BytesIO(original)))
    b = ImageOps.exif_transpose(Image.open(io.BytesIO(r.data)))
    assert a.size == b.size == (48, 64) and ImageChops.difference(a, b).getbbox() is None
    assert any("Orientation" in x for x in r.retained)


def test_sanitize_png_lossless():
    original = make_png()
    r = sanitize_image(original, "shot.png", **LIMITS)
    assert r.method == "lossless-strip"
    assert not r.after["metadata"]["text_chunks"]["present"]
    assert b"Jane Doe" not in r.data and b"TRAILER" not in r.data and b"secret description" not in r.data
    assert same_pixels(original, r.data)


def test_sanitize_webp_lossless():
    original = make_webp()
    before = inspect_image(original, "p.webp", **LIMITS)
    assert before["metadata"]["gps"]["present"] and before["metadata"]["xmp"]["present"]
    r = sanitize_image(original, "p.webp", **LIMITS)
    assert r.method == "lossless-strip"
    assert not r.after["metadata"]["gps"]["present"] and not r.after["metadata"]["xmp"]["present"]
    assert same_pixels(original, r.data)


def test_sanitize_gif_uses_reencode_and_reports_it():
    r = sanitize_image(make_gif(), "a.gif", **LIMITS)
    assert r.method == "re-encode" and not r.after["metadata"]["comment"]["present"]
    assert any("re-encoded" in n for n in r.notes)


def test_sanitize_rejects_animated():
    with pytest.raises(ImageValidationError) as e:
        sanitize_image(make_gif(animated=True), "anim.gif", **LIMITS)
    assert e.value.code == "animated_unsupported"


def test_sanitize_never_returns_unverified_output(monkeypatch):
    """If the lossless path produced something that still has metadata, fall back to re-encode."""
    from app.services.image_intelligence import sanitizer

    monkeypatch.setattr(sanitizer, "strip_jpeg", lambda data, **kw: (data, []))  # a broken stripper that strips nothing
    r = sanitize_image(make_jpeg(), "x.jpg", **LIMITS)
    assert r.method == "re-encode" and not r.after["metadata"]["gps"]["present"]


def test_sanitize_rejects_non_images():
    with pytest.raises(ImageValidationError):
        sanitize_image(b"not an image", "x.jpg", **LIMITS)


# ------------------------------------------------------------------ module (persistence privacy)
def _ctx(settings):
    t = StepTracker(analyzer.STEPS, lambda s: None)
    return RunContext("img1", settings, t, None, None), t


async def test_gps_not_persisted_by_default_but_returned_once(settings):
    ctx, _ = _ctx(settings)
    out = await analyzer.run(ctx, {"bytes": make_jpeg(), "filename": "me.jpg"})
    stored_gps = out.data["metadata"]["gps"]
    assert stored_gps["present"] and stored_gps["latitude"] is None and stored_gps["redacted"] is True
    assert "12.58" not in str(out.data) and "77.58" not in str(out.data)
    live = out.transient["metadata"]["gps"]
    assert live["latitude"] == pytest.approx(12.582222, abs=1e-5)
    assert any(f["category"] == "gps" and f["severity"] == "medium" for f in out.findings)
    assert not any("12.58" in f["detail"] for f in out.findings)


async def test_gps_persisted_when_explicitly_enabled(settings):
    settings.persist_image_gps = True
    ctx, _ = _ctx(settings)
    out = await analyzer.run(ctx, {"bytes": make_jpeg(), "filename": "me.jpg"})
    assert out.data["metadata"]["gps"]["latitude"] == pytest.approx(12.582222, abs=1e-5)


async def test_rejected_upload_is_a_failed_assessment_not_a_crash(settings):
    ctx, t = _ctx(settings)
    out = await analyzer.run(ctx, {"bytes": b"<svg onload=alert(1)>", "filename": "x.svg"})
    assert out.status == "failed" and out.data["rejected"]["code"] == "unsupported_type"
    assert {s["status"] for s in t.steps if s["key"] != "validate"} == {"skipped"}


async def test_reverse_search_links_are_plain_links_no_upload(settings):
    ctx, _ = _ctx(settings)
    out = await analyzer.run(ctx, {"bytes": make_png(), "filename": "a.png"})
    assert [r["name"] for r in out.data["reverse_search"]] == ["Google Lens", "TinEye", "Bing Visual Search", "Yandex Images"]
    assert all(r["url"].startswith("https://") and "?" not in r["url"] for r in out.data["reverse_search"])
