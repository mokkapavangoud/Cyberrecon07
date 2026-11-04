"""Module B: image analysis workspace (local, no third-party uploads)."""
from __future__ import annotations

import copy

from app.services.common import ModuleOutput, RunContext, finding, source

from .inspector import ImageValidationError, inspect_image

MODULE = "image"
STEPS = [
    ("validate", "Validate upload (content, size, pixel limits)"),
    ("metadata", "Extract metadata locally"),
    ("assess", "Assess privacy-relevant fields"),
]

REVERSE_SEARCH = [
    {"name": "Google Lens", "url": "https://lens.google.com/", "note": "Open the page and upload the image yourself."},
    {"name": "TinEye", "url": "https://tineye.com/", "note": "Open the page and upload the image yourself."},
    {"name": "Bing Visual Search", "url": "https://www.bing.com/visualsearch", "note": "Open the page and upload the image yourself."},
    {"name": "Yandex Images", "url": "https://yandex.com/images/", "note": "Open the page and upload the image yourself."},
]

LIMITATIONS = [
    "Embedded metadata is self-reported by the device or software that wrote it and can be edited, copied between files or fabricated.",
    "Metadata does not establish authenticity, authorship or the identity of any person. CyberRecon does not identify people.",
    "Missing metadata is common (messaging apps and social networks strip it) and is not evidence of anything on its own.",
    "The links below are third-party services. CyberRecon does not upload your image to them; you choose whether to.",
]


def redact_for_storage(data: dict, *, persist_gps: bool) -> dict:
    """Privacy by default: GPS coordinates are shown to the user live but not written to the database."""
    stored = copy.deepcopy(data)
    gps = stored["metadata"]["gps"]
    if gps["present"] and not persist_gps:
        for k in ("latitude", "longitude", "altitude_m"):
            gps[k] = None
        gps["redacted"] = True
    return stored


def build_findings(d: dict) -> list[dict]:
    f: list[dict] = []
    file, md = d["file"], d["metadata"]
    f.append(finding(MODULE, "file", f"{file['detected_format']} image, {file['width']}×{file['height']}px",
                     f"{file['size_bytes']:,} bytes, MIME type {file['mime_type']} (determined from file content), SHA-256 {file['sha256'][:16]}…",
                     source="Local file inspection"))
    if file["extension_matches_content"] is False:
        f.append(finding(MODULE, "file", "File extension does not match its content",
                         f"The name ends in .{file['extension']} but the content is {file['detected_format']}.", severity="low", source="Local file inspection"))
    if file["animated"]:
        f.append(finding(MODULE, "file", f"Animated image ({file['frames']} frames)", "Sanitisation is not available for animated images in this version.", source="Local file inspection"))
    gps = md["gps"]
    if gps["present"]:
        if gps.get("latitude") is not None or gps.get("redacted"):
            f.append(finding(MODULE, "gps", "GPS location embedded in metadata",
                             "The file carries GPS coordinates. Anyone who receives this file can read them. "
                             + ("Coordinates are not retained in this record." if gps.get("redacted") else ""),
                             severity="medium", source="EXIF GPS IFD"))
        else:
            f.append(finding(MODULE, "gps", "GPS block present without usable coordinates", "GPS tags exist (" + ", ".join(gps["fields"][:6]) + ") but no valid latitude/longitude.", severity="low", source="EXIF GPS IFD"))
    else:
        f.append(finding(MODULE, "gps", "No GPS metadata found", "No GPS block was present in the file.", source="EXIF"))
    ex = md["exif"]
    if ex["camera"].get("Make") or ex["camera"].get("Model"):
        f.append(finding(MODULE, "camera", "Camera information present",
                         " ".join(str(ex["camera"].get(k, "")) for k in ("Make", "Model")).strip(), source="EXIF"))
    for label in ex["sensitive"]:
        f.append(finding(MODULE, "identifiers", f"Embedded {label}", "Potentially identifying field found in EXIF.", severity="low", source="EXIF"))
    if ex["capture"].get("DateTimeOriginal"):
        f.append(finding(MODULE, "timestamps", "Capture timestamp present", f"DateTimeOriginal: {ex['capture']['DateTimeOriginal']} (self-reported, not verified).", source="EXIF"))
    if md["xmp"]["present"]:
        f.append(finding(MODULE, "xmp", "XMP metadata block present", f"{md['xmp']['size_bytes']:,} bytes; namespaces: {', '.join(md['xmp'].get('namespaces', [])[:8]) or 'n/a'}", source="XMP packet"))
    if md["iptc"]["present"]:
        f.append(finding(MODULE, "iptc", "IPTC records present", ", ".join(md["iptc"].get("fields", {}).keys()) or "unnamed records", severity="low", source="IPTC-IIM"))
    if md["text_chunks"]["present"]:
        f.append(finding(MODULE, "text", "Text chunks present", ", ".join(md["text_chunks"]["entries"].keys())[:200], source="PNG text chunks"))
    if d["privacy_summary"]["no_embedded_metadata"]:
        f.append(finding(MODULE, "metadata", "No embedded metadata found",
                         "No EXIF, XMP, IPTC, text or comment data. Consistent with stripped metadata; says nothing about origin or authenticity.", source="Local file inspection"))
    return f


async def run(ctx: RunContext, params: dict) -> ModuleOutput:
    settings, steps = ctx.settings, ctx.steps
    data, filename = params["bytes"], params.get("filename", "image")
    try:
        async with steps.step("validate"):
            analysis = inspect_image(data, filename, max_bytes=settings.max_upload_bytes, max_pixels=settings.max_image_pixels)
        async with steps.step("metadata"):
            analysis["reverse_search"] = REVERSE_SEARCH
            analysis["limitations"] = LIMITATIONS
        async with steps.step("assess"):
            pass  # findings are built from the (possibly redacted) stored form below
    except ImageValidationError as exc:
        err = {"step": "validate", "code": exc.code, "message": exc.message}
        for k in ("metadata", "assess"):
            steps.skip(k, "Upload rejected")
        return ModuleOutput(
            data={"rejected": {"code": exc.code, "message": exc.message}, "file": {"display_name": filename[:120]}},
            errors=[err], status="failed", summary={"headline": "Upload rejected", "error": exc.code},
            sources=[source("Uploaded file", "file", "failed", None, exc.message)],
            findings=[finding(MODULE, "upload", "Upload rejected", exc.message, source="Upload validation")],
        )

    stored = redact_for_storage(analysis, persist_gps=settings.persist_image_gps)
    out = ModuleOutput(
        data=stored,
        findings=build_findings(stored),
        sources=[source("Uploaded file (local analysis)", "file", "ok", None, "Analysed in memory; the image itself is not stored.")],
        summary={
            "headline": f"{analysis['file']['detected_format']} · {analysis['file']['width']}×{analysis['file']['height']} · "
                        + ("GPS present" if analysis["metadata"]["gps"]["present"] else "no GPS"),
            "gps_present": analysis["metadata"]["gps"]["present"],
            "metadata_present": analysis["metadata"]["any_embedded_metadata"],
        },
    )
    out.transient = analysis  # full (unredacted) result for the immediate response only
    return out
