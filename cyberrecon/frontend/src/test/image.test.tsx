import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { ImagesPage } from "../pages/ImagesPage";
import { ImageView } from "../views/ImageView";
import { baseAssessment, mockApi, renderApp } from "./utils";

const cfg = { limits: { max_upload_bytes: 1000 }, capabilities: {}, privacy: {} };
const result = (gps: object) => ({ file: { display_name: "p.jpg", size_bytes: 10, sha256: "ab", mime_type: "image/jpeg", detected_format: "JPEG", extension_matches_content: true, width: 1, height: 1, megapixels: 0, color_mode: "RGB", frames: 1 },
  metadata: { exif: { present: false }, gps, xmp: {}, iptc: {}, icc_profile: {}, text_chunks: {}, comment: {} }, privacy_summary: { sensitive_present: ["GPS location data"], notes: [] }, reverse_search: [{ name: "TinEye", url: "https://tineye.com/", note: "upload yourself" }], limitations: [] });

describe("image module", () => {
  it("rejects an oversized file in the browser before uploading", async () => {
    const m = mockApi({ "/api/config": { body: cfg } });
    renderApp(<ImagesPage />, { route: "/app/images" });
    await screen.findByText(/drop an image here/i);
    const big = new File([new Uint8Array(5000)], "big.jpg", { type: "image/jpeg" });
    await userEvent.upload(document.querySelector("input[type=file]")!, big);
    expect(await screen.findByRole("alert")).toHaveTextContent(/limit/i);
    expect(screen.getByRole("button", { name: /analyse image/i })).toBeDisabled();
    expect(m.calls.some((c) => c.init?.method === "POST")).toBe(false);
  });
  it("never shows coordinates for a stored (redacted) record, and says why", () => {
    const a = baseAssessment({ module: "image", result: result({ present: true, redacted: true }) });
    renderApp(<ImageView a={a as never} mode="live" />);
    expect(screen.getByText(/coordinates withheld/i)).toBeInTheDocument();
    expect(screen.queryByText(/openstreetmap/i)).not.toBeInTheDocument();
  });
  it("shows live coordinates only with an explicit third-party warning", () => {
    const a = baseAssessment({ module: "image", result: result({ present: false }) });
    renderApp(<ImageView a={a as never} mode="live" liveResult={result({ present: true, redacted: false, latitude: 1.5, longitude: 2.5 })} />);
    expect(screen.getByText("1.5")).toBeInTheDocument();
    expect(screen.getByText(/sends these coordinates to a third party/i)).toBeInTheDocument();
  });
  it("labels missing EXIF as missing, not as clean", () => {
    renderApp(<ImageView a={baseAssessment({ module: "image", result: result({ present: false }) }) as never} mode="live" />);
    expect(screen.getByText(/no exif data was found/i)).toBeInTheDocument();
    expect(screen.getByText(/no gps metadata is embedded/i)).toBeInTheDocument();
  });
  it("offers reverse-search links without uploading anything", async () => {
    const m = mockApi({});
    renderApp(<ImageView a={baseAssessment({ module: "image", result: result({ present: false }) }) as never} mode="live" />);
    await userEvent.click(screen.getByRole("tab", { name: /privacy/i }));
    const link = screen.getByRole("link", { name: /tineye/i });
    expect(link).toHaveAttribute("rel", expect.stringContaining("noopener"));
    expect(m.calls).toHaveLength(0);
  });
});
