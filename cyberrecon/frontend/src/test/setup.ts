import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

afterEach(() => cleanup());

// jsdom lacks these; React Flow, Recharts and layout code need them.
class RO { observe() {} unobserve() {} disconnect() {} }
(globalThis as any).ResizeObserver ??= RO;
(globalThis as any).DOMMatrixReadOnly ??= class { m22 = 1; constructor(_?: string) {} };
if (!window.matchMedia) window.matchMedia = ((q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}, onchange: null, dispatchEvent: () => false })) as any;
if (!URL.createObjectURL) { (URL as any).createObjectURL = () => "blob:test"; (URL as any).revokeObjectURL = () => {}; }
