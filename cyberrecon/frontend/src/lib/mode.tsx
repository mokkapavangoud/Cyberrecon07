import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import type { Mode } from "./api";

interface Ctx { mode: Mode; setMode: (m: Mode) => void }
const ModeCtx = createContext<Ctx>({ mode: "live", setMode: () => {} });
const KEY = "cyberrecon.mode";

function read(): Mode {
  try { return localStorage.getItem(KEY) === "demo" ? "demo" : "live"; } catch { return "live"; }
}

export function ModeProvider({ children, initial }: { children: ReactNode; initial?: Mode }) {
  const [mode, setModeState] = useState<Mode>(initial ?? read());
  const setMode = useCallback((m: Mode) => { setModeState(m); try { localStorage.setItem(KEY, m); } catch { /* storage unavailable: mode simply isn't remembered */ } }, []);
  const value = useMemo(() => ({ mode, setMode }), [mode, setMode]);
  return <ModeCtx.Provider value={value}>{children}</ModeCtx.Provider>;
}
export const useMode = () => useContext(ModeCtx);
