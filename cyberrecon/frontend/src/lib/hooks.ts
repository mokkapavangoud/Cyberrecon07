import { useQuery } from "@tanstack/react-query";
import { api, TERMINAL, type Mode } from "./api";

export const useConfig = () => useQuery({ queryKey: ["config"], queryFn: api.config, staleTime: 60_000, retry: 1 });
export const useHealth = () => useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 15_000, retry: false });

/** Polls once a second while the assessment is still running, so the progress shown is always the backend's real state. */
export function useAssessment(mode: Mode, id: string | undefined) {
  return useQuery({
    queryKey: ["assessment", mode, id], enabled: !!id, queryFn: () => api.getAssessment(mode, id!),
    refetchInterval: (q) => (q.state.data && !TERMINAL.includes(q.state.data.status) ? 1000 : false), retry: (n, e: any) => e?.status !== 404 && n < 2,
  });
}
export const useDashboard = (mode: Mode) => useQuery({ queryKey: ["dashboard", mode], queryFn: () => api.dashboard(mode) });
export const useAssessments = (mode: Mode, p: { module?: string; status?: string; q?: string; limit?: number; offset?: number }, enabled = true) =>
  useQuery({ queryKey: ["assessments", mode, p], enabled, queryFn: () => api.listAssessments(mode, p), refetchInterval: (q) => (q.state.data?.items.some((i) => !TERMINAL.includes(i.status)) ? 2000 : false) });
