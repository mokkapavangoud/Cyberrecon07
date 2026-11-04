import { lazy, Suspense } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Shell } from "./components/Shell";
import { ModeProvider } from "./lib/mode";
import { AssessmentPage } from "./pages/AssessmentPage";
const Dashboard = lazy(() => import("./pages/Dashboard").then((m) => ({ default: m.Dashboard })));
import { History } from "./pages/History";
import { ImagesPage } from "./pages/ImagesPage";
import { Landing } from "./pages/Landing";
import { ModulePage } from "./pages/ModulePage";
import { NotFound } from "./pages/NotFound";
import { Present } from "./pages/Present";
import { Reports } from "./pages/Reports";
import { SettingsPage } from "./pages/Settings";

export const makeClient = () => new QueryClient({ defaultOptions: { queries: { refetchOnWindowFocus: false, staleTime: 5_000, retry: 1 } } });

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/present" element={<Present />} />
      <Route path="/app" element={<Shell />}>
        <Route index element={<Suspense fallback={<div className="skeleton h-40" />}><Dashboard /></Suspense>} />
        <Route path="website" element={<ModulePage module="link" />} />
        <Route path="infrastructure" element={<ModulePage module="infrastructure" />} />
        <Route path="screenshots" element={<ModulePage module="screenshot" />} />
        <Route path="images" element={<ImagesPage />} />
        <Route path="history" element={<History />} />
        <Route path="assessments/:id" element={<AssessmentPage />} />
        <Route path="reports" element={<Reports />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFound />} />
      </Route>
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={makeClient()}>
      <ModeProvider>
        <BrowserRouter><AppRoutes /></BrowserRouter>
      </ModeProvider>
    </QueryClientProvider>
  );
}
