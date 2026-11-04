import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Trash2 } from "lucide-react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Button, ConfirmDialog, EmptyState, ErrorState, LoadingBlock } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useAssessment } from "../lib/hooks";
import { useMode } from "../lib/mode";
import { AssessmentView } from "../views/AssessmentView";

export function AssessmentPage() {
  const { id } = useParams();
  const { mode } = useMode();
  // Demo ids never exist on the live API and live ids never exist in the demo set, so the id decides where to look.
  const effective = id?.startsWith("demo-") ? "demo" : "live";
  const q = useAssessment(effective, id);
  const nav = useNavigate();
  const qc = useQueryClient();
  const del = useMutation({ mutationFn: () => api.deleteAssessment(id!), onSuccess: () => { qc.invalidateQueries({ queryKey: ["assessments"] }); qc.invalidateQueries({ queryKey: ["dashboard"] }); nav("/app/history"); } });
  if (q.isLoading) return <LoadingBlock rows={5} label="Loading the assessment" />;
  if (q.isError) {
    const e = q.error as ApiError;
    return e.status === 404 ? <EmptyState title="Assessment not found" action={<Link to="/app/history"><Button>Back to history</Button></Link>}>It may have been deleted, or the link is wrong.</EmptyState> : <ErrorState title="The assessment could not be loaded" message={e.message} onRetry={() => q.refetch()} />;
  }
  return (
    <div className="space-y-4">
      {effective === "live" && mode === "demo" && <p className="text-xs text-amber">This is a real saved assessment, shown while demo mode is on.</p>}
      <AssessmentView a={q.data!} mode={effective} />
      {effective === "live" && (
        <div className="flex justify-end border-t border-line pt-4">
          <ConfirmDialog trigger={<Button variant="danger" size="sm"><Trash2 className="size-4" />Delete this assessment</Button>} title="Delete this assessment?" confirmLabel="Delete" busy={del.isPending}
            description="The saved results, findings, reports and screenshot will be removed permanently." onConfirm={() => del.mutateAsync().then(() => undefined)} />
        </div>
      )}
    </div>
  );
}
