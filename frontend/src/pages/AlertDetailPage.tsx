import { useState } from "react";
import { useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  addAlertNote,
  getAlert,
  getAlertEvidence,
  listAlertHistory,
  listAlertNotes,
  transitionAlert,
} from "@/services/alertsService";
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { QueryState } from "@/components/ui/QueryState";
import { ALERT_TRANSITIONS } from "@/types/alerts";
import { useAuth } from "@/hooks/useAuth";
import { can } from "@/types/auth";
import { ApiError } from "@/services/apiClient";

const CLOSING_STATUSES = new Set(["FALSE_POSITIVE", "RESOLVED", "CLOSED"]);

export default function AlertDetailPage() {
  const { alertId = "" } = useParams();
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [noteBody, setNoteBody] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);

  const alertQuery = useQuery({ queryKey: ["alert", alertId], queryFn: () => getAlert(alertId) });
  const notesQuery = useQuery({ queryKey: ["alert-notes", alertId], queryFn: () => listAlertNotes(alertId) });
  const historyQuery = useQuery({ queryKey: ["alert-history", alertId], queryFn: () => listAlertHistory(alertId) });
  const evidenceQuery = useQuery({ queryKey: ["alert-evidence", alertId], queryFn: () => getAlertEvidence(alertId) });

  const transitionMutation = useMutation({
    mutationFn: (status: string) => transitionAlert(alertId, status),
    onSuccess: () => {
      setActionError(null);
      void queryClient.invalidateQueries({ queryKey: ["alert", alertId] });
      void queryClient.invalidateQueries({ queryKey: ["alert-history", alertId] });
      void queryClient.invalidateQueries({ queryKey: ["alert-counts"] });
    },
    onError: (error) => setActionError(error instanceof ApiError ? error.message : "Transition failed."),
  });

  const noteMutation = useMutation({
    mutationFn: () => addAlertNote(alertId, noteBody),
    onSuccess: () => {
      setNoteBody("");
      void queryClient.invalidateQueries({ queryKey: ["alert-notes", alertId] });
    },
  });

  return (
    <div className="p-6 space-y-6">
      <QueryState isLoading={alertQuery.isLoading} error={alertQuery.error}>
        {alertQuery.data && (
          <>
            <div className="flex items-start justify-between">
              <div>
                <p className="text-xs text-slate-500">{alertQuery.data.display_id}</p>
                <h1 className="text-xl font-semibold">{alertQuery.data.title}</h1>
                <p className="mt-1 text-sm text-slate-400">{alertQuery.data.description}</p>
              </div>
              <div className="flex gap-2">
                <SeverityBadge severity={alertQuery.data.severity} />
                <StatusBadge status={alertQuery.data.status} />
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm">
              <Field label="Risk score" value={String(alertQuery.data.risk_score)} />
              <Field label="Confidence" value={String(alertQuery.data.confidence)} />
              <Field label="Affected user" value={alertQuery.data.affected_user ?? "—"} />
              <Field label="Affected host" value={alertQuery.data.affected_host ?? "—"} />
              <Field label="Source IP" value={alertQuery.data.source_ip ?? "—"} />
              <Field label="Destination IP" value={alertQuery.data.destination_ip ?? "—"} />
              <Field label="Occurrences" value={String(alertQuery.data.occurrence_count)} />
              <Field label="MITRE" value={alertQuery.data.mitre_techniques.join(", ") || "—"} />
            </div>

            <section className="card space-y-3">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Transition</h2>
              <div className="flex flex-wrap gap-2">
                {(ALERT_TRANSITIONS[alertQuery.data.status] ?? []).map((target) => {
                  const needsClose = CLOSING_STATUSES.has(target);
                  const allowed = needsClose ? can(user, "alert", "close") : can(user, "alert", "write");
                  return (
                    <button
                      key={target}
                      type="button"
                      disabled={!allowed || transitionMutation.isPending}
                      onClick={() => transitionMutation.mutate(target)}
                      className="btn-secondary"
                      title={allowed ? undefined : "Requires alert:close permission"}
                    >
                      → {target.replace(/_/g, " ")}
                    </button>
                  );
                })}
              </div>
              {actionError && <p className="text-sm text-severity-critical">{actionError}</p>}
            </section>

            <section className="card space-y-3">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Notes</h2>
              <QueryState isLoading={notesQuery.isLoading} error={notesQuery.error} isEmpty={notesQuery.data?.length === 0} emptyLabel="No notes yet.">
                <ul className="space-y-2">
                  {notesQuery.data?.map((note) => (
                    <li key={note.id} className="text-sm border-b border-slate-800 pb-2">
                      <p>{note.body}</p>
                      <p className="text-xs text-slate-500">{new Date(note.created_at).toLocaleString()}</p>
                    </li>
                  ))}
                </ul>
              </QueryState>
              {can(user, "alert", "write") && (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (noteBody.trim()) noteMutation.mutate();
                  }}
                  className="flex gap-2"
                >
                  <input
                    value={noteBody}
                    onChange={(e) => setNoteBody(e.target.value)}
                    placeholder="Add a note…"
                    className="input"
                  />
                  <button type="submit" className="btn-primary" disabled={noteMutation.isPending}>
                    Add
                  </button>
                </form>
              )}
            </section>

            <section className="card space-y-3">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">History</h2>
              <QueryState isLoading={historyQuery.isLoading} error={historyQuery.error} isEmpty={historyQuery.data?.length === 0}>
                <ul className="space-y-1 text-sm">
                  {historyQuery.data?.map((t, i) => (
                    <li key={i} className="text-slate-300">
                      {t.from_status ?? "—"} → {t.to_status}{" "}
                      <span className="text-slate-500">{new Date(t.occurred_at).toLocaleString()}</span>
                      {t.note && <span className="text-slate-400"> — {t.note}</span>}
                    </li>
                  ))}
                </ul>
              </QueryState>
            </section>

            <section className="card space-y-3">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
                Evidence ({evidenceQuery.data?.resolved ?? 0}/{evidenceQuery.data?.total_event_ids ?? 0})
              </h2>
              <QueryState isLoading={evidenceQuery.isLoading} error={evidenceQuery.error}>
                {evidenceQuery.data && evidenceQuery.data.missing_event_ids.length > 0 && (
                  <p className="text-xs text-severity-medium">
                    {evidenceQuery.data.missing_event_ids.length} event(s) no longer in the event store.
                  </p>
                )}
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {evidenceQuery.data?.documents.filter((d) => d.found).map((d) => (
                    <pre key={d.event_id} className="text-xs bg-surface rounded p-2 overflow-x-auto">
                      {JSON.stringify(d.document, null, 2)}
                    </pre>
                  ))}
                </div>
              </QueryState>
            </section>
          </>
        )}
      </QueryState>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className="text-slate-200">{value}</p>
    </div>
  );
}
