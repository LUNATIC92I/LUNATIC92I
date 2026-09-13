import { useState } from "react";
import { useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  addIncidentNote,
  createIncidentTask,
  getIncident,
  getIncidentEvidence,
  listIncidentNotes,
  listIncidentTasks,
  listIncidentTimeline,
  transitionIncident,
  updateIncidentTask,
} from "@/services/incidentsService";
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { QueryState } from "@/components/ui/QueryState";
import { INCIDENT_TRANSITIONS, TASK_STATUSES } from "@/types/incidents";
import { useAuth } from "@/hooks/useAuth";
import { can } from "@/types/auth";

export default function IncidentDetailPage() {
  const { incidentId = "" } = useParams();
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [noteBody, setNoteBody] = useState("");
  const [taskTitle, setTaskTitle] = useState("");

  const incidentQuery = useQuery({ queryKey: ["incident", incidentId], queryFn: () => getIncident(incidentId) });
  const notesQuery = useQuery({ queryKey: ["incident-notes", incidentId], queryFn: () => listIncidentNotes(incidentId) });
  const tasksQuery = useQuery({ queryKey: ["incident-tasks", incidentId], queryFn: () => listIncidentTasks(incidentId) });
  const timelineQuery = useQuery({ queryKey: ["incident-timeline", incidentId], queryFn: () => listIncidentTimeline(incidentId) });
  const evidenceQuery = useQuery({ queryKey: ["incident-evidence", incidentId], queryFn: () => getIncidentEvidence(incidentId) });

  const canWrite = can(user, "incident", "write");

  const transitionMutation = useMutation({
    mutationFn: (status: string) => transitionIncident(incidentId, status),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["incident", incidentId] });
      void queryClient.invalidateQueries({ queryKey: ["incident-timeline", incidentId] });
      void queryClient.invalidateQueries({ queryKey: ["incident-counts"] });
    },
  });
  const noteMutation = useMutation({
    mutationFn: () => addIncidentNote(incidentId, noteBody),
    onSuccess: () => {
      setNoteBody("");
      void queryClient.invalidateQueries({ queryKey: ["incident-notes", incidentId] });
      void queryClient.invalidateQueries({ queryKey: ["incident-timeline", incidentId] });
    },
  });
  const taskMutation = useMutation({
    mutationFn: () => createIncidentTask(incidentId, { title: taskTitle }),
    onSuccess: () => {
      setTaskTitle("");
      void queryClient.invalidateQueries({ queryKey: ["incident-tasks", incidentId] });
    },
  });
  const taskStatusMutation = useMutation({
    mutationFn: ({ taskId, status }: { taskId: string; status: string }) => updateIncidentTask(incidentId, taskId, { status }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["incident-tasks", incidentId] }),
  });

  return (
    <div className="p-6 space-y-6">
      <QueryState isLoading={incidentQuery.isLoading} error={incidentQuery.error}>
        {incidentQuery.data && (
          <>
            <div className="flex items-start justify-between">
              <div>
                <p className="text-xs text-slate-500">{incidentQuery.data.display_id}</p>
                <h1 className="text-xl font-semibold">{incidentQuery.data.title}</h1>
                <p className="mt-1 text-sm text-slate-400">{incidentQuery.data.description}</p>
              </div>
              <div className="flex gap-2">
                <SeverityBadge severity={incidentQuery.data.severity} />
                <StatusBadge status={incidentQuery.data.status} />
              </div>
            </div>

            <section className="card space-y-3">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Workflow</h2>
              <div className="flex flex-wrap gap-2">
                {(INCIDENT_TRANSITIONS[incidentQuery.data.status] ?? []).map((target) => (
                  <button
                    key={target}
                    type="button"
                    disabled={!canWrite || transitionMutation.isPending}
                    onClick={() => transitionMutation.mutate(target)}
                    className="btn-secondary"
                  >
                    → {target}
                  </button>
                ))}
              </div>
            </section>

            <section className="card space-y-3">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Linked alerts</h2>
              <QueryState isLoading={false} error={null} isEmpty={incidentQuery.data.alerts.length === 0} emptyLabel="No alerts linked.">
                <ul className="space-y-1 text-sm">
                  {incidentQuery.data.alerts.map((a) => (
                    <li key={a.id} className="flex items-center gap-2">
                      <a href={`/alerts/${a.id}`} className="text-blue-400 hover:underline">
                        {a.display_id}
                      </a>
                      <span className="truncate">{a.title}</span>
                      <SeverityBadge severity={a.severity} />
                    </li>
                  ))}
                </ul>
              </QueryState>
            </section>

            <section className="card space-y-3">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Tasks</h2>
              <QueryState isLoading={tasksQuery.isLoading} error={tasksQuery.error} isEmpty={tasksQuery.data?.length === 0} emptyLabel="No tasks yet.">
                <ul className="space-y-2 text-sm">
                  {tasksQuery.data?.map((task) => (
                    <li key={task.id} className="flex items-center justify-between border-b border-slate-800 pb-2">
                      <span>{task.title}</span>
                      <select
                        value={task.status}
                        disabled={!canWrite}
                        onChange={(e) => taskStatusMutation.mutate({ taskId: task.id, status: e.target.value })}
                        className="input w-32"
                      >
                        {TASK_STATUSES.map((s) => (
                          <option key={s} value={s}>
                            {s.replace(/_/g, " ")}
                          </option>
                        ))}
                      </select>
                    </li>
                  ))}
                </ul>
              </QueryState>
              {canWrite && (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (taskTitle.trim()) taskMutation.mutate();
                  }}
                  className="flex gap-2"
                >
                  <input value={taskTitle} onChange={(e) => setTaskTitle(e.target.value)} placeholder="New task…" className="input" />
                  <button type="submit" className="btn-primary" disabled={taskMutation.isPending}>
                    Add
                  </button>
                </form>
              )}
            </section>

            <section className="card space-y-3">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Notes</h2>
              <QueryState isLoading={notesQuery.isLoading} error={notesQuery.error} isEmpty={notesQuery.data?.length === 0} emptyLabel="No notes yet.">
                <ul className="space-y-2 text-sm">
                  {notesQuery.data?.map((note) => (
                    <li key={note.id} className="border-b border-slate-800 pb-2">
                      <p>{note.body}</p>
                      <p className="text-xs text-slate-500">{new Date(note.created_at).toLocaleString()}</p>
                    </li>
                  ))}
                </ul>
              </QueryState>
              {canWrite && (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (noteBody.trim()) noteMutation.mutate();
                  }}
                  className="flex gap-2"
                >
                  <input value={noteBody} onChange={(e) => setNoteBody(e.target.value)} placeholder="Add a note…" className="input" />
                  <button type="submit" className="btn-primary" disabled={noteMutation.isPending}>
                    Add
                  </button>
                </form>
              )}
            </section>

            <section className="card space-y-3">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Timeline</h2>
              <QueryState isLoading={timelineQuery.isLoading} error={timelineQuery.error} isEmpty={timelineQuery.data?.length === 0}>
                <ul className="space-y-1 text-sm">
                  {timelineQuery.data?.map((entry, i) => (
                    <li key={i} className="text-slate-300">
                      <span className="text-xs text-slate-500">{new Date(entry.occurred_at).toLocaleString()}</span>{" "}
                      [{entry.kind}] {entry.summary}
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
