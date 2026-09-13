import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { createIncident, getIncidentCounts, listIncidents } from "@/services/incidentsService";
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { QueryState } from "@/components/ui/QueryState";
import { INCIDENT_SEVERITIES, INCIDENT_STATUSES } from "@/types/incidents";
import { useAuth } from "@/hooks/useAuth";
import { can } from "@/types/auth";

export default function IncidentsPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [status, setStatus] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("medium");

  const countsQuery = useQuery({ queryKey: ["incident-counts"], queryFn: getIncidentCounts });
  const incidentsQuery = useQuery({
    queryKey: ["incidents", { status }],
    queryFn: () => listIncidents({ status: status || undefined, limit: 100 }),
  });

  const createMutation = useMutation({
    mutationFn: () => createIncident({ title, severity }),
    onSuccess: (incident) => {
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["incident-counts"] });
      navigate(`/incidents/${incident.id}`);
    },
  });

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Incidents</h1>
        {can(user, "incident", "write") && (
          <button type="button" className="btn-primary" onClick={() => setShowCreate((v) => !v)}>
            New incident
          </button>
        )}
      </div>

      {showCreate && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (title.trim()) createMutation.mutate();
          }}
          className="card flex flex-wrap items-end gap-3"
        >
          <label className="flex-1 min-w-[200px] space-y-1">
            <span className="text-xs uppercase text-slate-500">Title</span>
            <input value={title} onChange={(e) => setTitle(e.target.value)} className="input" required />
          </label>
          <label className="space-y-1">
            <span className="text-xs uppercase text-slate-500">Severity</span>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="input">
              {INCIDENT_SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <button type="submit" className="btn-primary" disabled={createMutation.isPending}>
            Create
          </button>
        </form>
      )}

      {countsQuery.data && (
        <div className="grid grid-cols-4 sm:grid-cols-7 gap-3">
          <SummaryTile label="Open" value={countsQuery.data.open_total} />
          {INCIDENT_STATUSES.map((s) => (
            <SummaryTile key={s} label={s} value={countsQuery.data.by_status[s] ?? 0} />
          ))}
        </div>
      )}

      <select value={status} onChange={(e) => setStatus(e.target.value)} className="input w-48">
        <option value="">All statuses</option>
        {INCIDENT_STATUSES.map((s) => (
          <option key={s} value={s}>
            {s}
          </option>
        ))}
      </select>

      <QueryState
        isLoading={incidentsQuery.isLoading}
        error={incidentsQuery.error}
        isEmpty={incidentsQuery.data?.length === 0}
        emptyLabel="No incidents match these filters."
      >
        <div className="card overflow-x-auto p-0">
          <table className="table-base">
            <thead>
              <tr>
                <th>ID</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Priority</th>
                <th>Status</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {incidentsQuery.data?.map((incident) => (
                <tr key={incident.id} className="hover:bg-surface/60">
                  <td>
                    <Link to={`/incidents/${incident.id}`} className="text-blue-400 hover:underline">
                      {incident.display_id}
                    </Link>
                  </td>
                  <td className="max-w-md truncate">{incident.title}</td>
                  <td>
                    <SeverityBadge severity={incident.severity} />
                  </td>
                  <td>{incident.priority}</td>
                  <td>
                    <StatusBadge status={incident.status} />
                  </td>
                  <td>{new Date(incident.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </QueryState>
    </div>
  );
}

function SummaryTile({ label, value }: { label: string; value: number }) {
  return (
    <div className="card">
      <p className="text-2xl font-semibold">{value}</p>
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
    </div>
  );
}
