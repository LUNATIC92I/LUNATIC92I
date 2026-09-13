import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { getAlertCounts, listAlerts } from "@/services/alertsService";
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { QueryState } from "@/components/ui/QueryState";
import { ALERT_STATUSES } from "@/types/alerts";

export default function AlertsPage() {
  const [status, setStatus] = useState<string>("");
  const [severity, setSeverity] = useState<string>("");

  const countsQuery = useQuery({ queryKey: ["alert-counts"], queryFn: getAlertCounts });
  const alertsQuery = useQuery({
    queryKey: ["alerts", { status, severity }],
    queryFn: () => listAlerts({ status: status || undefined, severity: severity || undefined, limit: 100 }),
  });

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Alerts</h1>
      </div>

      {countsQuery.data && (
        <div className="grid grid-cols-3 sm:grid-cols-6 gap-3">
          <SummaryTile label="Open" value={countsQuery.data.open_total} />
          {ALERT_STATUSES.map((s) => (
            <SummaryTile key={s} label={s.replace(/_/g, " ")} value={countsQuery.data.by_status[s] ?? 0} />
          ))}
        </div>
      )}

      <div className="flex gap-3">
        <select value={status} onChange={(e) => setStatus(e.target.value)} className="input w-48">
          <option value="">All statuses</option>
          {ALERT_STATUSES.map((s) => (
            <option key={s} value={s}>
              {s.replace(/_/g, " ")}
            </option>
          ))}
        </select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="input w-48">
          <option value="">All severities</option>
          {["critical", "high", "medium", "low", "informational"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>

      <QueryState
        isLoading={alertsQuery.isLoading}
        error={alertsQuery.error}
        isEmpty={alertsQuery.data?.length === 0}
        emptyLabel="No alerts match these filters."
      >
        <div className="card overflow-x-auto p-0">
          <table className="table-base">
            <thead>
              <tr>
                <th>ID</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Risk</th>
                <th>Status</th>
                <th>Occurrences</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {alertsQuery.data?.map((alert) => (
                <tr key={alert.id} className="hover:bg-surface/60">
                  <td>
                    <Link to={`/alerts/${alert.id}`} className="text-blue-400 hover:underline">
                      {alert.display_id}
                    </Link>
                  </td>
                  <td className="max-w-md truncate">{alert.title}</td>
                  <td>
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td>{alert.risk_score}</td>
                  <td>
                    <StatusBadge status={alert.status} />
                  </td>
                  <td>{alert.occurrence_count}</td>
                  <td>{new Date(alert.last_seen_at).toLocaleString()}</td>
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
