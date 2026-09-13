import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { getAlertCounts, listAlerts } from "@/services/alertsService";
import { getIncidentCounts } from "@/services/incidentsService";
import { getCoverage } from "@/services/mitreService";
import { QueryState } from "@/components/ui/QueryState";
import { RankedBarList } from "@/components/ui/RankedBarList";
import { SeverityBadge } from "@/components/ui/Badge";
import { can } from "@/types/auth";
import { useAuth } from "@/hooks/useAuth";

function formatDuration(ms: number): string {
  const minutes = ms / 60_000;
  if (minutes < 60) return `${minutes.toFixed(0)}m`;
  const hours = minutes / 60;
  if (hours < 48) return `${hours.toFixed(1)}h`;
  return `${(hours / 24).toFixed(1)}d`;
}

function topN(counts: Record<string, number>, n: number) {
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([label, value]) => ({ label, value }));
}

export default function SocOverviewPage() {
  const { user } = useAuth();
  const canReadAlerts = can(user, "alert", "read");
  const canReadIncidents = can(user, "incident", "read");
  const canReadMitre = can(user, "mitre", "read");

  const alertCountsQuery = useQuery({ queryKey: ["alert-counts"], queryFn: getAlertCounts, enabled: canReadAlerts });
  // Capped at the list endpoint's max page size (500): the metrics below are
  // computed over this fetched window, not the tenant's full alert history —
  // exact for a small SOC, a documented sample for a very large one.
  const alertsQuery = useQuery({ queryKey: ["alerts", "overview"], queryFn: () => listAlerts({ limit: 500 }), enabled: canReadAlerts });
  const incidentCountsQuery = useQuery({ queryKey: ["incident-counts"], queryFn: getIncidentCounts, enabled: canReadIncidents });
  const coverageQuery = useQuery({ queryKey: ["mitre-coverage"], queryFn: getCoverage, enabled: canReadMitre });

  const metrics = useMemo(() => {
    const alerts = alertsQuery.data ?? [];
    const openAlerts = alerts.filter((a) => ["NEW", "IN_PROGRESS", "ESCALATED"].includes(a.status));
    const criticalOpen = openAlerts.filter((a) => a.severity === "critical");
    const avgRisk = openAlerts.length
      ? openAlerts.reduce((sum, a) => sum + a.risk_score, 0) / openAlerts.length
      : 0;

    const acknowledged = alerts.filter((a) => a.acknowledged_at);
    const mtta = acknowledged.length
      ? acknowledged.reduce(
          (sum, a) => sum + (new Date(a.acknowledged_at as string).getTime() - new Date(a.first_seen_at).getTime()),
          0,
        ) / acknowledged.length
      : null;

    const closed = alerts.filter((a) => a.closed_at);
    const mttr = closed.length
      ? closed.reduce(
          (sum, a) => sum + (new Date(a.closed_at as string).getTime() - new Date(a.first_seen_at).getTime()),
          0,
        ) / closed.length
      : null;

    const falsePositiveRate = closed.length
      ? (closed.filter((a) => a.status === "FALSE_POSITIVE").length / closed.length) * 100
      : null;

    const hostCounts: Record<string, number> = {};
    const userCounts: Record<string, number> = {};
    const ipCounts: Record<string, number> = {};
    for (const a of alerts) {
      if (a.affected_host) hostCounts[a.affected_host] = (hostCounts[a.affected_host] ?? 0) + 1;
      if (a.affected_user) userCounts[a.affected_user] = (userCounts[a.affected_user] ?? 0) + 1;
      if (a.source_ip) ipCounts[a.source_ip] = (ipCounts[a.source_ip] ?? 0) + 1;
    }

    return {
      openAlertsCount: openAlerts.length,
      criticalOpenCount: criticalOpen.length,
      avgRisk,
      mtta,
      mttr,
      falsePositiveRate,
      topHosts: topN(hostCounts, 5),
      topUsers: topN(userCounts, 5),
      topIps: topN(ipCounts, 5),
      recentCritical: alerts.filter((a) => a.severity === "critical" || a.severity === "high").slice(0, 5),
    };
  }, [alertsQuery.data]);

  const topTechniques = useMemo(
    () =>
      topN(
        Object.fromEntries((coverageQuery.data?.techniques ?? []).map((t) => [`${t.technique_id} ${t.name}`, t.detection_count])),
        5,
      ),
    [coverageQuery.data],
  );

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-semibold">SOC Overview</h1>

      {canReadAlerts && (
        <QueryState isLoading={alertsQuery.isLoading || alertCountsQuery.isLoading} error={alertsQuery.error || alertCountsQuery.error}>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <StatTile label="Open alerts" value={String(metrics.openAlertsCount)} />
            <StatTile label="Critical (open)" value={String(metrics.criticalOpenCount)} accent="critical" />
            {canReadIncidents && <StatTile label="Open incidents" value={String(incidentCountsQuery.data?.open_total ?? "—")} />}
            <StatTile label="Avg risk (open)" value={metrics.avgRisk.toFixed(0)} />
            <StatTile label="MTTA" value={metrics.mtta !== null ? formatDuration(metrics.mtta) : "—"} />
            <StatTile label="MTTR" value={metrics.mttr !== null ? formatDuration(metrics.mttr) : "—"} />
          </div>
        </QueryState>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {canReadAlerts && (
          <>
            <section className="card">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400 mb-2">Top affected hosts</h2>
              <RankedBarList items={metrics.topHosts} />
            </section>
            <section className="card">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400 mb-2">Top affected users</h2>
              <RankedBarList items={metrics.topUsers} />
            </section>
            <section className="card">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400 mb-2">Top source IPs</h2>
              <RankedBarList items={metrics.topIps} />
            </section>
          </>
        )}
        {canReadMitre && (
          <section className="card">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400 mb-2">
              Top MITRE techniques
              {coverageQuery.data && <span className="ml-2 text-slate-500 font-normal">({(coverageQuery.data.coverage_rate * 100).toFixed(0)}% coverage)</span>}
            </h2>
            <RankedBarList items={topTechniques} />
          </section>
        )}
        {canReadAlerts && (
          <section className="card">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400 mb-2">
              False positive rate
            </h2>
            <p className="text-2xl font-semibold">
              {metrics.falsePositiveRate !== null ? `${metrics.falsePositiveRate.toFixed(0)}%` : "—"}
            </p>
            <p className="text-xs text-slate-500">of closed alerts in the fetched window</p>
          </section>
        )}
      </div>

      {canReadAlerts && (
        <section className="card space-y-2">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Recent high-severity alerts</h2>
          <ul className="space-y-1 text-sm">
            {metrics.recentCritical.map((a) => (
              <li key={a.id} className="flex items-center gap-2">
                <a href={`/alerts/${a.id}`} className="text-blue-400 hover:underline">
                  {a.display_id}
                </a>
                <SeverityBadge severity={a.severity} />
                <span className="truncate">{a.title}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

function StatTile({ label, value, accent }: { label: string; value: string; accent?: "critical" }) {
  return (
    <div className="card">
      <p className={`text-2xl font-semibold ${accent === "critical" ? "text-status-critical" : ""}`}>{value}</p>
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
    </div>
  );
}
