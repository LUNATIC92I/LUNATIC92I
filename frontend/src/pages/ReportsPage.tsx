import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { getAlertCounts } from "@/services/alertsService";
import { getIncidentCounts } from "@/services/incidentsService";
import { getCoverage } from "@/services/mitreService";
import { listAssets } from "@/services/assetsService";
import { listIocs } from "@/services/threatIntelService";
import { QueryState } from "@/components/ui/QueryState";

/**
 * A live rollup composed from the same read APIs the other screens use —
 * there is no separate reporting backend (and none is scoped for this
 * phase), so this screen is exactly "SOC Overview's numbers, laid out for
 * printing/sharing" rather than a distinct feature with its own data.
 */
export default function ReportsPage() {
  const alertCounts = useQuery({ queryKey: ["alert-counts"], queryFn: getAlertCounts });
  const incidentCounts = useQuery({ queryKey: ["incident-counts"], queryFn: getIncidentCounts });
  const coverage = useQuery({ queryKey: ["mitre-coverage"], queryFn: getCoverage });
  const assets = useQuery({ queryKey: ["assets"], queryFn: listAssets });
  const iocs = useQuery({ queryKey: ["iocs", ""], queryFn: () => listIocs() });

  const isLoading = alertCounts.isLoading || incidentCounts.isLoading || coverage.isLoading || assets.isLoading || iocs.isLoading;
  const error = alertCounts.error || incidentCounts.error || coverage.error || assets.error || iocs.error;

  const assetsByCriticality = (assets.data ?? []).reduce<Record<string, number>>((acc, a) => {
    acc[a.criticality] = (acc[a.criticality] ?? 0) + 1;
    return acc;
  }, {});
  const iocsByClassification = (iocs.data ?? []).reduce<Record<string, number>>((acc, i) => {
    acc[i.classification] = (acc[i.classification] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">SOC Summary Report</h1>
        <button type="button" className="btn-secondary print:hidden" onClick={() => window.print()}>
          Print / Export
        </button>
      </div>

      <QueryState isLoading={isLoading} error={error}>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <ReportSection title="Alerts by status">
            <BreakdownTable rows={{ ...alertCounts.data?.by_status }} />
            <p className="text-xs text-slate-500 mt-2">{alertCounts.data?.open_total} currently open</p>
          </ReportSection>
          <ReportSection title="Incidents by status">
            <BreakdownTable rows={{ ...incidentCounts.data?.by_status }} />
            <p className="text-xs text-slate-500 mt-2">{incidentCounts.data?.open_total} currently open</p>
          </ReportSection>
          <ReportSection title="MITRE ATT&CK coverage">
            <p className="text-2xl font-semibold">{((coverage.data?.coverage_rate ?? 0) * 100).toFixed(1)}%</p>
            <p className="text-xs text-slate-500">
              {coverage.data?.covered_techniques} covered / {coverage.data?.total_techniques} total techniques
            </p>
          </ReportSection>
          <ReportSection title="Assets by criticality">
            <BreakdownTable rows={assetsByCriticality} />
          </ReportSection>
          <ReportSection title="Threat intel by classification">
            <BreakdownTable rows={iocsByClassification} />
          </ReportSection>
        </div>
      </QueryState>
    </div>
  );
}

function ReportSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="card space-y-2">
      <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">{title}</h2>
      {children}
    </section>
  );
}

function BreakdownTable({ rows }: { rows: Record<string, number> }) {
  const entries = Object.entries(rows);
  if (entries.length === 0) return <p className="text-sm text-slate-500">No data.</p>;
  return (
    <table className="table-base">
      <tbody>
        {entries.map(([label, value]) => (
          <tr key={label}>
            <td>{label.replace(/_/g, " ")}</td>
            <td className="text-right">{value}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
