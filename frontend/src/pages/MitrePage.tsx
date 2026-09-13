import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getCoverage } from "@/services/mitreService";
import { QueryState } from "@/components/ui/QueryState";
import { CoverageBar, CoverageLegend } from "@/components/ui/CoverageBar";

const STATUS_DOT: Record<string, string> = {
  covered: "bg-status-good",
  partial: "bg-status-warning",
  uncovered: "bg-slate-700",
};

export default function MitrePage() {
  const [tacticFilter, setTacticFilter] = useState<string>("");
  const coverageQuery = useQuery({ queryKey: ["mitre-coverage"], queryFn: getCoverage });

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-semibold">MITRE ATT&amp;CK Coverage</h1>

      <QueryState isLoading={coverageQuery.isLoading} error={coverageQuery.error}>
        {coverageQuery.data && (
          <>
            {coverageQuery.data.catalog_is_stale && (
              <div className="rounded border border-status-warning/40 bg-status-warning/10 px-4 py-2 text-sm text-status-warning">
                The imported ATT&amp;CK catalog is older than the configured freshness window — coverage may not reflect the current matrix.
              </div>
            )}

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <StatTile label="Coverage rate" value={`${(coverageQuery.data.coverage_rate * 100).toFixed(1)}%`} />
              <StatTile label="Covered techniques" value={String(coverageQuery.data.covered_techniques)} />
              <StatTile label="Partially covered" value={String(coverageQuery.data.partially_covered_techniques)} />
              <StatTile label="Total techniques" value={String(coverageQuery.data.total_techniques)} />
            </div>

            <section className="card space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Coverage by tactic</h2>
                <CoverageLegend />
              </div>
              <div className="space-y-2">
                {coverageQuery.data.tactics.map((tactic) => (
                  <button
                    key={tactic.tactic_id}
                    type="button"
                    onClick={() => setTacticFilter((current) => (current === tactic.shortname ? "" : tactic.shortname))}
                    className={`w-full text-left space-y-1 rounded p-1 ${tacticFilter === tactic.shortname ? "bg-surface/80" : ""}`}
                  >
                    <div className="flex justify-between text-xs text-slate-400">
                      <span>{tactic.name}</span>
                      <span>
                        {tactic.covered + tactic.partial}/{tactic.total}
                      </span>
                    </div>
                    <CoverageBar covered={tactic.covered} partial={tactic.partial} total={tactic.total} />
                  </button>
                ))}
              </div>
            </section>

            <section className="card space-y-3">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
                Techniques {tacticFilter && `— ${tacticFilter}`}
              </h2>
              <div className="max-h-[32rem] overflow-y-auto">
                <table className="table-base">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Name</th>
                      <th>Status</th>
                      <th>Detections</th>
                    </tr>
                  </thead>
                  <tbody>
                    {coverageQuery.data.techniques
                      .filter((t) => !tacticFilter || t.tactics.includes(tacticFilter))
                      .map((t) => (
                        <tr key={t.technique_id}>
                          <td className="font-mono text-xs">{t.technique_id}</td>
                          <td>{t.name}</td>
                          <td>
                            <span className="flex items-center gap-1.5">
                              <span className={`h-2 w-2 rounded-full ${STATUS_DOT[t.status]}`} />
                              {t.status}
                            </span>
                          </td>
                          <td>{t.detection_count}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}
      </QueryState>
    </div>
  );
}

function StatTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="card">
      <p className="text-2xl font-semibold">{value}</p>
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
    </div>
  );
}
