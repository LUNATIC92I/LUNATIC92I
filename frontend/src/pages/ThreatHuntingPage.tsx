import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  createSavedHunt,
  deleteSavedHunt,
  exportHunt,
  fetchHuntingFields,
  listSavedHunts,
  runPivot,
  runSavedHunt,
  searchHunt,
} from "@/services/huntingService";
import { QueryState } from "@/components/ui/QueryState";
import { HUNT_OPERATORS, PIVOT_NAMES } from "@/types/hunting";
import type { Condition, HuntQuery, HuntSearchResponse, PivotResponse } from "@/types/hunting";
import { useAuth } from "@/hooks/useAuth";
import { can } from "@/types/auth";
import { ApiError } from "@/services/apiClient";

// eslint-disable-next-line react-refresh/only-export-components -- exported for a direct unit test (ThreatHuntingPage.test.ts) rather than split into its own file for one pure function
export function pivotLabel(name: string): string {
  // "ip_to_events" -> "IP → Events". A blanket `replace(/_/g, " → ")` would
  // also turn the literal word "to" into an arrow, producing "ip → to →
  // events" — this only treats the one `_to_` separator as the arrow.
  const [from, to] = name.split("_to_");
  return `${from.toUpperCase()} → ${to.replace(/_/g, " ")}`;
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export default function ThreatHuntingPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const canExecute = can(user, "hunt", "execute");
  const canWrite = can(user, "hunt", "write");

  const [freeText, setFreeText] = useState("");
  const [useFilter, setUseFilter] = useState(false);
  const [field, setField] = useState("");
  const [operator, setOperator] = useState<string>("equals");
  const [value, setValue] = useState("");
  const [results, setResults] = useState<HuntSearchResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saveName, setSaveName] = useState("");

  const [pivotName, setPivotName] = useState<string>(PIVOT_NAMES[0]);
  const [pivotValue, setPivotValue] = useState("");
  const [pivotResult, setPivotResult] = useState<PivotResponse | null>(null);

  const fieldsQuery = useQuery({ queryKey: ["hunting-fields"], queryFn: fetchHuntingFields });
  const savedHuntsQuery = useQuery({ queryKey: ["saved-hunts"], queryFn: listSavedHunts, enabled: canWrite });

  function buildQuery(): HuntQuery {
    const query: HuntQuery = {};
    if (freeText.trim()) query.free_text = freeText.trim();
    if (useFilter && field && value) {
      const condition: Condition = { field, operator, value: operator === "exists" ? value === "true" : value };
      query.filters = condition;
    }
    return query;
  }

  const searchMutation = useMutation({
    mutationFn: () => searchHunt(buildQuery(), 100),
    onSuccess: (data) => {
      setResults(data);
      setError(null);
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : "Search failed."),
  });

  const saveMutation = useMutation({
    mutationFn: () => createSavedHunt({ name: saveName, query: buildQuery() }),
    onSuccess: () => {
      setSaveName("");
      void queryClient.invalidateQueries({ queryKey: ["saved-hunts"] });
    },
  });

  const deleteSavedMutation = useMutation({
    mutationFn: (id: string) => deleteSavedHunt(id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["saved-hunts"] }),
  });

  const runSavedMutation = useMutation({
    mutationFn: (id: string) => runSavedHunt(id),
    onSuccess: (data) => setResults(data),
  });

  const pivotMutation = useMutation({
    mutationFn: () => runPivot(pivotName, pivotValue),
    onSuccess: (data) => setPivotResult(data),
    onError: (err) => setError(err instanceof ApiError ? err.message : "Pivot failed."),
  });

  const [exporting, setExporting] = useState(false);
  async function handleExport(format: "csv" | "json") {
    setExporting(true);
    try {
      const { blob, extension } = await exportHunt(buildQuery(), format);
      downloadBlob(blob, `hunt-export.${extension}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed.");
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-semibold">Threat Hunting</h1>

      <section className="card space-y-3">
        <div className="flex flex-wrap gap-3 items-end">
          <label className="flex-1 min-w-[220px] space-y-1">
            <span className="text-xs uppercase text-slate-500">Free text</span>
            <input value={freeText} onChange={(e) => setFreeText(e.target.value)} className="input" placeholder="hostname, user, ip, hash…" />
          </label>
          <button type="button" className="btn-secondary" onClick={() => setUseFilter((v) => !v)}>
            {useFilter ? "Remove filter" : "Add structured filter"}
          </button>
        </div>

        {useFilter && (
          <div className="flex flex-wrap gap-2 items-end">
            <label className="space-y-1">
              <span className="text-xs uppercase text-slate-500">Field</span>
              <input
                list="hunting-fields"
                value={field}
                onChange={(e) => setField(e.target.value)}
                className="input w-56"
                placeholder="source_ip"
              />
              <datalist id="hunting-fields">
                {fieldsQuery.data?.fields.map((f) => (
                  <option key={f} value={f} />
                ))}
              </datalist>
            </label>
            <label className="space-y-1">
              <span className="text-xs uppercase text-slate-500">Operator</span>
              <select value={operator} onChange={(e) => setOperator(e.target.value)} className="input w-40">
                {HUNT_OPERATORS.map((op) => (
                  <option key={op} value={op}>
                    {op}
                  </option>
                ))}
              </select>
            </label>
            <label className="space-y-1">
              <span className="text-xs uppercase text-slate-500">Value</span>
              <input value={value} onChange={(e) => setValue(e.target.value)} className="input w-56" />
            </label>
          </div>
        )}

        <div className="flex flex-wrap gap-2 items-center">
          <button type="button" className="btn-primary" disabled={!canExecute || searchMutation.isPending} onClick={() => searchMutation.mutate()}>
            Search
          </button>
          {canExecute && (
            <>
              <button type="button" className="btn-secondary" disabled={exporting} onClick={() => void handleExport("csv")}>
                Export CSV
              </button>
              <button type="button" className="btn-secondary" disabled={exporting} onClick={() => void handleExport("json")}>
                Export JSON
              </button>
            </>
          )}
          {canWrite && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (saveName.trim()) saveMutation.mutate();
              }}
              className="flex gap-2 items-center ml-auto"
            >
              <input value={saveName} onChange={(e) => setSaveName(e.target.value)} placeholder="Save as…" className="input w-40" />
              <button type="submit" className="btn-secondary" disabled={saveMutation.isPending}>
                Save
              </button>
            </form>
          )}
        </div>
        {error && <p className="text-sm text-severity-critical">{error}</p>}
      </section>

      {results && (
        <section className="card space-y-2">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
            Results ({results.events.length} of {results.total})
          </h2>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {results.events.map((event, i) => (
              <pre key={i} className="text-xs bg-surface rounded p-2 overflow-x-auto">
                {JSON.stringify(event, null, 2)}
              </pre>
            ))}
          </div>
        </section>
      )}

      {canWrite && (
        <section className="card space-y-2">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Saved hunts</h2>
          <QueryState isLoading={savedHuntsQuery.isLoading} error={savedHuntsQuery.error} isEmpty={savedHuntsQuery.data?.length === 0} emptyLabel="No saved hunts yet.">
            <ul className="space-y-1 text-sm">
              {savedHuntsQuery.data?.map((hunt) => (
                <li key={hunt.id} className="flex items-center justify-between border-b border-slate-800 pb-1">
                  <span>{hunt.name}</span>
                  <span className="flex gap-2">
                    <button type="button" className="text-blue-400 hover:underline" onClick={() => runSavedMutation.mutate(hunt.id)}>
                      Run
                    </button>
                    <button type="button" className="text-severity-critical hover:underline" onClick={() => deleteSavedMutation.mutate(hunt.id)}>
                      Delete
                    </button>
                  </span>
                </li>
              ))}
            </ul>
          </QueryState>
        </section>
      )}

      {canExecute && (
        <section className="card space-y-3">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Pivots</h2>
          <div className="flex flex-wrap gap-2 items-end">
            <label className="space-y-1">
              <span className="text-xs uppercase text-slate-500">Pivot</span>
              <select value={pivotName} onChange={(e) => setPivotName(e.target.value)} className="input w-56">
                {PIVOT_NAMES.map((p) => (
                  <option key={p} value={p}>
                    {pivotLabel(p)}
                  </option>
                ))}
              </select>
            </label>
            <label className="space-y-1">
              <span className="text-xs uppercase text-slate-500">Value</span>
              <input value={pivotValue} onChange={(e) => setPivotValue(e.target.value)} className="input w-56" />
            </label>
            <button type="button" className="btn-primary" disabled={!pivotValue.trim() || pivotMutation.isPending} onClick={() => pivotMutation.mutate()}>
              Run pivot
            </button>
          </div>
          {pivotResult && (
            <div className="space-y-2 max-h-96 overflow-y-auto">
              <p className="text-xs text-slate-500">{pivotResult.total} total</p>
              {pivotResult.result_type === "values"
                ? pivotResult.values.map((v) => (
                    <p key={v.value} className="text-sm">
                      {v.value} <span className="text-slate-500">×{v.count}</span>
                    </p>
                  ))
                : pivotResult.events.map((event, i) => (
                    <pre key={i} className="text-xs bg-surface rounded p-2 overflow-x-auto">
                      {JSON.stringify(event, null, 2)}
                    </pre>
                  ))}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
