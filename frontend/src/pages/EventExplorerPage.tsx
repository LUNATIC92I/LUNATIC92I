import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { searchHunt } from "@/services/huntingService";
import type { HuntSearchResponse } from "@/types/hunting";
import { ApiError } from "@/services/apiClient";

/**
 * A plain browse-and-inspect view over the same POST /hunting/search
 * Threat Hunting uses — this screen intentionally has no structured
 * filters, pivots, saved hunts or export; it exists for "just show me
 * recent events matching this text" rather than a hunt investigation.
 */
export default function EventExplorerPage() {
  const [freeText, setFreeText] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [selected, setSelected] = useState<Record<string, unknown> | null>(null);
  const [results, setResults] = useState<HuntSearchResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const searchMutation = useMutation({
    mutationFn: () =>
      searchHunt(
        {
          free_text: freeText.trim() || undefined,
          since: since ? new Date(since).toISOString() : undefined,
          until: until ? new Date(until).toISOString() : undefined,
        },
        200,
      ),
    onSuccess: (data) => {
      setResults(data);
      setError(null);
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : "Search failed."),
  });

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-semibold">Event Explorer</h1>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (freeText.trim() || since || until) searchMutation.mutate();
        }}
        className="card flex flex-wrap items-end gap-3"
      >
        <label className="flex-1 min-w-[220px] space-y-1">
          <span className="text-xs uppercase text-slate-500">Search</span>
          <input value={freeText} onChange={(e) => setFreeText(e.target.value)} className="input" placeholder="hostname, user, ip, hash…" />
        </label>
        <label className="space-y-1">
          <span className="text-xs uppercase text-slate-500">Since</span>
          <input type="datetime-local" value={since} onChange={(e) => setSince(e.target.value)} className="input" />
        </label>
        <label className="space-y-1">
          <span className="text-xs uppercase text-slate-500">Until</span>
          <input type="datetime-local" value={until} onChange={(e) => setUntil(e.target.value)} className="input" />
        </label>
        <button type="submit" className="btn-primary" disabled={searchMutation.isPending}>
          Search
        </button>
      </form>
      {error && <p className="text-sm text-severity-critical">{error}</p>}

      {results && (
        <div className="grid grid-cols-2 gap-4">
          <div className="card overflow-x-auto p-0">
            <p className="p-2 text-xs text-slate-500">{results.events.length} of {results.total} events</p>
            <table className="table-base">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Class</th>
                  <th>Severity</th>
                  <th>Hostname</th>
                </tr>
              </thead>
              <tbody>
                {results.events.map((event, i) => (
                  <tr key={i} onClick={() => setSelected(event)} className="cursor-pointer hover:bg-surface/60">
                    <td>{String(event.timestamp ?? "")}</td>
                    <td>{String(event.class ?? "")}</td>
                    <td>{String(event.severity ?? "")}</td>
                    <td>{String(event.hostname ?? "")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="card">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400 mb-2">Event detail</h2>
            {selected ? (
              <pre className="text-xs overflow-x-auto whitespace-pre-wrap">{JSON.stringify(selected, null, 2)}</pre>
            ) : (
              <p className="text-sm text-slate-500">Select an event to inspect it.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
