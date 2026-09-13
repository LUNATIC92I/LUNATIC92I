import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { listAuditLog } from "@/services/auditService";
import { QueryState } from "@/components/ui/QueryState";

export default function AuditPage() {
  const [action, setAction] = useState("");
  const [selected, setSelected] = useState<Record<string, unknown> | null>(null);
  const auditQuery = useQuery({ queryKey: ["audit", action], queryFn: () => listAuditLog({ action: action || undefined }) });

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-semibold">Audit Log</h1>

      <input
        value={action}
        onChange={(e) => setAction(e.target.value)}
        placeholder="Filter by action (e.g. CREATE_ASSET)…"
        className="input w-72"
      />

      <QueryState isLoading={auditQuery.isLoading} error={auditQuery.error} isEmpty={auditQuery.data?.length === 0}>
        <div className="grid grid-cols-2 gap-4">
          <div className="card overflow-x-auto p-0 max-h-[36rem] overflow-y-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>When</th>
                  <th>Action</th>
                  <th>Object</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {auditQuery.data?.map((entry) => (
                  <tr key={entry.id} onClick={() => setSelected(entry as unknown as Record<string, unknown>)} className="cursor-pointer hover:bg-surface/60">
                    <td>{new Date(entry.occurred_at).toLocaleString()}</td>
                    <td className="font-mono text-xs">{entry.action}</td>
                    <td>{entry.object_type}</td>
                    <td className={entry.result === "success" ? "text-status-good" : "text-status-critical"}>{entry.result}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="card">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400 mb-2">Entry detail</h2>
            {selected ? (
              <pre className="text-xs overflow-x-auto whitespace-pre-wrap">{JSON.stringify(selected, null, 2)}</pre>
            ) : (
              <p className="text-sm text-slate-500">Select an entry to inspect it.</p>
            )}
          </div>
        </div>
      </QueryState>
    </div>
  );
}
