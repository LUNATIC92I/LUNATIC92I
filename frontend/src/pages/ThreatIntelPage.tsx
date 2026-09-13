import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createIoc, deleteIoc, listIocs } from "@/services/threatIntelService";
import { CLASSIFICATIONS, IOC_TYPES } from "@/types/threatIntel";
import { QueryState } from "@/components/ui/QueryState";
import { useAuth } from "@/hooks/useAuth";
import { can } from "@/types/auth";
import { ApiError } from "@/services/apiClient";

const CLASSIFICATION_COLOR: Record<string, string> = {
  malicious: "text-status-critical",
  suspicious: "text-status-warning",
  benign: "text-status-good",
  unknown: "text-slate-400",
};

export default function ThreatIntelPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const canWrite = can(user, "ioc", "write");
  const [typeFilter, setTypeFilter] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [value, setValue] = useState("");
  const [classification, setClassification] = useState("unknown");
  const [source, setSource] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);

  const iocsQuery = useQuery({
    queryKey: ["iocs", typeFilter],
    queryFn: () => listIocs({ ioc_type: typeFilter || undefined }),
  });

  const createMutation = useMutation({
    mutationFn: () => createIoc({ value, classification, confidence: 50, source }),
    onSuccess: () => {
      setValue("");
      setSource("");
      setCreateError(null);
      void queryClient.invalidateQueries({ queryKey: ["iocs"] });
    },
    onError: (err) => setCreateError(err instanceof ApiError ? err.message : "Failed to create indicator."),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteIoc(id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["iocs"] }),
  });

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Threat Intelligence</h1>
        {canWrite && (
          <button type="button" className="btn-primary" onClick={() => setShowCreate((v) => !v)}>
            Add indicator
          </button>
        )}
      </div>

      {showCreate && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (value.trim() && source.trim()) createMutation.mutate();
          }}
          className="card flex flex-wrap items-end gap-3"
        >
          <label className="flex-1 min-w-[200px] space-y-1">
            <span className="text-xs uppercase text-slate-500">Value</span>
            <input value={value} onChange={(e) => setValue(e.target.value)} className="input" required />
          </label>
          <label className="space-y-1">
            <span className="text-xs uppercase text-slate-500">Classification</span>
            <select value={classification} onChange={(e) => setClassification(e.target.value)} className="input">
              {CLASSIFICATIONS.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </label>
          <label className="space-y-1">
            <span className="text-xs uppercase text-slate-500">Source</span>
            <input value={source} onChange={(e) => setSource(e.target.value)} className="input" required />
          </label>
          <button type="submit" className="btn-primary" disabled={createMutation.isPending}>
            Add
          </button>
          {createError && <p className="text-sm text-severity-critical w-full">{createError}</p>}
        </form>
      )}

      <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} className="input w-48">
        <option value="">All types</option>
        {IOC_TYPES.map((t) => (
          <option key={t} value={t}>
            {t}
          </option>
        ))}
      </select>

      <QueryState isLoading={iocsQuery.isLoading} error={iocsQuery.error} isEmpty={iocsQuery.data?.length === 0} emptyLabel="No indicators.">
        <div className="card overflow-x-auto p-0">
          <table className="table-base">
            <thead>
              <tr>
                <th>Value</th>
                <th>Type</th>
                <th>Classification</th>
                <th>Confidence</th>
                <th>Source</th>
                <th>Last seen</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {iocsQuery.data?.map((ioc) => (
                <tr key={ioc.id} className={ioc.is_expired ? "opacity-50" : ""}>
                  <td className="font-mono text-xs">{ioc.value}</td>
                  <td>{ioc.ioc_type}</td>
                  <td className={CLASSIFICATION_COLOR[ioc.classification]}>{ioc.classification}</td>
                  <td>{ioc.confidence}</td>
                  <td>{ioc.source}{ioc.shared && <span className="ml-1 text-xs text-slate-500">(shared)</span>}</td>
                  <td>{new Date(ioc.last_seen).toLocaleString()}</td>
                  <td>
                    {canWrite && !ioc.shared && (
                      <button type="button" className="text-severity-critical hover:underline text-xs" onClick={() => deleteMutation.mutate(ioc.id)}>
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </QueryState>
    </div>
  );
}
