import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createAsset, deleteAsset, listAssets, updateAsset } from "@/services/assetsService";
import { ASSET_TYPES, CRITICALITIES } from "@/types/assets";
import { QueryState } from "@/components/ui/QueryState";
import { useAuth } from "@/hooks/useAuth";
import { can } from "@/types/auth";

const CRITICALITY_COLOR: Record<string, string> = {
  CRITICAL: "text-status-critical",
  HIGH: "text-status-serious",
  MEDIUM: "text-status-warning",
  LOW: "text-status-good",
};

export default function AssetsPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const canWrite = can(user, "asset", "write");
  const canDelete = can(user, "asset", "delete");
  const [showCreate, setShowCreate] = useState(false);
  const [hostname, setHostname] = useState("");
  const [assetType, setAssetType] = useState<string>(ASSET_TYPES[0]);
  const [criticality, setCriticality] = useState("MEDIUM");

  const assetsQuery = useQuery({ queryKey: ["assets"], queryFn: listAssets });

  const createMutation = useMutation({
    mutationFn: () => createAsset({ hostname, asset_type: assetType, criticality }),
    onSuccess: () => {
      setHostname("");
      void queryClient.invalidateQueries({ queryKey: ["assets"] });
    },
  });
  const criticalityMutation = useMutation({
    mutationFn: ({ id, value }: { id: string; value: string }) => updateAsset(id, { criticality: value }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["assets"] }),
  });
  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteAsset(id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["assets"] }),
  });

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Assets</h1>
        {canWrite && (
          <button type="button" className="btn-primary" onClick={() => setShowCreate((v) => !v)}>
            New asset
          </button>
        )}
      </div>

      {showCreate && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            createMutation.mutate();
          }}
          className="card flex flex-wrap items-end gap-3"
        >
          <label className="flex-1 min-w-[200px] space-y-1">
            <span className="text-xs uppercase text-slate-500">Hostname</span>
            <input value={hostname} onChange={(e) => setHostname(e.target.value)} className="input" />
          </label>
          <label className="space-y-1">
            <span className="text-xs uppercase text-slate-500">Type</span>
            <select value={assetType} onChange={(e) => setAssetType(e.target.value)} className="input">
              {ASSET_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t.replace(/_/g, " ")}
                </option>
              ))}
            </select>
          </label>
          <label className="space-y-1">
            <span className="text-xs uppercase text-slate-500">Criticality</span>
            <select value={criticality} onChange={(e) => setCriticality(e.target.value)} className="input">
              {CRITICALITIES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </label>
          <button type="submit" className="btn-primary" disabled={createMutation.isPending}>
            Create
          </button>
        </form>
      )}

      <QueryState isLoading={assetsQuery.isLoading} error={assetsQuery.error} isEmpty={assetsQuery.data?.length === 0} emptyLabel="No assets registered.">
        <div className="card overflow-x-auto p-0">
          <table className="table-base">
            <thead>
              <tr>
                <th>Hostname</th>
                <th>Type</th>
                <th>Criticality</th>
                <th>Owner</th>
                <th>Last seen</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {assetsQuery.data?.map((asset) => (
                <tr key={asset.id} className={asset.is_active ? "" : "opacity-50"}>
                  <td>{asset.hostname ?? asset.ip_address ?? "—"}</td>
                  <td>{asset.asset_type.replace(/_/g, " ")}</td>
                  <td>
                    {canWrite ? (
                      <select
                        value={asset.criticality}
                        onChange={(e) => criticalityMutation.mutate({ id: asset.id, value: e.target.value })}
                        className={`input w-32 ${CRITICALITY_COLOR[asset.criticality]}`}
                      >
                        {CRITICALITIES.map((c) => (
                          <option key={c} value={c}>
                            {c}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <span className={CRITICALITY_COLOR[asset.criticality]}>{asset.criticality}</span>
                    )}
                  </td>
                  <td>{asset.owner ?? "—"}</td>
                  <td>{asset.last_seen_at ? new Date(asset.last_seen_at).toLocaleString() : "—"}</td>
                  <td>
                    {canDelete && (
                      <button type="button" className="text-severity-critical hover:underline text-xs" onClick={() => deleteMutation.mutate(asset.id)}>
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
