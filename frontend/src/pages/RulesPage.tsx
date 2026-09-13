import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listRules, listRuleVersions, setRuleStatus, testRule } from "@/services/rulesService";
import { RULE_STATUSES } from "@/types/rules";
import { QueryState } from "@/components/ui/QueryState";
import { SeverityBadge } from "@/components/ui/Badge";
import { useAuth } from "@/hooks/useAuth";
import { can } from "@/types/auth";
import { ApiError } from "@/services/apiClient";

export default function RulesPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const canExecute = can(user, "rule", "execute");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [testYaml, setTestYaml] = useState("");
  const [testEventJson, setTestEventJson] = useState("{}");
  const [testResultText, setTestResultText] = useState<string | null>(null);
  const [testError, setTestError] = useState<string | null>(null);

  const rulesQuery = useQuery({ queryKey: ["rules"], queryFn: listRules });
  const versionsQuery = useQuery({
    queryKey: ["rule-versions", selectedKey],
    queryFn: () => listRuleVersions(selectedKey as string),
    enabled: !!selectedKey,
  });

  const statusMutation = useMutation({
    mutationFn: ({ ruleKey, status }: { ruleKey: string; status: string }) => setRuleStatus(ruleKey, status),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["rules"] }),
  });

  const testMutation = useMutation({
    mutationFn: () => testRule(testYaml, JSON.parse(testEventJson)),
    onSuccess: (result) => {
      setTestResultText(JSON.stringify(result, null, 2));
      setTestError(null);
    },
    onError: (err) => {
      setTestError(err instanceof ApiError ? err.message : err instanceof SyntaxError ? "Event is not valid JSON." : "Test failed.");
    },
  });

  const selectedRule = rulesQuery.data?.find((r) => r.rule_key === selectedKey);

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-semibold">Detection Rules</h1>

      <QueryState isLoading={rulesQuery.isLoading} error={rulesQuery.error} isEmpty={rulesQuery.data?.length === 0}>
        <div className="grid grid-cols-2 gap-4">
          <div className="card overflow-x-auto p-0 max-h-[36rem] overflow-y-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Severity</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {rulesQuery.data?.map((rule) => (
                  <tr
                    key={rule.rule_key}
                    onClick={() => setSelectedKey(rule.rule_key)}
                    className={`cursor-pointer hover:bg-surface/60 ${selectedKey === rule.rule_key ? "bg-surface/80" : ""}`}
                  >
                    <td>
                      <p>{rule.name}</p>
                      <p className="text-xs text-slate-500 font-mono">{rule.rule_key}</p>
                    </td>
                    <td>
                      <SeverityBadge severity={rule.severity} />
                    </td>
                    <td>
                      {canExecute ? (
                        <select
                          value={rule.status}
                          onClick={(e) => e.stopPropagation()}
                          onChange={(e) => statusMutation.mutate({ ruleKey: rule.rule_key, status: e.target.value })}
                          className="input w-28"
                        >
                          {RULE_STATUSES.map((s) => (
                            <option key={s} value={s}>
                              {s}
                            </option>
                          ))}
                        </select>
                      ) : (
                        rule.status
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="card space-y-3">
            {selectedRule ? (
              <>
                <h2 className="text-sm font-semibold">{selectedRule.name}</h2>
                <p className="text-sm text-slate-400">{selectedRule.description}</p>
                <p className="text-xs text-slate-500">MITRE: {selectedRule.mitre_techniques.join(", ") || "—"}</p>
                <p className="text-xs text-slate-500">Version {selectedRule.current_version}</p>
                <pre className="text-xs bg-surface rounded p-2 overflow-x-auto max-h-64 overflow-y-auto">{selectedRule.definition_yaml}</pre>
                <QueryState isLoading={versionsQuery.isLoading} error={versionsQuery.error} isEmpty={versionsQuery.data?.length === 0}>
                  <details>
                    <summary className="text-xs text-slate-400 cursor-pointer">Version history ({versionsQuery.data?.length ?? 0})</summary>
                    <ul className="text-xs mt-2 space-y-1">
                      {versionsQuery.data?.map((v) => (
                        <li key={v.version}>
                          v{v.version} — {v.change_summary ?? "no summary"} ({new Date(v.created_at).toLocaleString()})
                        </li>
                      ))}
                    </ul>
                  </details>
                </QueryState>
              </>
            ) : (
              <p className="text-sm text-slate-500">Select a rule to view its definition.</p>
            )}
          </div>
        </div>
      </QueryState>

      {canExecute && (
        <section className="card space-y-3">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Test a rule (dry run)</h2>
          <div className="grid grid-cols-2 gap-3">
            <textarea
              value={testYaml}
              onChange={(e) => setTestYaml(e.target.value)}
              placeholder="Rule YAML…"
              className="input h-40 font-mono text-xs"
            />
            <textarea
              value={testEventJson}
              onChange={(e) => setTestEventJson(e.target.value)}
              placeholder="Event JSON…"
              className="input h-40 font-mono text-xs"
            />
          </div>
          <button type="button" className="btn-primary" disabled={!testYaml.trim() || testMutation.isPending} onClick={() => testMutation.mutate()}>
            Run test
          </button>
          {testError && <p className="text-sm text-severity-critical">{testError}</p>}
          {testResultText && <pre className="text-xs bg-surface rounded p-2 overflow-x-auto">{testResultText}</pre>}
        </section>
      )}
    </div>
  );
}
