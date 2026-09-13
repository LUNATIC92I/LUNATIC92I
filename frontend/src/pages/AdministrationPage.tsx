import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getMyOrganization } from "@/services/organizationsService";
import { createUser, listRoleCatalog, listUsers, updateUser } from "@/services/usersService";
import { QueryState } from "@/components/ui/QueryState";
import { RequirePermission } from "@/components/RequirePermission";
import { useAuth } from "@/hooks/useAuth";
import { can } from "@/types/auth";
import { ApiError } from "@/services/apiClient";

export default function AdministrationPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const canManageUsers = can(user, "user", "write");

  const orgQuery = useQuery({ queryKey: ["organization"], queryFn: getMyOrganization });
  const usersQuery = useQuery({ queryKey: ["users"], queryFn: listUsers });
  const rolesQuery = useQuery({ queryKey: ["role-catalog"], queryFn: listRoleCatalog, enabled: canManageUsers });

  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);

  const createMutation = useMutation({
    mutationFn: () => createUser({ email, full_name: fullName, password, role }),
    onSuccess: () => {
      setEmail("");
      setFullName("");
      setPassword("");
      setCreateError(null);
      void queryClient.invalidateQueries({ queryKey: ["users"] });
    },
    onError: (err) => setCreateError(err instanceof ApiError ? err.message : "Failed to create user."),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: { is_active?: boolean; role?: string } }) =>
      updateUser(id, payload),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["users"] }),
  });

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-semibold">Administration</h1>

      <RequirePermission resource="organization" action="read">
        <section className="card space-y-1">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Organization</h2>
          <QueryState isLoading={orgQuery.isLoading} error={orgQuery.error}>
            {orgQuery.data && (
              <div className="text-sm">
                <p>{orgQuery.data.name}</p>
                <p className="text-slate-500">/{orgQuery.data.slug}</p>
              </div>
            )}
          </QueryState>
        </section>
      </RequirePermission>

      <section className="card space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">User management</h2>

        {canManageUsers && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (email.trim() && fullName.trim() && password && role) createMutation.mutate();
            }}
            className="flex flex-wrap items-end gap-3"
          >
            <label className="space-y-1">
              <span className="text-xs uppercase text-slate-500">Email</span>
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="input" required />
            </label>
            <label className="space-y-1">
              <span className="text-xs uppercase text-slate-500">Full name</span>
              <input value={fullName} onChange={(e) => setFullName(e.target.value)} className="input" required />
            </label>
            <label className="space-y-1">
              <span className="text-xs uppercase text-slate-500">Temporary password</span>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="input" required minLength={12} />
            </label>
            <label className="space-y-1">
              <span className="text-xs uppercase text-slate-500">Role</span>
              <select value={role} onChange={(e) => setRole(e.target.value)} className="input" required>
                <option value="" disabled>
                  Select…
                </option>
                {rolesQuery.data?.roles.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </label>
            <button type="submit" className="btn-primary" disabled={createMutation.isPending}>
              Create user
            </button>
            {createError && <p className="text-sm text-severity-critical w-full">{createError}</p>}
          </form>
        )}

        <QueryState isLoading={usersQuery.isLoading} error={usersQuery.error} isEmpty={usersQuery.data?.length === 0}>
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Active</th>
                </tr>
              </thead>
              <tbody>
                {usersQuery.data?.map((u) => (
                  <tr key={u.id}>
                    <td>{u.full_name}</td>
                    <td>{u.email}</td>
                    <td>
                      {canManageUsers ? (
                        <select
                          value={u.roles[0] ?? ""}
                          onChange={(e) => updateMutation.mutate({ id: u.id, payload: { role: e.target.value } })}
                          className="input w-48"
                        >
                          {rolesQuery.data?.roles.map((r) => (
                            <option key={r} value={r}>
                              {r}
                            </option>
                          ))}
                        </select>
                      ) : (
                        u.roles.join(", ")
                      )}
                    </td>
                    <td>
                      {canManageUsers ? (
                        <button
                          type="button"
                          className="btn-secondary"
                          onClick={() => updateMutation.mutate({ id: u.id, payload: { is_active: !u.is_active } })}
                        >
                          {u.is_active ? "Deactivate" : "Reactivate"}
                        </button>
                      ) : u.is_active ? (
                        "Active"
                      ) : (
                        "Inactive"
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </QueryState>
      </section>
    </div>
  );
}
