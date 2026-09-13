import { useQuery } from "@tanstack/react-query";
import { listUsers } from "@/services/usersService";
import { QueryState } from "@/components/ui/QueryState";

export default function UsersPage() {
  const usersQuery = useQuery({ queryKey: ["users"], queryFn: listUsers });

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-semibold">Users</h1>
      <p className="text-sm text-slate-400">
        Creating accounts and changing roles happens on the Administration screen.
      </p>

      <QueryState isLoading={usersQuery.isLoading} error={usersQuery.error} isEmpty={usersQuery.data?.length === 0}>
        <div className="card overflow-x-auto p-0">
          <table className="table-base">
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Roles</th>
                <th>MFA</th>
                <th>Active</th>
              </tr>
            </thead>
            <tbody>
              {usersQuery.data?.map((user) => (
                <tr key={user.id} className={user.is_active ? "" : "opacity-50"}>
                  <td>{user.full_name}</td>
                  <td>{user.email}</td>
                  <td>{user.roles.join(", ")}</td>
                  <td>{user.mfa_enabled ? "Enabled" : "—"}</td>
                  <td>{user.is_active ? "Active" : "Inactive"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </QueryState>
    </div>
  );
}
