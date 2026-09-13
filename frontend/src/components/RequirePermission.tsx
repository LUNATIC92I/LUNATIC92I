import type { ReactNode } from "react";
import { useAuth } from "@/hooks/useAuth";
import { can } from "@/types/auth";

/**
 * Hides a screen/section the caller's role cannot use. This is UI
 * convenience only (spec §19) — every API call underneath is independently
 * re-checked server-side by `require_permission()`, so this component
 * hiding something never substitutes for that check and its absence would
 * never be a security hole, only a confusing screen.
 */
export function RequirePermission({
  resource,
  action,
  children,
}: {
  resource: string;
  action: string;
  children: ReactNode;
}) {
  const { user } = useAuth();
  if (!can(user, resource, action)) {
    return (
      <div className="p-8 text-center text-slate-400">
        <p className="text-lg font-medium text-slate-200">Access restricted</p>
        <p className="mt-2 text-sm">
          Your role does not have <code className="text-slate-300">{resource}:{action}</code>{" "}
          permission.
        </p>
      </div>
    );
  }
  return <>{children}</>;
}
