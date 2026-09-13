import type { ReactNode } from "react";
import { ApiError } from "@/services/apiClient";

interface QueryStateProps {
  isLoading: boolean;
  error: unknown;
  isEmpty?: boolean;
  emptyLabel?: string;
  children: ReactNode;
}

/** Every list/detail screen goes through this so a slow backend, a 403, and
 * an empty result set each render something an analyst can act on instead
 * of a blank panel. */
export function QueryState({ isLoading, error, isEmpty, emptyLabel, children }: QueryStateProps) {
  if (isLoading) {
    return <div className="p-8 text-sm text-slate-500">Loading…</div>;
  }
  if (error) {
    const message = error instanceof ApiError ? error.message : "Something went wrong.";
    return (
      <div className="p-8 text-sm text-severity-critical">
        Failed to load: {message}
      </div>
    );
  }
  if (isEmpty) {
    return <div className="p-8 text-sm text-slate-500">{emptyLabel ?? "Nothing here yet."}</div>;
  }
  return <>{children}</>;
}
