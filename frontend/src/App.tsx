import { useEffect, useState } from "react";

type BackendStatus = "checking" | "online" | "offline";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

/**
 * Phase 1 placeholder. This is intentionally NOT a dashboard — no charts, no
 * mock metrics. It exists only to prove the frontend/backend/Docker wiring
 * works end to end. The real SOC screens (spec §23) are built from Phase 14
 * onward, against real APIs.
 */
export default function App() {
  const [status, setStatus] = useState<BackendStatus>("checking");

  useEffect(() => {
    fetch(`${API_BASE_URL}/health`)
      .then((res) => setStatus(res.ok ? "online" : "offline"))
      .catch(() => setStatus("offline"));
  }, []);

  return (
    <main className="min-h-screen bg-surface text-slate-100 flex items-center justify-center p-6">
      <div className="max-w-lg w-full bg-surface-raised rounded-lg border border-slate-800 p-8 space-y-4">
        <h1 className="text-2xl font-semibold tracking-tight">LUNATIC-IT SIEM</h1>
        <p className="text-slate-400">Detect. Investigate. Respond.</p>
        <div className="pt-2 border-t border-slate-800">
          <p className="text-sm text-slate-400">
            Phase 1 — repository &amp; infrastructure scaffold. No SOC features
            implemented yet; see <code>docs/DEVELOPMENT_PLAN.md</code>.
          </p>
          <p className="mt-3 text-sm">
            Backend API:{" "}
            <span
              className={
                status === "online"
                  ? "text-emerald-400"
                  : status === "offline"
                    ? "text-severity-critical"
                    : "text-slate-500"
              }
            >
              {status}
            </span>
          </p>
        </div>
      </div>
    </main>
  );
}
