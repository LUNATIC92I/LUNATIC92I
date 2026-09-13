import { useState, type FormEvent, type ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { ApiError } from "@/services/apiClient";

export default function LoginPage() {
  const { login, status } = useAuth();
  const [organizationSlug, setOrganizationSlug] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (status === "authenticated") {
    return <Navigate to="/" replace />;
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login({ organizationSlug, email, password, mfaCode: mfaCode || undefined });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401 && /mfa/i.test(err.message)) {
        setMfaRequired(true);
        setError("Enter your 6-digit MFA code.");
      } else if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Login failed.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="min-h-screen bg-surface text-slate-100 flex items-center justify-center p-6">
      <form
        onSubmit={(event) => void handleSubmit(event)}
        className="w-full max-w-sm space-y-4 rounded-lg border border-slate-800 bg-surface-raised p-8"
      >
        <div>
          <h1 className="text-xl font-semibold tracking-tight">LUNATIC-IT SIEM</h1>
          <p className="text-sm text-slate-400">Detect. Investigate. Respond.</p>
        </div>

        <Field label="Organization">
          <input
            required
            value={organizationSlug}
            onChange={(e) => setOrganizationSlug(e.target.value)}
            className="input"
            autoComplete="organization"
          />
        </Field>
        <Field label="Email">
          <input
            required
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="input"
            autoComplete="username"
          />
        </Field>
        <Field label="Password">
          <input
            required
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="input"
            autoComplete="current-password"
          />
        </Field>
        {mfaRequired && (
          <Field label="MFA code">
            <input
              required
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value)}
              className="input"
              maxLength={6}
              inputMode="numeric"
              autoComplete="one-time-code"
            />
          </Field>
        )}

        {error && <p className="text-sm text-severity-critical">{error}</p>}

        <button
          type="submit"
          disabled={submitting}
          className="w-full rounded bg-blue-600 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
        >
          {submitting ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </main>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block space-y-1">
      <span className="text-xs uppercase tracking-wide text-slate-400">{label}</span>
      {children}
    </label>
  );
}
