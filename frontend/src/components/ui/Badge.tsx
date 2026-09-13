const SEVERITY_CLASSES: Record<string, string> = {
  critical: "bg-severity-critical/20 text-severity-critical border-severity-critical/40",
  high: "bg-severity-high/20 text-severity-high border-severity-high/40",
  medium: "bg-severity-medium/20 text-severity-medium border-severity-medium/40",
  low: "bg-severity-low/20 text-severity-low border-severity-low/40",
  informational: "bg-slate-500/20 text-slate-300 border-slate-500/40",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const classes = SEVERITY_CLASSES[severity.toLowerCase()] ?? "bg-slate-700/40 text-slate-300 border-slate-600";
  return (
    <span className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium uppercase tracking-wide ${classes}`}>
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className="inline-flex items-center rounded border border-slate-600 bg-slate-700/40 px-2 py-0.5 text-xs font-medium uppercase tracking-wide text-slate-200">
      {status.replace(/_/g, " ")}
    </span>
  );
}
