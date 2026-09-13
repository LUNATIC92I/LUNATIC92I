/** A stacked bar: covered / partial / uncovered, in that fixed order, with a
 * 2px surface gap between segments and rounded ends (dataviz skill's mark
 * spec for adjacent fills) so the boundary between statuses is never a hard
 * accidental line. Status color, never a categorical hue, since the
 * question here is "is this okay?" not "which series is this." */
export function CoverageBar({ covered, partial, total }: { covered: number; partial: number; total: number }) {
  if (total === 0) {
    return <div className="h-3 w-full rounded-full bg-slate-800" />;
  }
  const uncovered = total - covered - partial;
  const coveredPct = (covered / total) * 100;
  const partialPct = (partial / total) * 100;
  const uncoveredPct = (uncovered / total) * 100;

  return (
    <div className="flex h-3 w-full gap-0.5" role="img" aria-label={`${covered} covered, ${partial} partial, ${uncovered} uncovered of ${total}`}>
      {coveredPct > 0 && (
        <div className="h-full rounded-full bg-status-good" style={{ width: `${coveredPct}%` }} />
      )}
      {partialPct > 0 && (
        <div className="h-full rounded-full bg-status-warning" style={{ width: `${partialPct}%` }} />
      )}
      {uncoveredPct > 0 && (
        <div className="h-full rounded-full bg-slate-700" style={{ width: `${uncoveredPct}%` }} />
      )}
    </div>
  );
}

export function CoverageLegend() {
  return (
    <div className="flex items-center gap-4 text-xs text-slate-400">
      <LegendItem colorClass="bg-status-good" label="Covered" />
      <LegendItem colorClass="bg-status-warning" label="Partial" />
      <LegendItem colorClass="bg-slate-700" label="Uncovered" />
    </div>
  );
}

function LegendItem({ colorClass, label }: { colorClass: string; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className={`h-2.5 w-2.5 rounded-full ${colorClass}`} />
      {label}
    </span>
  );
}
