/** A ranked magnitude list — one measure across categories, so one hue
 * (no legend needed: this is not identity, it's "how much", per the
 * dataviz skill's sequential-magnitude rule). Direct labels on every row
 * since there are only ever a handful shown. */
export function RankedBarList({ items }: { items: { label: string; value: number }[] }) {
  if (items.length === 0) {
    return <p className="text-sm text-slate-500">No data yet.</p>;
  }
  const max = Math.max(...items.map((i) => i.value), 1);
  return (
    <ul className="space-y-2">
      {items.map((item) => (
        <li key={item.label} className="space-y-0.5">
          <div className="flex justify-between text-xs text-slate-300">
            <span className="truncate">{item.label}</span>
            <span className="text-slate-500">{item.value}</span>
          </div>
          <div className="h-2 w-full rounded-full bg-slate-800">
            <div className="h-2 rounded-full bg-blue-500" style={{ width: `${(item.value / max) * 100}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}
