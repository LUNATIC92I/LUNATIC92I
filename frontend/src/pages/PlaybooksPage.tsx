/**
 * The playbook engine itself (spec §18: the action set, the dry-run/approval
 * state machine) is Phase 15's work and does not exist yet — there is no
 * `/playbooks` API to call. This screen says that plainly rather than
 * rendering invented playbooks or sample runs; the standing rule against
 * simulated features applies to the dashboard exactly as it does to the
 * backend.
 */
export default function PlaybooksPage() {
  return (
    <div className="p-6">
      <h1 className="text-xl font-semibold mb-4">Playbooks</h1>
      <div className="card">
        <p className="text-slate-300">Playbook execution is not available yet.</p>
        <p className="mt-2 text-sm text-slate-500">
          The SOAR playbook engine (approval workflow, dry-run/execute, action set) ships in Phase 15.
          This screen will show real, executable playbooks once that backend exists — nothing here is
          a placeholder for functionality that already works.
        </p>
      </div>
    </div>
  );
}
