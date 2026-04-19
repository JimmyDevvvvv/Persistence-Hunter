// src/components/ui/StatCard.jsx
export function StatCard({ label, value, sub, accent = 'cyan', onClick }) {
    const colors = {
        cyan: 'border-cyan-500/30 text-cyan-400',
        red: 'border-red-500/30 text-red-400',
        orange: 'border-orange-500/30 text-orange-400',
        green: 'border-green-500/30 text-green-400',
        purple: 'border-purple-500/30 text-purple-400',
    }
    return (
        <div
            onClick={onClick}
            className={`corner-accent bg-bg-surface border border-bg-border rounded p-4
                  ${onClick ? 'cursor-pointer hover:border-bg-hover transition-colors' : ''}`}
        >
            <div className={`mono text-3xl font-semibold ${colors[accent]}`}>{value ?? '—'}</div>
            <div className="text-xs text-slate-400 mt-1 font-body">{label}</div>
            {sub && <div className="text-[10px] text-slate-600 mt-0.5 mono">{sub}</div>}
        </div>
    )
}