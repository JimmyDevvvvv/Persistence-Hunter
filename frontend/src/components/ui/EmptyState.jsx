// src/components/ui/EmptyState.jsx
export function EmptyState({ icon = '◈', message, sub }) {
    return (
        <div className="flex flex-col items-center justify-center py-16 text-center">
            <div className="text-4xl text-slate-700 mb-3 mono">{icon}</div>
            <div className="text-slate-400 text-sm">{message}</div>
            {sub && <div className="text-slate-600 text-xs mt-1 mono">{sub}</div>}
        </div>
    )
}