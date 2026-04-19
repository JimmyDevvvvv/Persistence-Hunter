// src/components/features/EntryCard.jsx
import { useNavigate } from 'react-router-dom'
import { SeverityBadge } from '../ui/SeverityBadge'
import { MitreTag } from '../ui/MitreTag'

export function EntryCard({ entry }) {
    const navigate = useNavigate()
    const type = entry.entry_type
    const name = entry.name || entry.task_name || entry.service_name || '?'
    const value = entry.value_data || entry.command || entry.binary_path || ''
    const techniques = entry.techniques || []

    return (
        <div
            onClick={() => navigate(`/entries/${type}/${entry.id}`)}
            className="bg-bg-surface border border-bg-border rounded p-3
                 hover:border-bg-hover cursor-pointer transition-colors
                 hover:bg-bg-hover"
        >
            <div className="flex items-center gap-2 mb-1.5">
                <SeverityBadge severity={entry.severity} size="xs" />
                <span className="mono text-[10px] text-slate-600 uppercase">{type}</span>
                <span className="mono text-xs text-slate-300 truncate font-medium flex-1">{name}</span>
            </div>

            <div className="mono text-[10px] text-slate-500 truncate mb-2">
                {value.slice(0, 80)}
            </div>

            {techniques.length > 0 && (
                <div className="flex flex-wrap gap-1">
                    {techniques.slice(0, 4).map(t => (
                        <MitreTag key={t.id} id={t.id} name={t.name} />
                    ))}
                </div>
            )}
        </div>
    )
}