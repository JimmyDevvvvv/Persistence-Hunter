// src/components/ui/SeverityBadge.jsx
export function SeverityBadge({ severity, size = 'sm' }) {
    const cfg = {
        critical: { label: 'CRITICAL', cls: 'sev-critical bg-sev-critical' },
        high: { label: 'HIGH', cls: 'sev-high bg-sev-high' },
        medium: { label: 'MEDIUM', cls: 'sev-medium bg-sev-medium' },
        low: { label: 'LOW', cls: 'sev-low bg-sev-low' },
    }
    const { label, cls } = cfg[severity] || cfg.low
    const pad = size === 'xs' ? 'px-1.5 py-0.5 text-[9px]' : 'px-2 py-0.5 text-[10px]'
    return (
        <span className={`mono font-semibold tracking-widest border rounded-sm ${pad} ${cls}`}>
            {label}
        </span>
    )
}