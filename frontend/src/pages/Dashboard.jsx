// src/pages/Dashboard.jsx
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { fetchStats, fetchAlerts } from '../api/client'

const SEV_COLORS = {
    critical: 'var(--red)',
    high: 'var(--orange)',
    medium: 'var(--yellow)',
    low: 'var(--green)',
}

function StatBox({ label, value, accent, sub, onClick }) {
    return (
        <div
            onClick={onClick}
            className={`stat-card accent-${accent}`}
            style={{ cursor: onClick ? 'pointer' : 'default' }}
        >
            <div className="font-display text-4xl font-bold mb-1"
                style={{ color: `var(--${accent === 'orange' ? 'orange' : accent})` }}>
                {value ?? '—'}
            </div>
            <div className="text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
                {label}
            </div>
            {sub && (
                <div className="font-mono text-[10px] mt-1" style={{ color: 'var(--text-muted)' }}>
                    {sub}
                </div>
            )}
        </div>
    )
}

function AlertRow({ alert, index, last }) {
    const navigate = useNavigate()
    const name = alert.name || alert.task_name || alert.service_name || '?'
    const value = alert.value_data || alert.command || alert.binary_path || ''
    const sevColor = SEV_COLORS[alert.severity] || 'var(--text-muted)'

    return (
        <div
            onClick={() => navigate(`/entries/${alert.entry_type}/${alert.id}`)}
            className={`flex items-center gap-4 px-5 py-2.5 cursor-pointer transition-all stagger-${Math.min(index + 1, 5)}`}
            style={{ borderBottom: !last ? '1px solid var(--bg-border)' : 'none' }}
            onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
        >
            {/* Severity dot */}
            <div className="w-2 h-2 rounded-full shrink-0"
                style={{ background: sevColor, boxShadow: `0 0 6px ${sevColor}` }} />

            {/* Type badge */}
            <span className="font-mono text-[9px] uppercase px-1.5 py-0.5 rounded shrink-0"
                style={{ background: 'var(--bg-raised)', color: 'var(--text-muted)', border: '1px solid var(--bg-border)', minWidth: 52, textAlign: 'center' }}>
                {alert.entry_type}
            </span>

            {/* Name */}
            <span className="font-mono text-xs font-medium flex-shrink-0 w-44 truncate"
                style={{ color: 'var(--text-primary)' }}>
                {name}
            </span>

            {/* Value */}
            <span className="font-mono text-[10px] truncate flex-1"
                style={{ color: 'var(--text-muted)' }}>
                {value.slice(0, 80)}
            </span>

            {/* Severity label */}
            <span className={`badge-${alert.severity} font-mono text-[9px] px-2 py-0.5 rounded uppercase font-semibold tracking-wider shrink-0`}>
                {alert.severity}
            </span>
        </div>
    )
}

export function Dashboard() {
    const navigate = useNavigate()
    const { data: stats, isLoading } = useQuery({
        queryKey: ['stats'],
        queryFn: fetchStats,
        refetchInterval: 30000,
    })
    const { data: alertsData } = useQuery({
        queryKey: ['alerts-dash'],
        queryFn: () => fetchAlerts(8),
        refetchInterval: 30000,
    })

    if (isLoading) return (
        <div className="flex items-center justify-center h-64 gap-3">
            <div className="w-5 h-5 border-2 rounded-full animate-spin"
                style={{ borderColor: 'var(--bg-border)', borderTopColor: 'var(--cyan)' }} />
            <span className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>Loading...</span>
        </div>
    )

    const s   = stats || {}
    const tot = s.totals || {}
    const el  = s.event_log || {}
    const enr = s.enrichment || {}

    const alerts = alertsData?.alerts || []

    return (
        <div className="space-y-6 animate-slide-up">

            {/* ── Page header ── */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="font-display text-3xl font-bold gradient-text"
                        style={{ letterSpacing: '0.04em' }}>
                        Overview
                    </h1>
                    <p className="font-mono text-[11px] mt-1" style={{ color: 'var(--text-muted)' }}>
                        {new Date().toLocaleString()} · reghunt.db
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    {/* System health indicator */}
                    <div style={{
                        display: 'flex', alignItems: 'center', gap: 8,
                        background: 'rgba(0,229,153,0.07)',
                        border: '1px solid rgba(0,229,153,0.2)',
                        borderRadius: 8, padding: '6px 12px',
                    }}>
                        <div className="w-1.5 h-1.5 rounded-full animate-pulse"
                            style={{ background: 'var(--green)', boxShadow: '0 0 8px var(--green)' }} />
                        <span className="font-mono text-[10px] uppercase tracking-widest"
                            style={{ color: 'var(--green)' }}>
                            Systems Nominal
                        </span>
                    </div>
                </div>
            </div>

            {/* ── Threat stats row ── */}
            <div className="stagger-1">
                <div className="font-mono text-[10px] uppercase tracking-widest mb-3"
                    style={{ color: 'var(--text-muted)' }}>
                    Threat Overview
                </div>
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                    <StatBox label="Critical Findings"  value={tot.critical ?? 0}                          accent="red"    onClick={() => navigate('/alerts')} />
                    <StatBox label="High Severity"       value={tot.high ?? 0}                              accent="orange" onClick={() => navigate('/alerts')} />
                    <StatBox label="Registry Entries"    value={tot.registry ?? 0}                          accent="cyan"   onClick={() => navigate('/entries?type=registry')} />
                    <StatBox label="Tasks + Services"    value={(tot.tasks ?? 0) + (tot.services ?? 0)}     accent="purple" onClick={() => navigate('/entries')} />
                </div>
            </div>

            {/* ── Telemetry stats row ── */}
            <div className="stagger-2">
                <div className="font-mono text-[10px] uppercase tracking-widest mb-3"
                    style={{ color: 'var(--text-muted)' }}>
                    Telemetry & Enrichment
                </div>
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                    <StatBox label="Sysmon Events"    value={el.sysmon_events?.toLocaleString() ?? 0}  accent="green"  sub="Event ID 1 + 13" />
                    <StatBox label="Process Events"   value={el.process_events?.toLocaleString() ?? 0} accent="green"  sub="Event ID 4688" />
                    <StatBox label="Attack Chains"    value={enr.chains_built ?? 0}                    accent="cyan"   sub="Process chains built" />
                    <StatBox label="Enriched Entries" value={enr.enriched_entries ?? 0}                accent="purple" sub="File + threat intel" />
                </div>
            </div>

            {/* ── Recent alerts table ── */}
            <div className="panel animate-slide-up stagger-3">
                <div className="panel-header">
                    <div className="flex items-center gap-3">
                        <div className="w-2 h-2 rounded-full" style={{ background: 'var(--red)', boxShadow: '0 0 6px var(--red)' }} />
                        <span className="panel-label">Recent Alerts</span>
                        {alerts.length > 0 && (
                            <span className="font-mono text-[9px] px-1.5 py-0.5 rounded"
                                style={{ background: 'rgba(255,53,96,0.1)', color: 'var(--red)', border: '1px solid rgba(255,53,96,0.25)' }}>
                                {alerts.length}
                            </span>
                        )}
                    </div>
                    <button
                        onClick={() => navigate('/alerts')}
                        className="font-mono text-[10px] transition-all hover:opacity-80 flex items-center gap-1"
                        style={{ color: 'var(--cyan)' }}
                    >
                        View all
                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                            <path d="M5 12h14M12 5l7 7-7 7" />
                        </svg>
                    </button>
                </div>

                <div>
                    {alerts.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-12 gap-3"
                            style={{ color: 'var(--text-muted)' }}>
                            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" opacity="0.3">
                                <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
                            </svg>
                            <span className="font-mono text-xs">No recent alerts</span>
                        </div>
                    ) : (
                        alerts.map((alert, i) => (
                            <AlertRow key={i} alert={alert} index={i} last={i === alerts.length - 1} />
                        ))
                    )}
                </div>
            </div>
        </div>
    )
}