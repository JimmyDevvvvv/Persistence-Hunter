// src/pages/Entries.jsx
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { fetchEntries } from '../api/client'

const TYPES = ['all', 'registry', 'task', 'service']
const SEVS  = ['all', 'critical', 'high', 'medium', 'low']

const SEV_PILL_MAP = {
    critical: 'active-red',
    high:     'active-orange',
    medium:   'active-yellow',
    low:      'active-green',
    all:      'active',
}

const SEV_COLORS = {
    critical: 'var(--red)',
    high:     'var(--orange)',
    medium:   'var(--yellow)',
    low:      'var(--green)',
}

function SevBadge({ severity }) {
    const styles = {
        critical: { bg: 'rgba(255,53,96,0.12)',  color: 'var(--red)',    border: 'rgba(255,53,96,0.35)',  shadow: 'rgba(255,53,96,0.15)' },
        high:     { bg: 'rgba(255,140,0,0.1)',   color: 'var(--orange)', border: 'rgba(255,140,0,0.3)',   shadow: null },
        medium:   { bg: 'rgba(245,197,24,0.08)', color: 'var(--yellow)', border: 'rgba(245,197,24,0.25)', shadow: null },
        low:      { bg: 'rgba(0,229,153,0.08)',  color: 'var(--green)',  border: 'rgba(0,229,153,0.25)',  shadow: null },
    }
    const s = styles[severity] || { bg: 'var(--bg-raised)', color: 'var(--text-muted)', border: 'var(--bg-border)', shadow: null }
    return (
        <span style={{
            fontFamily: 'IBM Plex Mono',
            fontSize: 9,
            fontWeight: 600,
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            padding: '2px 7px',
            borderRadius: 4,
            background: s.bg,
            color: s.color,
            border: `1px solid ${s.border}`,
            boxShadow: s.shadow ? `0 0 8px ${s.shadow}` : 'none',
            whiteSpace: 'nowrap',
        }}>
            {severity}
        </span>
    )
}

export function Entries() {
    const navigate     = useNavigate()
    const [params]     = useSearchParams()
    const [type, setType] = useState(params.get('type') || 'all')
    const [sev, setSev]   = useState('all')

    const { data, isLoading } = useQuery({
        queryKey: ['entries', type, sev],
        queryFn: () => fetchEntries({
            entry_type: type,
            severity:   sev === 'all' ? undefined : sev,
            limit: 500,
        }),
    })

    const entries = data?.entries || []

    return (
        <div className="space-y-4 animate-slide-up">

            {/* ── Page header ── */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="font-display text-3xl font-bold gradient-text"
                        style={{ letterSpacing: '0.04em' }}>
                        Entries
                    </h1>
                    <p className="font-mono text-[11px] mt-1" style={{ color: 'var(--text-muted)' }}>
                        All collected persistence mechanisms
                    </p>
                </div>
                <div className="font-mono text-[11px]" style={{ color: 'var(--text-muted)' }}>
                    {isLoading ? '—' : entries.length.toLocaleString()} entries
                </div>
            </div>

            {/* ── Filters ── */}
            <div className="flex items-center gap-3 flex-wrap">
                <div className="pill-group">
                    {TYPES.map(t => (
                        <button
                            key={t}
                            onClick={() => setType(t)}
                            className={`pill ${type === t ? 'active' : ''}`}
                        >
                            {t}
                        </button>
                    ))}
                </div>
                <div className="pill-group">
                    {SEVS.map(s => (
                        <button
                            key={s}
                            onClick={() => setSev(s)}
                            className={`pill ${sev === s ? SEV_PILL_MAP[s] : ''}`}
                        >
                            {s}
                        </button>
                    ))}
                </div>
            </div>

            {/* ── Table ── */}
            <div className="panel">
                {/* Head */}
                <div className="table-head"
                    style={{ gridTemplateColumns: '90px 80px 200px 1fr 110px' }}>
                    {['Severity', 'Type', 'Name', 'Value / Path', 'Last Seen'].map(h => (
                        <span key={h} className="panel-label">{h}</span>
                    ))}
                </div>

                {isLoading ? (
                    <div className="flex justify-center items-center py-16">
                        <div className="flex items-center gap-3">
                            <div className="w-5 h-5 border-2 rounded-full animate-spin"
                                style={{ borderColor: 'var(--bg-border)', borderTopColor: 'var(--cyan)' }} />
                            <span className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>Loading...</span>
                        </div>
                    </div>
                ) : entries.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 gap-3"
                        style={{ color: 'var(--text-muted)' }}>
                        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" opacity="0.25">
                            <line x1="8" y1="6" x2="21" y2="6" /><line x1="8" y1="12" x2="21" y2="12" />
                            <line x1="8" y1="18" x2="21" y2="18" /><line x1="3" y1="6" x2="3.01" y2="6" />
                            <line x1="3" y1="12" x2="3.01" y2="12" /><line x1="3" y1="18" x2="3.01" y2="18" />
                        </svg>
                        <span className="font-mono text-xs">No entries found</span>
                    </div>
                ) : (
                    <div>
                        {entries.map((e, i) => {
                            const name  = e.name || e.task_name || e.service_name || '?'
                            const value = e.value_data || e.command || e.binary_path || ''
                            const etype = e.entry_type || type

                            return (
                                <div
                                    key={i}
                                    onClick={() => navigate(`/entries/${etype}/${e.id}`)}
                                    className={`table-row stagger-${Math.min(i + 1, 5)}`}
                                    style={{ gridTemplateColumns: '90px 80px 200px 1fr 110px', height: 38 }}
                                >
                                    <div><SevBadge severity={e.severity} /></div>

                                    <span className="font-mono text-[10px] uppercase"
                                        style={{ color: 'var(--text-muted)' }}>
                                        {etype}
                                    </span>

                                    <span className="font-mono text-xs truncate"
                                        style={{ color: 'var(--text-primary)' }}>
                                        {name}
                                    </span>

                                    <span className="font-mono text-[10px] truncate"
                                        style={{ color: 'var(--text-muted)' }}>
                                        {value.slice(0, 90)}
                                    </span>

                                    <span className="font-mono text-[9px]"
                                        style={{ color: 'var(--text-muted)', opacity: 0.6 }}>
                                        {e.last_seen?.slice(0, 10)}
                                    </span>
                                </div>
                            )
                        })}
                    </div>
                )}
            </div>
        </div>
    )
}