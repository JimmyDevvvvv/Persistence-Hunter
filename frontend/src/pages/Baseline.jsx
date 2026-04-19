// src/pages/Baseline.jsx
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchBaselines, fetchDiff, createBaseline, deleteBaseline } from '../api/client'
import { useNavigate } from 'react-router-dom'
import { useState } from 'react'

const SEVERITY_STYLES = {
    critical: { bg: 'rgba(255,53,96,0.12)',  color: 'var(--red)',    border: 'rgba(255,53,96,0.35)'  },
    high:     { bg: 'rgba(255,140,0,0.1)',   color: 'var(--orange)', border: 'rgba(255,140,0,0.3)'   },
    medium:   { bg: 'rgba(245,197,24,0.08)', color: 'var(--yellow)', border: 'rgba(245,197,24,0.25)' },
    low:      { bg: 'rgba(0,229,153,0.08)',  color: 'var(--green)',  border: 'rgba(0,229,153,0.25)'  },
}

function SevBadge({ severity }) {
    const s = SEVERITY_STYLES[severity] || { bg: 'var(--bg-raised)', color: 'var(--text-muted)', border: 'var(--bg-border)' }
    return (
        <span style={{
            fontFamily: 'IBM Plex Mono', fontSize: 9, fontWeight: 600,
            letterSpacing: '0.08em', textTransform: 'uppercase',
            padding: '2px 6px', borderRadius: 4,
            background: s.bg, color: s.color, border: `1px solid ${s.border}`,
            whiteSpace: 'nowrap',
        }}>
            {severity}
        </span>
    )
}

export function Baseline() {
    const navigate = useNavigate()
    const qc       = useQueryClient()

    const { data: blData } = useQuery({
        queryKey: ['baselines'],
        queryFn: fetchBaselines,
    })

    const { data: diff, isLoading: diffLoading } = useQuery({
        queryKey: ['diff'],
        queryFn: () => fetchDiff({ entry_type: 'all' }),
    })

    const createMut = useMutation({
        mutationFn: () => createBaseline({ name: null, entry_type: 'all' }),
        onSuccess: () => {
            qc.invalidateQueries(['baselines'])
            qc.invalidateQueries(['diff'])
        },
    })

    const deleteMut = useMutation({
        mutationFn: deleteBaseline,
        onSuccess: () => qc.invalidateQueries(['baselines']),
    })

    const baselines     = blData?.baselines || []
    const newEntries    = diff?.new || []
    const removedEntries= diff?.removed || []

    return (
        <div className="space-y-6 animate-slide-up">

            {/* ── Header ── */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="font-display text-3xl font-bold gradient-text"
                        style={{ letterSpacing: '0.04em' }}>
                        Baseline
                    </h1>
                    <p className="font-mono text-[11px] mt-1" style={{ color: 'var(--text-muted)' }}>
                        Snapshot and diff persistence state over time
                    </p>
                </div>
                <button
                    onClick={() => createMut.mutate()}
                    disabled={createMut.isPending}
                    className="btn-glow"
                    style={createMut.isPending ? { opacity: 0.5, cursor: 'not-allowed' } : {}}
                >
                    {createMut.isPending ? (
                        <div className="w-3 h-3 rounded-full animate-spin"
                            style={{ border: '2px solid rgba(0,212,255,0.3)', borderTopColor: 'var(--cyan)' }} />
                    ) : (
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                            <circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="3" />
                        </svg>
                    )}
                    Snapshot Now
                </button>
            </div>

            {/* ── Diff panels ── */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* New entries */}
                <div className="panel">
                    <div className="panel-header">
                        <div className="flex items-center gap-2">
                            <div className="w-2 h-2 rounded-full"
                                style={{ background: 'var(--red)', boxShadow: '0 0 6px var(--red)' }} />
                            <span className="panel-label">New Since Baseline</span>
                        </div>
                        {newEntries.length > 0 && (
                            <span className="font-mono text-[9px] px-1.5 py-0.5 rounded"
                                style={{ background: 'rgba(255,53,96,0.1)', color: 'var(--red)', border: '1px solid rgba(255,53,96,0.25)' }}>
                                {newEntries.length}
                            </span>
                        )}
                    </div>
                    {diffLoading ? (
                        <div className="flex justify-center items-center py-10">
                            <div className="w-4 h-4 border-2 rounded-full animate-spin"
                                style={{ borderColor: 'var(--bg-border)', borderTopColor: 'var(--cyan)' }} />
                        </div>
                    ) : newEntries.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-12 gap-2"
                            style={{ color: 'var(--text-muted)' }}>
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" opacity="0.25">
                                <polyline points="20 6 9 17 4 12" />
                            </svg>
                            <div className="font-mono text-xs">Nothing new</div>
                            <div className="font-mono text-[10px]" style={{ opacity: 0.6 }}>Matches baseline</div>
                        </div>
                    ) : (
                        <div>
                            {newEntries.map((e, i) => (
                                <div
                                    key={i}
                                    onClick={() => navigate(`/entries/${e.type}/${e.id}`)}
                                    className={`flex items-center gap-3 px-5 py-2.5 cursor-pointer table-row stagger-${Math.min(i + 1, 5)}`}
                                    style={{ borderBottom: i < newEntries.length - 1 ? '1px solid var(--bg-border)' : 'none' }}
                                >
                                    <SevBadge severity={e.severity} />
                                    <span className="font-mono text-[10px] w-16 uppercase" style={{ color: 'var(--text-muted)' }}>{e.type}</span>
                                    <span className="font-mono text-xs truncate flex-1" style={{ color: 'var(--text-primary)' }}>
                                        {e.name || '?'}
                                    </span>
                                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"
                                        style={{ color: 'var(--text-muted)', flexShrink: 0 }}>
                                        <path d="M5 12h14M12 5l7 7-7 7" />
                                    </svg>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* Removed entries */}
                <div className="panel">
                    <div className="panel-header">
                        <div className="flex items-center gap-2">
                            <div className="w-2 h-2 rounded-full" style={{ background: 'var(--text-muted)' }} />
                            <span className="panel-label">Removed</span>
                        </div>
                        {removedEntries.length > 0 && (
                            <span className="font-mono text-[9px] px-1.5 py-0.5 rounded"
                                style={{ background: 'var(--bg-raised)', color: 'var(--text-muted)', border: '1px solid var(--bg-border)' }}>
                                {removedEntries.length}
                            </span>
                        )}
                    </div>
                    {removedEntries.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-12 gap-2"
                            style={{ color: 'var(--text-muted)' }}>
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" opacity="0.25">
                                <circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="3" />
                            </svg>
                            <div className="font-mono text-xs">Nothing removed</div>
                        </div>
                    ) : (
                        <div>
                            {removedEntries.map((e, i) => (
                                <div key={i} className={`flex items-center gap-3 px-5 py-2.5 table-row stagger-${Math.min(i + 1, 5)}`}
                                    style={{ borderBottom: i < removedEntries.length - 1 ? '1px solid var(--bg-border)' : 'none' }}>
                                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="2" strokeLinecap="round">
                                        <polyline points="3 6 5 6 21 6" /><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6" />
                                        <path d="M10 11v6M14 11v6" />
                                    </svg>
                                    <span className="font-mono text-xs truncate" style={{ color: 'var(--text-muted)' }}>
                                        {e.name}
                                    </span>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>

            {/* ── Baseline history ── */}
            <div className="panel">
                <div className="panel-header">
                    <span className="panel-label">Baseline History</span>
                    <span className="font-mono text-[9px] px-1.5 py-0.5 rounded"
                        style={{ background: 'var(--bg-raised)', color: 'var(--text-muted)', border: '1px solid var(--bg-border)' }}>
                        {baselines.length}
                    </span>
                </div>
                {baselines.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-12 gap-2"
                        style={{ color: 'var(--text-muted)' }}>
                        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" opacity="0.2">
                            <circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="3" />
                            <line x1="12" y1="3" x2="12" y2="6" /><line x1="12" y1="18" x2="12" y2="21" />
                            <line x1="3" y1="12" x2="6" y2="12" /><line x1="18" y1="12" x2="21" y2="12" />
                        </svg>
                        <div className="font-mono text-xs">No baselines yet</div>
                        <div className="font-mono text-[10px]" style={{ opacity: 0.6 }}>Click "Snapshot Now" to create one</div>
                    </div>
                ) : (
                    <div>
                        {baselines.map((b, i) => (
                            <div key={b.id}
                                className={`flex items-center gap-4 px-5 py-3 table-row stagger-${Math.min(i + 1, 5)}`}
                                style={{ borderBottom: i < baselines.length - 1 ? '1px solid var(--bg-border)' : 'none' }}>
                                <span className="font-mono text-[10px]"
                                    style={{ color: 'var(--text-muted)', opacity: 0.6 }}>
                                    #{b.id}
                                </span>
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"
                                    style={{ color: 'var(--text-muted)', flexShrink: 0 }}>
                                    <circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="3" />
                                </svg>
                                <span className="font-mono text-xs flex-1" style={{ color: 'var(--text-primary)' }}>
                                    {b.name}
                                </span>
                                <span className="font-mono text-[10px]" style={{ color: 'var(--text-muted)' }}>
                                    {b.entry_count} entries
                                </span>
                                <span className="font-mono text-[10px]" style={{ color: 'var(--text-muted)', opacity: 0.6 }}>
                                    {b.created_at?.slice(0, 16)}
                                </span>
                                <button
                                    onClick={() => deleteMut.mutate(b.id)}
                                    className="w-6 h-6 flex items-center justify-center rounded transition-all"
                                    style={{ color: 'var(--text-muted)' }}
                                    onMouseEnter={e => {
                                        e.currentTarget.style.color = 'var(--red)'
                                        e.currentTarget.style.background = 'rgba(255,53,96,0.1)'
                                    }}
                                    onMouseLeave={e => {
                                        e.currentTarget.style.color = 'var(--text-muted)'
                                        e.currentTarget.style.background = 'transparent'
                                    }}
                                >
                                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                                        <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                                    </svg>
                                </button>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    )
}