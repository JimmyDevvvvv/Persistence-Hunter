// src/pages/EntryDetail.jsx
import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AnimatePresence, motion } from 'framer-motion'
import { fetchEntry, fetchChain, triggerEnrichment } from '../api/client'
import { ProcessTree } from '../components/features/ProcessTree'
import { IntelPanel } from '../components/features/IntelPanel'

const SEV_SCORE = { critical: 95, high: 88, medium: 45, low: 15 }

const TYPE_BADGE = {
    registry: { label: 'Registry', color: '#3b82f6', bg: 'rgba(59,130,246,0.15)', border: 'rgba(59,130,246,0.35)' },
    task: { label: 'Task', color: '#f59e0b', bg: 'rgba(245,158,11,0.15)', border: 'rgba(245,158,11,0.35)' },
    service: { label: 'Service', color: '#10b981', bg: 'rgba(16,185,129,0.15)', border: 'rgba(16,185,129,0.35)' },
    startup: { label: 'Startup', color: '#8b5cf6', bg: 'rgba(139,92,246,0.15)', border: 'rgba(139,92,246,0.35)' },
    ifeo: { label: 'IFEO', color: '#06b6d4', bg: 'rgba(6,182,212,0.15)', border: 'rgba(6,182,212,0.35)' },
    'run key': { label: 'Run Key', color: '#f97316', bg: 'rgba(249,115,22,0.15)', border: 'rgba(249,115,22,0.35)' },
}

function getTypeBadge(entryType, iocNotes) {
    const lower = (iocNotes || '').toLowerCase()
    if (lower.includes('ifeo') || lower.includes('debugger')) return TYPE_BADGE['ifeo']
    if (lower.includes('run key') || lower.includes('currentversion\\run')) return TYPE_BADGE['run key']
    return TYPE_BADGE[entryType?.toLowerCase()] || TYPE_BADGE['registry']
}

function ScoreBox({ score, severity }) {
    const colors = {
        critical: { color: '#ff3560', border: '#ff3560', bg: 'rgba(255,53,96,0.15)' },
        high: { color: '#f97316', border: '#f97316', bg: 'rgba(249,115,22,0.15)' },
        medium: { color: '#f5c518', border: '#f5c518', bg: 'rgba(245,197,24,0.12)' },
        low: { color: '#00e599', border: '#00e599', bg: 'rgba(0,229,153,0.1)' },
    }
    const c = colors[severity] || colors.medium
    return (
        <div style={{
            minWidth: 36, height: 28,
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
            background: c.bg, border: `1px solid ${c.border}`,
            borderRadius: 5, padding: '0 8px',
            fontFamily: 'IBM Plex Mono', fontSize: 13, fontWeight: 700,
            color: c.color,
        }}>
            {score}
        </div>
    )
}

function TypeBadge({ entryType, iocNotes }) {
    const b = getTypeBadge(entryType, iocNotes)
    return (
        <span style={{
            fontFamily: 'IBM Plex Mono', fontSize: 10, fontWeight: 600,
            letterSpacing: '0.04em', textTransform: 'uppercase',
            padding: '3px 8px', borderRadius: 4,
            background: b.bg, color: b.color, border: `1px solid ${b.border}`,
            whiteSpace: 'nowrap',
        }}>
            {b.label}
        </span>
    )
}

function TechBadge({ id, name }) {
    return (
        <span title={name} style={{
            fontFamily: 'IBM Plex Mono', fontSize: 10, fontWeight: 600,
            padding: '3px 8px', borderRadius: 4,
            background: 'rgba(168,85,247,0.12)', color: '#a855f7',
            border: '1px solid rgba(168,85,247,0.3)',
        }}>
            {id}
        </span>
    )
}

function SevBadge({ severity }) {
    const colors = {
        critical: { color: 'var(--red)', bg: 'rgba(255,53,96,0.12)', border: 'rgba(255,53,96,0.35)' },
        high: { color: 'var(--orange)', bg: 'rgba(249,115,22,0.12)', border: 'rgba(249,115,22,0.35)' },
        medium: { color: 'var(--yellow)', bg: 'rgba(245,197,24,0.1)', border: 'rgba(245,197,24,0.3)' },
        low: { color: 'var(--green)', bg: 'rgba(0,229,153,0.08)', border: 'rgba(0,229,153,0.25)' },
    }
    const c = colors[severity] || colors.medium
    return (
        <span style={{
            fontFamily: 'IBM Plex Mono', fontSize: 9.5, fontWeight: 700,
            letterSpacing: '0.1em', textTransform: 'uppercase',
            padding: '3px 8px', borderRadius: 4,
            background: c.bg, color: c.color, border: `1px solid ${c.border}`,
        }}>
            {severity}
        </span>
    )
}

export function EntryDetail() {
    const { type, id } = useParams()
    const navigate = useNavigate()
    const [tab, setTab] = useState('chain')
    const [enriching, setEnriching] = useState(false)
    const MotionDiv = motion.div

    const { data: entry, isLoading, refetch: refetchEntry } = useQuery({
        queryKey: ['entry', type, id],
        queryFn: () => fetchEntry(type, id),
    })

    const { data: chainData, isLoading: chainLoading, error: chainError } = useQuery({
        queryKey: ['chain', type, id],
        queryFn: () => fetchChain(type, id),
        enabled: !!entry,
    })

    async function handleEnrich() {
        setEnriching(true)
        try {
            await triggerEnrichment(type, id)
            refetchEntry()
        } finally {
            setEnriching(false)
        }
    }

    if (isLoading) return (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 256, gap: 12 }}>
            <div className="w-5 h-5 border-2 rounded-full animate-spin"
                style={{ borderColor: 'var(--bg-border)', borderTopColor: 'var(--cyan)' }} />
            <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 12, color: 'var(--text-muted)' }}>Loading entry...</span>
        </div>
    )
    if (!entry) return (
        <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 13, padding: 32, color: 'var(--red)', display: 'flex', alignItems: 'center', gap: 8 }}>
            ✗ Entry not found
        </div>
    )

    const name = entry.name || entry.task_name || entry.service_name || '?'
    const value = entry.value_data || entry.command || entry.binary_path || ''
    const techniques = entry.techniques || []
    const score = SEV_SCORE[entry.severity] ?? 0
    const chain = chainData?.chain || []
    const chainLine = chain.length > 0 ? chain.map(n => n.name).join(' → ') : ''
    const riskCount = (entry.enrichment?.risk_indicators?.length || 0)

    // Anomalies
    const anomalies = []
    if (chain.some(n => n.type === 'malicious')) anomalies.push('malicious_writer')
    const hasLolbin = chain.some(n => ['powershell.exe', 'cmd.exe', 'reg.exe', 'rundll32.exe', 'mshta.exe'].includes(n.name?.toLowerCase()))
    if (hasLolbin && chain.length >= 2) anomalies.push('lolbin_chain')
    if (chain.some(n => n.source === 'unknown')) anomalies.push('no_origin')
    if (entry.ioc_notes?.toLowerCase().includes('suspicious')) anomalies.push('suspicious_path')
    if (entry.enrichment && !entry.enrichment.pe_signed && entry.enrichment.pe_is_pe) anomalies.push('unsigned_binary')
    const iocLower = (entry.ioc_notes || '').toLowerCase()
    if (iocLower.includes('ifeo') || iocLower.includes('debugger')) anomalies.push('ifeo_accessibility_hijack')

    const tabs = [
        { key: 'chain', label: 'Attack Chain', count: chain.length },
        { key: 'intel', label: 'Intel', count: riskCount },
        { key: 'details', label: 'Details' },
    ]

    return (
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden', animationName: 'slideUp', animationDuration: '0.25s', animationTimingFunction: 'ease-out' }}>
            {/* ── Header ── */}
            <div style={{ padding: '12px 20px 10px', borderBottom: '1px solid var(--bg-border)', flexShrink: 0 }}>

                {/* Back */}
                <button
                    onClick={() => navigate(-1)}
                    style={{
                        display: 'inline-flex', alignItems: 'center', gap: 5,
                        fontFamily: 'IBM Plex Mono', fontSize: 10, color: 'var(--text-muted)',
                        marginBottom: 10, cursor: 'pointer', transition: 'opacity 0.15s',
                    }}
                    onMouseEnter={e => e.currentTarget.style.opacity = '0.7'}
                    onMouseLeave={e => e.currentTarget.style.opacity = '1'}
                >
                    ← Back
                </button>

                {/* Row 1: score + sev badge + name + type + techniques */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 7, flexWrap: 'wrap' }}>
                    <ScoreBox score={score} severity={entry.severity} />
                    <SevBadge severity={entry.severity} />
                    <span style={{ fontFamily: 'Inter', fontSize: 22, fontWeight: 700, color: 'var(--text-primary)' }}>
                        {name}
                    </span>
                    <TypeBadge entryType={type} iocNotes={entry.ioc_notes} />
                    {techniques.map(t => <TechBadge key={t.id} id={t.id} name={t.name} />)}

                    {/* Enrich button pushed right */}
                    <div style={{ flex: 1 }} />
                    <button
                        onClick={handleEnrich}
                        disabled={enriching}
                        style={{
                            display: 'inline-flex', alignItems: 'center', gap: 6,
                            fontFamily: 'IBM Plex Mono', fontSize: 11, fontWeight: 600,
                            letterSpacing: '0.08em', textTransform: 'uppercase',
                            padding: '6px 14px', borderRadius: 6,
                            border: '1px solid rgba(0,212,255,0.4)', color: 'var(--cyan)',
                            background: 'rgba(0,212,255,0.06)', cursor: enriching ? 'not-allowed' : 'pointer',
                            opacity: enriching ? 0.5 : 1,
                        }}
                    >
                        {enriching ? (
                            <div className="w-3 h-3 rounded-full animate-spin"
                                style={{ border: '1.5px solid rgba(0,212,255,0.3)', borderTopColor: 'var(--cyan)' }} />
                        ) : (
                            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                                <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
                            </svg>
                        )}
                        {enriching ? 'Enriching...' : '⚡ Enrich'}
                    </button>
                </div>

                {/* Row 2: metadata */}
                <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 11, color: 'var(--text-muted)', display: 'flex', gap: 20, flexWrap: 'wrap' }}>
                    <span>Source: <strong style={{ color: 'var(--text-secondary)' }}>
                        {chain[0]?.source?.toUpperCase() || 'SYSMON/4688'}
                    </strong></span>
                    <span>User: <strong style={{ color: 'var(--text-secondary)' }}>
                        {chain[0]?.user || chain[chain.length - 1]?.user || 'Unknown'}
                    </strong></span>
                    {entry.last_seen && (
                        <span>Seen: <strong style={{ color: 'var(--text-secondary)' }}>
                            {new Date(entry.last_seen).toLocaleString()}
                        </strong></span>
                    )}
                    {chain.length > 0 && (
                        <span>Depth: <strong style={{ color: 'var(--cyan)' }}>{chain.length} hops</strong></span>
                    )}
                </div>
            </div>

            {/* ── Chain summary line ── */}
            {chainLine && (
                <div style={{
                    padding: '7px 20px',
                    fontFamily: 'IBM Plex Mono', fontSize: 11,
                    borderBottom: '1px solid var(--bg-border)',
                    background: 'rgba(0,212,255,0.02)',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                    <span style={{ color: 'var(--text-muted)', marginRight: 6 }}>CHAIN:</span>
                    <span style={{ color: 'var(--cyan)' }}>{chainLine}</span>
                </div>
            )}

            {/* ── Anomaly banner ── */}
            {anomalies.length > 0 && (
                <div style={{
                    padding: '8px 20px',
                    background: 'rgba(255,53,96,0.05)',
                    borderBottom: '1px solid rgba(255,53,96,0.2)',
                    borderLeft: '3px solid var(--red)',
                    flexShrink: 0,
                }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
                        <span style={{ color: 'var(--red)', fontWeight: 700, fontSize: 14 }}>!!</span>
                        <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 10.5, fontWeight: 600, color: 'var(--red)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                            Behavioral Anomalies Detected In Chain
                        </span>
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {anomalies.map(a => (
                            <span key={a} style={{
                                fontFamily: 'IBM Plex Mono', fontSize: 9.5,
                                padding: '2px 8px', borderRadius: 4,
                                background: 'rgba(255,53,96,0.12)', color: 'var(--red)',
                                border: '1px solid rgba(255,53,96,0.3)',
                            }}>
                                {a}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {/* ── Tabs ── */}
            <div style={{ display: 'flex', borderBottom: '1px solid var(--bg-border)', flexShrink: 0, background: 'var(--bg-surface)' }}>
                {tabs.map(t => (
                    <button
                        key={t.key}
                        onClick={() => setTab(t.key)}
                        style={{
                            fontFamily: 'IBM Plex Mono', fontSize: 10.5, fontWeight: 500,
                            letterSpacing: '0.08em', textTransform: 'uppercase',
                            padding: '9px 18px',
                            borderBottom: `2px solid ${tab === t.key ? 'var(--cyan)' : 'transparent'}`,
                            color: tab === t.key ? 'var(--cyan)' : 'var(--text-muted)',
                            background: tab === t.key ? 'rgba(0,212,255,0.03)' : 'transparent',
                            cursor: 'pointer',
                            display: 'flex', alignItems: 'center', gap: 5,
                            transition: 'color 0.12s, border-color 0.12s',
                        }}
                    >
                        {t.label}
                        {t.count != null && t.count > 0 && (
                            <span style={{
                                fontFamily: 'IBM Plex Mono', fontSize: 9,
                                padding: '1px 5px', borderRadius: 3,
                                background: tab === t.key ? 'rgba(0,212,255,0.15)' : 'var(--bg-raised)',
                                color: tab === t.key ? 'var(--cyan)' : 'var(--text-muted)',
                                border: `1px solid ${tab === t.key ? 'rgba(0,212,255,0.3)' : 'var(--bg-border)'}`,
                            }}>
                                {t.count}
                            </span>
                        )}
                    </button>
                ))}
            </div>

            {/* ── Tab content ── */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>
                <AnimatePresence mode="wait">
                    <MotionDiv
                        key={tab}
                        initial={{ opacity: 0, y: 10, filter: 'blur(2px)' }}
                        animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
                        exit={{ opacity: 0, y: -8, filter: 'blur(2px)' }}
                        transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
                    >
                        {tab === 'chain' && (
                            <ProcessTree chain={chain} loading={chainLoading} error={chainError} />
                        )}

                        {tab === 'intel' && (
                            <IntelPanel entryType={type} entryId={id} enrichment={entry.enrichment} />
                        )}

                        {tab === 'details' && (
                            <div style={{ maxWidth: 640 }}>
                                <div style={{
                                    background: 'var(--bg-surface)', border: '1px solid var(--bg-border)',
                                    borderRadius: 8, overflow: 'hidden',
                                }}>
                                    <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--bg-border)', background: 'rgba(255,255,255,0.02)' }}>
                                        <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 9.5, fontWeight: 600, letterSpacing: '0.12em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                                            Entry Details
                                        </span>
                                    </div>
                                    <div style={{ padding: '4px 16px 8px' }}>
                                        {[
                                            ['Name', name, true],
                                            ['Value / Path', value, true],
                                            ['Hive', entry.hive, true],
                                            ['Reg Path', entry.reg_path, true],
                                            ['Run As', entry.run_as, false],
                                            ['Start Type', entry.start_type, false],
                                            ['Trigger', entry.trigger_type, false],
                                            ['IOC Notes', entry.ioc_notes, false],
                                            ['First Seen', entry.first_seen?.slice(0, 19), false],
                                            ['Last Seen', entry.last_seen?.slice(0, 19), false],
                                            ['Entry ID', `${type}/${id}`, true],
                                        ].map(([label, val, mono]) => val ? (
                                            <div key={label} style={{ display: 'flex', gap: 16, padding: '8px 0', borderBottom: '1px solid var(--bg-border)' }}>
                                                <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 10.5, color: 'var(--text-muted)', width: 90, flexShrink: 0 }}>{label}</span>
                                                <span style={{ fontFamily: mono ? 'IBM Plex Mono' : 'Inter', fontSize: 11.5, color: 'var(--text-secondary)', wordBreak: 'break-all' }}>{val}</span>
                                            </div>
                                        ) : null)}
                                    </div>
                                </div>
                            </div>
                        )}
                    </MotionDiv>
                </AnimatePresence>

            </div>
        </div>
    )
}