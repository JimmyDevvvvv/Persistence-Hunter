// src/pages/EntryDetail.jsx
import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AnimatePresence, motion } from 'framer-motion'
import { fetchEntry, fetchChain, fetchScore, fetchSignatures, runScorer } from '../api/client'
import { ProcessTree } from '../components/features/ProcessTree'
import { IntelPanel } from '../components/features/IntelPanel'

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
            {score == null ? '—' : score}
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

    const { data: scoreData } = useQuery({
        queryKey: ['score', type, id],
        queryFn: () => fetchScore(type, id),
        enabled: !!entry,
    })

    const { data: chainData, isLoading: chainLoading, error: chainError } = useQuery({
        queryKey: ['chain', type, id],
        queryFn: () => fetchChain(type, id),
        enabled: !!entry,
    })

    async function handleRunScorer() {
        setEnriching(true)
        try {
            await runScorer()
            refetchEntry()
        } finally {
            setEnriching(false)
        }
    }

    const { data: sigData } = useQuery({
        queryKey: ['signatures'],
        queryFn: () => fetchSignatures({ exe_only: true }),
        staleTime: 5 * 60 * 1000,
        enabled: type === 'service',
    })

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
    const score = scoreData?.score ?? null
    const chain = chainData?.chain || []
    const chainLine = chain.length > 0 ? chain.map(n => n.name).join(' → ') : ''
    const riskCount = (scoreData?.risk_indicators?.length || 0)

    // Find signature for this service entry
    const sigEntry = type === 'service'
        ? (sigData?.results || []).find(r => r.service_name?.toLowerCase() === name?.toLowerCase())
        : null

    // Client-side PS decode
    const decodedPS = (() => {
        const val = value || ''
        const m = val.match(/-(?:EncodedCommand|enc?)\s+([A-Za-z0-9+/=]{8,})/i)
        if (!m) return null
        try {
            const b64 = m[1].trim().padEnd(m[1].length + (4 - m[1].length % 4) % 4, '=')
            const raw = atob(b64)
            let str = ''
            for (let i = 0; i < raw.length - 1; i += 2) {
                str += String.fromCharCode(raw.charCodeAt(i) | (raw.charCodeAt(i + 1) << 8))
            }
            return str.trim() || null
        } catch { return null }
    })()

    // Anomalies
    const anomalies = []
    if (chain.some(n => n.type === 'malicious')) anomalies.push('malicious_writer')
    const hasLolbin = chain.some(n => ['powershell.exe', 'cmd.exe', 'reg.exe', 'rundll32.exe', 'mshta.exe'].includes(n.name?.toLowerCase()))
    if (hasLolbin && chain.length >= 2) anomalies.push('lolbin_chain')
    if (chain.some(n => n.source === 'unknown')) anomalies.push('no_origin')
    if (entry.ioc_notes?.toLowerCase().includes('suspicious')) anomalies.push('suspicious_path')
    if (scoreData?.breakdown?.some(b => b.description?.toLowerCase().includes('unsigned'))) anomalies.push('unsigned_binary')
    const iocLower = (entry.ioc_notes || '').toLowerCase()
    if (iocLower.includes('ifeo') || iocLower.includes('debugger')) anomalies.push('ifeo_accessibility_hijack')

    const tabs = [
        { key: 'summary', label: 'Summary' },
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

                    <div style={{ flex: 1 }} />
                    <button
                        onClick={handleRunScorer}
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
                        {enriching ? 'Scoring...' : '⚡ Run Scorer'}
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
                        {tab === 'summary' && (
                            <div style={{ maxWidth: 720, display: 'flex', flexDirection: 'column', gap: 14 }}>
                                <style>{`
                                    @keyframes rh-s-in{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
                                    @keyframes rh-s-scan{0%{left:-60%}100%{left:160%}}
                                    @keyframes rh-s-pip{0%,100%{box-shadow:0 0 4px currentColor}50%{box-shadow:0 0 14px currentColor,0 0 28px currentColor}}
                                    @keyframes rh-s-glow{0%,100%{opacity:.4}50%{opacity:1}}
                                    @keyframes rh-s-bar{from{width:0}to{width:var(--tw)}}
                                    .rh-s-card{border-radius:12px;overflow:hidden;position:relative;transition:transform .2s,box-shadow .2s;}
                                    .rh-s-card:hover{transform:translateY(-2px);}
                                    .rh-s-shimmer{position:absolute;top:0;left:-60%;width:60%;height:100%;background:linear-gradient(90deg,transparent,rgba(255,255,255,.04),transparent);animation:rh-s-scan 3s ease-in-out infinite;}
                                `}</style>

                                {/* ── Hero threat card ── */}
                                <div className="rh-s-card" style={{
                                    background: `linear-gradient(135deg, ${entry.severity === 'critical' ? 'rgba(255,32,85,.12) 0%, rgba(15,19,32,.95)' :
                                            entry.severity === 'high' ? 'rgba(255,119,34,.1) 0%, rgba(15,19,32,.95)' :
                                                'rgba(255,214,10,.08) 0%, rgba(15,19,32,.95)'
                                        } 100%)`,
                                    border: `1px solid ${entry.severity === 'critical' ? 'rgba(255,32,85,.3)' : entry.severity === 'high' ? 'rgba(255,119,34,.25)' : 'rgba(255,214,10,.2)'}`,
                                    boxShadow: `0 8px 32px ${entry.severity === 'critical' ? 'rgba(255,32,85,.08)' : entry.severity === 'high' ? 'rgba(255,119,34,.06)' : 'rgba(255,214,10,.05)'}`,
                                    animation: 'rh-s-in .35s cubic-bezier(.16,1,.3,1)',
                                    padding: '20px 22px',
                                }}>
                                    <div className="rh-s-shimmer" />
                                    {/* Top row */}
                                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
                                        <div>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                                                <div style={{
                                                    width: 8, height: 8, borderRadius: '50%',
                                                    background: entry.severity === 'critical' ? '#ff2055' : entry.severity === 'high' ? '#ff7722' : '#ffd60a',
                                                    animation: 'rh-s-pip 1.8s ease-in-out infinite',
                                                    color: entry.severity === 'critical' ? '#ff2055' : entry.severity === 'high' ? '#ff7722' : '#ffd60a',
                                                }} />
                                                <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, fontWeight: 700, letterSpacing: '.16em', textTransform: 'uppercase', color: entry.severity === 'critical' ? '#ff2055' : entry.severity === 'high' ? '#ff7722' : '#ffd60a' }}>
                                                    {entry.severity} persistence
                                                </span>
                                            </div>
                                            <div style={{ fontFamily: "'Space Grotesk',sans-serif", fontSize: 22, fontWeight: 700, color: 'rgba(238,242,255,.97)', letterSpacing: '-.01em', marginBottom: 4 }}>
                                                {name}
                                            </div>
                                            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'rgba(90,107,138,1)' }}>
                                                {type} · {entry.hive || ''} · {chain.length} hop chain
                                            </div>
                                        </div>
                                        {score != null && (
                                            <div style={{ textAlign: 'center', flexShrink: 0 }}>
                                                <div style={{
                                                    fontFamily: "'JetBrains Mono',monospace", fontSize: 36, fontWeight: 700, lineHeight: 1,
                                                    color: score >= 80 ? '#ff2055' : score >= 60 ? '#ff7722' : '#ffd60a',
                                                    textShadow: `0 0 30px ${score >= 80 ? 'rgba(255,32,85,.4)' : score >= 60 ? 'rgba(255,119,34,.3)' : 'rgba(255,214,10,.3)'}`,
                                                }}>
                                                    {score}
                                                </div>
                                                <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, color: 'rgba(53,64,96,.8)', textTransform: 'uppercase', letterSpacing: '.1em', marginTop: 2 }}>
                                                    threat score
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                    {/* Score bar */}
                                    {score != null && (
                                        <div style={{ marginBottom: 14 }}>
                                            <div style={{ height: 3, background: 'rgba(255,255,255,.05)', borderRadius: 3, overflow: 'hidden' }}>
                                                <div style={{
                                                    height: '100%', borderRadius: 3,
                                                    width: `${score}%`,
                                                    background: score >= 80 ? 'linear-gradient(90deg,#ff2055,#ff6b8a)' : score >= 60 ? 'linear-gradient(90deg,#ff7722,#ffaa55)' : 'linear-gradient(90deg,#ffd60a,#ffe87a)',
                                                    boxShadow: `0 0 8px ${score >= 80 ? '#ff2055' : score >= 60 ? '#ff7722' : '#ffd60a'}60`,
                                                    animation: 'rh-s-bar .8s cubic-bezier(.16,1,.3,1) .2s both',
                                                    '--tw': `${score}%`,
                                                }} />
                                            </div>
                                        </div>
                                    )}
                                    {/* Meta row */}
                                    <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap' }}>
                                        {[
                                            ['User', chain[0]?.user || 'Unknown'],
                                            ['Source', chain[0]?.source?.toUpperCase() || 'STUB'],
                                            ['Seen', entry.last_seen ? new Date(entry.last_seen).toLocaleString() : '—'],
                                            ['Depth', `${chain.length} hops`],
                                        ].map(([k, v]) => (
                                            <div key={k}>
                                                <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, color: 'rgba(53,64,96,.7)', textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 2 }}>{k}</div>
                                                <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'rgba(192,200,224,.9)' }}>{v}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>

                                {/* ── Anomalies banner ── */}
                                {anomalies.length > 0 && (
                                    <div className="rh-s-card" style={{
                                        background: 'rgba(255,32,85,.06)', border: '1px solid rgba(255,32,85,.25)',
                                        padding: '14px 18px', animation: 'rh-s-in .35s cubic-bezier(.16,1,.3,1) .04s both',
                                    }}>
                                        <div className="rh-s-shimmer" style={{ background: 'linear-gradient(90deg,transparent,rgba(255,32,85,.06),transparent)' }} />
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#ff2055" strokeWidth="2.5" strokeLinecap="round">
                                                <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                                                <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
                                            </svg>
                                            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, fontWeight: 700, letterSpacing: '.14em', textTransform: 'uppercase', color: '#ff2055' }}>
                                                Behavioral Anomalies Detected
                                            </span>
                                        </div>
                                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7 }}>
                                            {anomalies.map((a, i) => (
                                                <span key={a} style={{
                                                    fontFamily: "'JetBrains Mono',monospace", fontSize: 9, padding: '4px 10px', borderRadius: 5,
                                                    background: 'rgba(255,32,85,.12)', color: '#ff2055', border: '1px solid rgba(255,32,85,.3)',
                                                    animation: `rh-s-in .25s ease ${i * .05}s both`,
                                                }}>
                                                    {a.replace(/_/g, ' ')}
                                                </span>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* ── Two-col grid: signature + decoded PS / IOC ── */}
                                <div style={{ display: 'grid', gridTemplateColumns: type === 'service' || decodedPS ? '1fr 1fr' : '1fr', gap: 14 }}>
                                    {/* Signature */}
                                    {type === 'service' && (
                                        <div className="rh-s-card" style={{
                                            background: 'rgba(13,17,30,.95)', padding: '16px 18px',
                                            border: `1px solid ${sigEntry?.sig_status === 'Valid' ? 'rgba(0,230,118,.2)' : sigEntry?.sig_status === 'NotSigned' ? 'rgba(255,32,85,.25)' : sigEntry?.sig_status === 'Missing' ? 'rgba(255,214,10,.2)' : 'rgba(255,255,255,.07)'}`,
                                            animation: 'rh-s-in .35s cubic-bezier(.16,1,.3,1) .08s both',
                                        }}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 12 }}>
                                                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={sigEntry?.sig_status === 'Valid' ? '#00e676' : '#ff2055'} strokeWidth="2" strokeLinecap="round">
                                                    {sigEntry?.sig_status === 'Valid'
                                                        ? <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><polyline points="9 12 11 14 15 10" /></>
                                                        : <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><line x1="9" y1="9" x2="15" y2="15" /><line x1="15" y1="9" x2="9" y2="15" /></>
                                                    }
                                                </svg>
                                                <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700, letterSpacing: '.14em', textTransform: 'uppercase', color: 'rgba(53,64,96,.85)' }}>Binary Signature</span>
                                            </div>
                                            {sigEntry ? (<>
                                                <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 12, fontWeight: 700, color: sigEntry.sig_status === 'Valid' ? '#00e676' : '#ff2055', marginBottom: 8 }}>
                                                    {sigEntry.sig_status === 'Valid' ? '✅ Signed' : sigEntry.sig_status === 'NotSigned' ? '❌ Unsigned' : sigEntry.sig_status === 'Missing' ? '👻 Missing' : sigEntry.sig_status}
                                                </div>
                                                {sigEntry.signer && <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: 'rgba(140,155,175,1)', marginBottom: 4 }}>{sigEntry.signer}</div>}
                                                {sigEntry.issuer && <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, color: 'rgba(53,64,96,.7)', marginBottom: 8 }}>{sigEntry.issuer}</div>}
                                                {sigEntry.suspicious_path && <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: '#ffd60a', marginBottom: 8 }}>⚠ Suspicious path</div>}
                                                {sigEntry.sha256 && <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, color: 'rgba(53,64,96,.6)', wordBreak: 'break-all', marginBottom: 8 }}>{sigEntry.sha256.slice(0, 32)}…</div>}
                                                {sigEntry.vt_url && <a href={sigEntry.vt_url} target="_blank" rel="noopener noreferrer" style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: '#00e5ff', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                                                    VirusTotal →
                                                </a>}
                                            </>) : (
                                                <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'rgba(90,107,138,1)', lineHeight: 1.6 }}>
                                                    No data yet<br />
                                                    <span style={{ fontSize: 8, color: 'rgba(53,64,96,.7)' }}>POST /api/signatures/run</span>
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* Decoded PS */}
                                    {decodedPS && (
                                        <div className="rh-s-card" style={{
                                            background: 'rgba(0,229,255,.04)', padding: '16px 18px',
                                            border: '1px solid rgba(0,229,255,.2)',
                                            boxShadow: '0 4px 24px rgba(0,229,255,.05)',
                                            animation: 'rh-s-in .35s cubic-bezier(.16,1,.3,1) .1s both',
                                        }}>
                                            <div className="rh-s-shimmer" style={{ background: 'linear-gradient(90deg,transparent,rgba(0,229,255,.06),transparent)' }} />
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 12 }}>
                                                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#00e5ff" strokeWidth="2.5" strokeLinecap="round">
                                                    <rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0110 0v4" />
                                                </svg>
                                                <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700, letterSpacing: '.14em', textTransform: 'uppercase', color: '#00e5ff' }}>Decoded Payload</span>
                                            </div>
                                            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: '#00e5ff', lineHeight: 1.8, wordBreak: 'break-all', whiteSpace: 'pre-wrap', opacity: .9 }}>
                                                {decodedPS.length > 300 ? decodedPS.slice(0, 300) + '…' : decodedPS}
                                            </div>
                                        </div>
                                    )}
                                </div>

                                {/* ── IOC notes ── */}
                                {entry.ioc_notes && entry.ioc_notes.toLowerCase() !== 'none' && (
                                    <div className="rh-s-card" style={{
                                        background: 'rgba(255,214,10,.04)', padding: '14px 18px',
                                        border: '1px solid rgba(255,214,10,.18)',
                                        animation: 'rh-s-in .35s cubic-bezier(.16,1,.3,1) .12s both',
                                    }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 8 }}>
                                            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#ffd60a" strokeWidth="2.5" strokeLinecap="round">
                                                <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
                                            </svg>
                                            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700, letterSpacing: '.14em', textTransform: 'uppercase', color: '#ffd60a' }}>IOC Notes</span>
                                        </div>
                                        <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: 'rgba(192,200,224,.9)', lineHeight: 1.7 }}>{entry.ioc_notes}</div>
                                    </div>
                                )}

                                {/* ── MITRE tags ── */}
                                {techniques.length > 0 && (
                                    <div className="rh-s-card" style={{
                                        background: 'rgba(196,112,255,.04)', padding: '14px 18px',
                                        border: '1px solid rgba(196,112,255,.15)',
                                        animation: 'rh-s-in .35s cubic-bezier(.16,1,.3,1) .14s both',
                                    }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 10 }}>
                                            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#c470ff" strokeWidth="2" strokeLinecap="round">
                                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                                            </svg>
                                            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700, letterSpacing: '.14em', textTransform: 'uppercase', color: '#c470ff' }}>MITRE ATT&CK</span>
                                        </div>
                                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7 }}>
                                            {techniques.map((t, i) => (
                                                <span key={t.id || t} style={{
                                                    fontFamily: "'JetBrains Mono',monospace", fontSize: 9, padding: '4px 10px', borderRadius: 5,
                                                    background: 'rgba(196,112,255,.12)', color: '#c470ff', border: '1px solid rgba(196,112,255,.3)',
                                                    animation: `rh-s-in .25s ease ${i * .05 + .14}s both`,
                                                    cursor: 'default',
                                                }}>
                                                    {t.id || t}
                                                    {t.name && <span style={{ color: 'rgba(196,112,255,.55)', marginLeft: 6, fontWeight: 400 }}>— {t.name}</span>}
                                                </span>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* ── Chain summary ── */}
                                {chain.length > 0 && (
                                    <div className="rh-s-card" style={{
                                        background: 'rgba(13,17,30,.95)', padding: '16px 18px',
                                        border: '1px solid rgba(255,255,255,.07)',
                                        animation: 'rh-s-in .35s cubic-bezier(.16,1,.3,1) .16s both',
                                    }}>
                                        <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700, letterSpacing: '.14em', textTransform: 'uppercase', color: 'rgba(53,64,96,.85)', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 7 }}>
                                            <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                                                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
                                            </svg>
                                            Attack Chain
                                        </div>
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                                            {chain.map((node, i) => {
                                                const c = node.type === 'malicious' ? '#ff2055' : node.type === 'suspicious' ? '#ff7722' : '#00e5ff'
                                                const isLast = i === chain.length - 1
                                                return (
                                                    <div key={i} style={{ display: 'flex', alignItems: 'stretch', gap: 0 }}>
                                                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 20, flexShrink: 0, marginRight: 10 }}>
                                                            <div style={{ width: 8, height: 8, borderRadius: '50%', background: c, boxShadow: `0 0 8px ${c}80`, flexShrink: 0, marginTop: 2 }} />
                                                            {!isLast && <div style={{ width: 1, flex: 1, background: 'rgba(255,255,255,.07)', minHeight: 16 }} />}
                                                        </div>
                                                        <div style={{ paddingBottom: isLast ? 0 : 12 }}>
                                                            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: c, fontWeight: 600 }}>{node.name}</span>
                                                            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, color: 'rgba(53,64,96,.7)', padding: '1px 5px', borderRadius: 3, background: 'rgba(255,255,255,.04)', border: '1px solid rgba(255,255,255,.06)', marginLeft: 8 }}>{node.source}</span>
                                                            {node.user && <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, color: 'rgba(53,64,96,.5)', marginLeft: 6 }}>{node.user}</span>}
                                                        </div>
                                                    </div>
                                                )
                                            })}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {tab === 'chain' && (
                            <ProcessTree chain={chain} loading={chainLoading} error={chainError} />
                        )}

                        {tab === 'intel' && (
                            <IntelPanel entryType={type} entryId={id} entry={entry} />
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