// src/pages/Alerts.jsx
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
    fetchAlerts, fetchChain, fetchScore, fetchAllScores, fetchSignatures,
    scoreToSeverity, SCORE_LABEL, SCORE_COLOR,
} from '../api/client'
import { ProcessTree } from '../components/features/ProcessTree'

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

function ScoreBox({ score }) {
    const sev = scoreToSeverity(score)
    const color = sev ? SCORE_COLOR[sev] : 'rgba(106,117,144,0.9)'
    const bg = sev ? `${SCORE_COLOR[sev]}22` : 'rgba(255,255,255,0.04)'
    return (
        <div style={{
            minWidth: 32, height: 24,
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
            background: bg, border: `1px solid ${color}`,
            borderRadius: 4, padding: '0 6px',
            fontFamily: 'IBM Plex Mono', fontSize: 11, fontWeight: 700, color,
        }}>
            {score == null ? '—' : score}
        </div>
    )
}

function SeverityBadge({ score }) {
    const sev = scoreToSeverity(score)
    const color = sev ? SCORE_COLOR[sev] : null
    if (!sev) return null
    return (
        <span style={{
            fontFamily: 'IBM Plex Mono', fontSize: 8.5, fontWeight: 700,
            letterSpacing: '0.08em', textTransform: 'uppercase',
            padding: '2px 6px', borderRadius: 4,
            background: `${color}18`, color, border: `1px solid ${color}40`,
            whiteSpace: 'nowrap',
        }}>
            {SCORE_LABEL[sev]}
        </span>
    )
}

function TypeBadge({ entryType, iocNotes }) {
    const b = getTypeBadge(entryType, iocNotes)
    return (
        <span style={{
            fontFamily: 'IBM Plex Mono', fontSize: 9.5, fontWeight: 600,
            letterSpacing: '0.04em', textTransform: 'uppercase',
            padding: '2px 7px', borderRadius: 4,
            background: b.bg, color: b.color, border: `1px solid ${b.border}`,
            whiteSpace: 'nowrap',
        }}>
            {b.label}
        </span>
    )
}

function buildChainSummary(alert) {
    if (alert.chain_summary) return alert.chain_summary
    if (alert.overall_verdict) return `verdict: ${alert.overall_verdict}`
    if (alert.ioc_notes) return alert.ioc_notes
    return ''
}

// ── List item ─────────────────────────────────────────────────────────────────

function EntryListItem({ alert, score, active, onClick, index }) {
    const name = alert.name || alert.task_name || alert.service_name || '?'
    const path = alert.value_data || alert.command || alert.binary_path || alert.reg_path || ''
    const chain = buildChainSummary(alert)
    const sev = scoreToSeverity(score)
    const borderColor = sev ? SCORE_COLOR[sev] : 'var(--text-muted)'

    return (
        <div
            onClick={onClick}
            className={`stagger-${Math.min((index || 0) + 1, 5)}`}
            style={{
                padding: '10px 14px',
                borderLeft: `3px solid ${active ? 'var(--cyan)' : borderColor}`,
                borderBottom: '1px solid var(--bg-border)',
                background: active ? 'rgba(0,212,255,0.05)' : 'transparent',
                cursor: 'pointer', transition: 'background 0.1s',
            }}
            onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'rgba(255,255,255,0.025)' }}
            onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent' }}
        >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <span style={{
                    fontFamily: 'Inter', fontSize: 13, fontWeight: 600, color: 'var(--text-primary)',
                    flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                    {name}
                </span>
                <ScoreBox score={score} />
                <TypeBadge entryType={alert.entry_type} iocNotes={alert.ioc_notes} />
            </div>
            <div style={{
                fontFamily: 'IBM Plex Mono', fontSize: 10, color: 'var(--text-muted)',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                marginBottom: chain ? 3 : 0,
            }}>
                {path.slice(0, 55) || '—'}
            </div>
            {chain && (
                <div style={{
                    fontFamily: 'IBM Plex Mono', fontSize: 10,
                    color: 'var(--cyan)', opacity: 0.8,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                    {chain.slice(0, 60)}
                </div>
            )}
        </div>
    )
}

// ── Detail panel ──────────────────────────────────────────────────────────────

function TechBadge({ id, name }) {
    return (
        <span title={name} style={{
            fontFamily: 'IBM Plex Mono', fontSize: 10, fontWeight: 600,
            padding: '2px 8px', borderRadius: 4,
            background: 'rgba(168,85,247,0.12)', color: '#a855f7',
            border: '1px solid rgba(168,85,247,0.3)',
        }}>
            {id}
        </span>
    )
}

function AlertDetail({ alert }) {
    const navigate = useNavigate()
    const [tab, setTab] = useState('chain')

    const { data: chainData, isLoading: chainLoading } = useQuery({
        queryKey: ['chain', alert?.entry_type, alert?.id],
        queryFn: () => fetchChain(alert.entry_type, alert.id),
        enabled: !!alert,
    })

    const { data: scoreData } = useQuery({
        queryKey: ['score', alert?.entry_type, alert?.id],
        queryFn: () => fetchScore(alert.entry_type, alert.id),
        enabled: !!alert,
        retry: 1,
    })

    const { data: sigData } = useQuery({
        queryKey: ['signatures'],
        queryFn: () => fetchSignatures({ exe_only: true }),
        staleTime: 5 * 60 * 1000,
        enabled: alert?.entry_type === 'service',
    })

    if (!alert) return (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
            <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 32, opacity: 0.12, marginBottom: 12 }}>◈</div>
                <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 12 }}>Select an entry to inspect</div>
                <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 10, opacity: 0.5, marginTop: 4 }}>Click any entry on the left</div>
            </div>
        </div>
    )

    const name = alert.name || alert.task_name || alert.service_name || '?'
    const value = alert.value_data || alert.command || alert.binary_path || ''
    const techniques = alert.techniques || []
    const score = scoreData?.score ?? null
    const chain = chainData?.chain || []
    const chainLine = chain.length > 0 ? chain.map(n => n.name).join(' → ') : (alert.ioc_notes || '')

    const sigEntry = alert.entry_type === 'service'
        ? (sigData?.results || []).find(r => r.service_name?.toLowerCase() === name?.toLowerCase())
        : null

    const decodedPS = (() => {
        const m = (value || '').match(/-(?:EncodedCommand|enc?)\s+([A-Za-z0-9+/=]{8,})/i)
        if (!m) return null
        try {
            const b64 = m[1].trim().padEnd(m[1].length + (4 - m[1].length % 4) % 4, '=')
            const raw = atob(b64)
            let str = ''
            for (let i = 0; i < raw.length - 1; i += 2)
                str += String.fromCharCode(raw.charCodeAt(i) | (raw.charCodeAt(i + 1) << 8))
            return str.trim() || null
        } catch { return null }
    })()

    const anomalies = []
    if (chain.some(n => n.type === 'malicious')) anomalies.push('malicious_writer')
    const hasLolbin = chain.some(n =>
        ['powershell.exe', 'cmd.exe', 'reg.exe', 'rundll32.exe', 'mshta.exe'].includes(n.name?.toLowerCase())
    )
    if (hasLolbin && chain.length >= 2) anomalies.push('lolbin_chain')
    if (alert.ioc_notes?.includes('suspicious')) anomalies.push('suspicious_path')
    const iocLower = (alert.ioc_notes || '').toLowerCase()
    if (iocLower.includes('ifeo') || iocLower.includes('debugger')) anomalies.push('ifeo_accessibility_hijack')
    if (iocLower.includes('run key')) anomalies.push('autorun_key')

    const tabs = [
        { key: 'summary', label: 'Summary' },
        { key: 'chain', label: 'Attack Chain', count: chain.length },
        { key: 'intel', label: 'Intel', count: (scoreData?.risk_indicators || []).length },
        { key: 'details', label: 'Details' },
    ]

    return (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', animation: 'fadeIn 0.15s ease-out' }}>

            <div style={{ padding: '14px 20px 12px', borderBottom: '1px solid var(--bg-border)', flexShrink: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6, flexWrap: 'wrap' }}>
                    <ScoreBox score={score} />
                    <SeverityBadge score={score} />
                    <span style={{ fontFamily: 'Inter', fontSize: 20, fontWeight: 700, color: 'var(--text-primary)' }}>
                        {name}
                    </span>
                    <TypeBadge entryType={alert.entry_type} iocNotes={alert.ioc_notes} />
                    {techniques.map(t => <TechBadge key={t.id} id={t.id} name={t.name} />)}
                </div>
                <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 11, color: 'var(--text-muted)', display: 'flex', gap: 20, flexWrap: 'wrap' }}>
                    <span>Source: <strong style={{ color: 'var(--text-secondary)' }}>
                        {chain[0]?.source?.toUpperCase() || (alert.entry_type === 'registry' ? 'REGISTRY' : 'SYSMON')}
                    </strong></span>
                    <span>User: <strong style={{ color: 'var(--text-secondary)' }}>
                        {chain[0]?.user || chain[chain.length - 1]?.user || 'Unknown'}
                    </strong></span>
                    {alert.last_seen && (
                        <span>Seen: <strong style={{ color: 'var(--text-secondary)' }}>
                            {new Date(alert.last_seen).toLocaleString()}
                        </strong></span>
                    )}
                    {chain.length > 0 && (
                        <span>Depth: <strong style={{ color: 'var(--cyan)' }}>{chain.length} hops</strong></span>
                    )}
                </div>
            </div>

            {chainLine && (
                <div style={{
                    padding: '8px 20px', fontFamily: 'IBM Plex Mono', fontSize: 11,
                    borderBottom: '1px solid var(--bg-border)', background: 'rgba(0,212,255,0.02)',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                    <span style={{ color: 'var(--text-muted)', marginRight: 6 }}>CHAIN:</span>
                    <span style={{ color: 'var(--cyan)' }}>{chainLine}</span>
                </div>
            )}

            {anomalies.length > 0 && (
                <div style={{
                    padding: '8px 20px', background: 'rgba(255,53,96,0.05)',
                    borderBottom: '1px solid rgba(255,53,96,0.2)', borderLeft: '3px solid var(--red)',
                }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
                        <span style={{ color: 'var(--red)', fontWeight: 700, fontSize: 13 }}>!!</span>
                        <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 10.5, fontWeight: 600, color: 'var(--red)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                            Behavioral Anomalies Detected In Chain
                        </span>
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {anomalies.map(a => (
                            <span key={a} style={{
                                fontFamily: 'IBM Plex Mono', fontSize: 9.5, padding: '2px 8px', borderRadius: 4,
                                background: 'rgba(255,53,96,0.12)', color: 'var(--red)', border: '1px solid rgba(255,53,96,0.3)',
                            }}>{a}</span>
                        ))}
                    </div>
                </div>
            )}

            <div style={{ display: 'flex', borderBottom: '1px solid var(--bg-border)', flexShrink: 0, background: 'var(--bg-surface)' }}>
                {tabs.map(t => (
                    <button key={t.key} onClick={() => setTab(t.key)} style={{
                        fontFamily: 'IBM Plex Mono', fontSize: 10.5, fontWeight: 500,
                        letterSpacing: '0.08em', textTransform: 'uppercase', padding: '9px 16px',
                        borderBottom: `2px solid ${tab === t.key ? 'var(--cyan)' : 'transparent'}`,
                        color: tab === t.key ? 'var(--cyan)' : 'var(--text-muted)',
                        background: tab === t.key ? 'rgba(0,212,255,0.03)' : 'transparent',
                        cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 5,
                        transition: 'color 0.12s, border-color 0.12s',
                    }}>
                        {t.label}
                        {t.count != null && t.count > 0 && (
                            <span style={{
                                fontFamily: 'IBM Plex Mono', fontSize: 9, padding: '1px 5px', borderRadius: 3,
                                background: tab === t.key ? 'rgba(0,212,255,0.15)' : 'var(--bg-raised)',
                                color: tab === t.key ? 'var(--cyan)' : 'var(--text-muted)',
                                border: `1px solid ${tab === t.key ? 'rgba(0,212,255,0.3)' : 'var(--bg-border)'}`,
                            }}>{t.count}</span>
                        )}
                    </button>
                ))}
            </div>

            <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px' }}>

                {tab === 'summary' && (
                    <div style={{ maxWidth: 720, display: 'flex', flexDirection: 'column', gap: 14 }}>
                        <style>{`
                            @keyframes rh-al-in{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
                            @keyframes rh-al-scan{0%{left:-60%}100%{left:160%}}
                            @keyframes rh-al-pip{0%,100%{box-shadow:0 0 4px currentColor}50%{box-shadow:0 0 14px currentColor,0 0 28px currentColor}}
                            .rh-al-card{border-radius:12px;overflow:hidden;position:relative;transition:transform .2s,box-shadow .2s;}
                            .rh-al-card:hover{transform:translateY(-2px);}
                            .rh-al-shimmer{position:absolute;top:0;left:-60%;width:60%;height:100%;background:linear-gradient(90deg,transparent,rgba(255,255,255,.04),transparent);animation:rh-al-scan 3s ease-in-out infinite;pointer-events:none;}
                        `}</style>

                        {/* ── Hero threat card ── */}
                        <div className="rh-al-card" style={{
                            background: `linear-gradient(135deg,${score >= 80 ? 'rgba(255,32,85,.12)' : score >= 60 ? 'rgba(255,119,34,.1)' : 'rgba(255,214,10,.08)'} 0%,rgba(15,19,32,.95) 100%)`,
                            border: `1px solid ${score >= 80 ? 'rgba(255,32,85,.3)' : score >= 60 ? 'rgba(255,119,34,.25)' : 'rgba(255,214,10,.2)'}`,
                            boxShadow: `0 8px 32px ${score >= 80 ? 'rgba(255,32,85,.08)' : score >= 60 ? 'rgba(255,119,34,.06)' : 'rgba(255,214,10,.04)'}`,
                            padding: '20px 22px',
                            animation: 'rh-al-in .35s cubic-bezier(.16,1,.3,1)',
                        }}>
                            <div className="rh-al-shimmer" />
                            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
                                <div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                                        <div style={{ width: 8, height: 8, borderRadius: '50%', background: score >= 80 ? '#ff2055' : score >= 60 ? '#ff7722' : '#ffd60a', animation: 'rh-al-pip 1.8s ease-in-out infinite', color: score >= 80 ? '#ff2055' : score >= 60 ? '#ff7722' : '#ffd60a' }} />
                                        <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 10, fontWeight: 700, letterSpacing: '.16em', textTransform: 'uppercase', color: score >= 80 ? '#ff2055' : score >= 60 ? '#ff7722' : '#ffd60a' }}>
                                            {alert.severity} persistence
                                        </span>
                                    </div>
                                    <div style={{ fontFamily: 'Inter', fontSize: 22, fontWeight: 700, color: 'rgba(238,242,255,.97)', letterSpacing: '-.01em', marginBottom: 4 }}>{name}</div>
                                    <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 10, color: 'rgba(90,107,138,1)' }}>{alert.entry_type} · {chain.length} hop chain</div>
                                </div>
                                {score != null && (
                                    <div style={{ textAlign: 'center', flexShrink: 0 }}>
                                        <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 36, fontWeight: 700, lineHeight: 1, color: score >= 80 ? '#ff2055' : score >= 60 ? '#ff7722' : '#ffd60a', textShadow: `0 0 30px ${score >= 80 ? 'rgba(255,32,85,.4)' : score >= 60 ? 'rgba(255,119,34,.3)' : 'rgba(255,214,10,.3)'}` }}>{score}</div>
                                        <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 8, color: 'rgba(53,64,96,.8)', textTransform: 'uppercase', letterSpacing: '.1em', marginTop: 2 }}>threat score</div>
                                    </div>
                                )}
                            </div>
                            {score != null && (
                                <div style={{ marginBottom: 14 }}>
                                    <div style={{ height: 3, background: 'rgba(255,255,255,.05)', borderRadius: 3, overflow: 'hidden' }}>
                                        <div style={{ height: '100%', borderRadius: 3, width: `${score}%`, background: score >= 80 ? 'linear-gradient(90deg,#ff2055,#ff6b8a)' : score >= 60 ? 'linear-gradient(90deg,#ff7722,#ffaa55)' : 'linear-gradient(90deg,#ffd60a,#ffe87a)', boxShadow: `0 0 8px ${score >= 80 ? '#ff2055' : score >= 60 ? '#ff7722' : '#ffd60a'}60`, transition: 'width 1s cubic-bezier(.16,1,.3,1)' }} />
                                    </div>
                                </div>
                            )}
                            <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap' }}>
                                {[['User', chain[0]?.user || 'Unknown'], ['Source', chain[0]?.source?.toUpperCase() || 'STUB'], ['Seen', alert.last_seen ? new Date(alert.last_seen).toLocaleString() : '—'], ['Depth', `${chain.length} hops`]].map(([k, v]) => (
                                    <div key={k}>
                                        <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 8, color: 'rgba(53,64,96,.7)', textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 2 }}>{k}</div>
                                        <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 10, color: 'rgba(192,200,224,.9)' }}>{v}</div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* ── Anomalies ── */}
                        {anomalies.length > 0 && (
                            <div className="rh-al-card" style={{ background: 'rgba(255,32,85,.06)', border: '1px solid rgba(255,32,85,.25)', padding: '14px 18px', animation: 'rh-al-in .35s cubic-bezier(.16,1,.3,1) .04s both' }}>
                                <div className="rh-al-shimmer" style={{ background: 'linear-gradient(90deg,transparent,rgba(255,32,85,.06),transparent)' }} />
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#ff2055" strokeWidth="2.5" strokeLinecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
                                    <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 9, fontWeight: 700, letterSpacing: '.14em', textTransform: 'uppercase', color: '#ff2055' }}>Behavioral Anomalies</span>
                                </div>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7 }}>
                                    {anomalies.map((a, i) => (
                                        <span key={a} style={{ fontFamily: 'IBM Plex Mono', fontSize: 9, padding: '4px 10px', borderRadius: 5, background: 'rgba(255,32,85,.12)', color: '#ff2055', border: '1px solid rgba(255,32,85,.3)', animation: `rh-al-in .25s ease ${i * .05}s both` }}>
                                            {a.replace(/_/g, ' ')}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* ── Two-col: signature + decoded PS ── */}
                        <div style={{ display: 'grid', gridTemplateColumns: alert.entry_type === 'service' || decodedPS ? (alert.entry_type === 'service' && decodedPS ? '1fr 1fr' : '1fr 1fr') : '1fr', gap: 14 }}>
                            {alert.entry_type === 'service' && (
                                <div className="rh-al-card" style={{ background: 'rgba(13,17,30,.95)', padding: '16px 18px', border: `1px solid ${sigEntry?.sig_status === 'Valid' ? 'rgba(0,230,118,.2)' : sigEntry?.sig_status === 'NotSigned' ? 'rgba(255,32,85,.25)' : 'rgba(255,255,255,.07)'}`, animation: 'rh-al-in .35s cubic-bezier(.16,1,.3,1) .08s both' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 12 }}>
                                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={sigEntry?.sig_status === 'Valid' ? '#00e676' : '#ff2055'} strokeWidth="2" strokeLinecap="round">
                                            {sigEntry?.sig_status === 'Valid' ? <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><polyline points="9 12 11 14 15 10" /></> : <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><line x1="9" y1="9" x2="15" y2="15" /><line x1="15" y1="9" x2="9" y2="15" /></>}
                                        </svg>
                                        <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 8, fontWeight: 700, letterSpacing: '.14em', textTransform: 'uppercase', color: 'rgba(53,64,96,.85)' }}>Binary Signature</span>
                                    </div>
                                    {sigEntry ? (<>
                                        <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 12, fontWeight: 700, color: sigEntry.sig_status === 'Valid' ? '#00e676' : '#ff2055', marginBottom: 8 }}>
                                            {sigEntry.sig_status === 'Valid' ? `✅ Signed` : sigEntry.sig_status === 'NotSigned' ? '❌ Unsigned' : sigEntry.sig_status === 'Missing' ? '👻 Missing' : sigEntry.sig_status}
                                        </div>
                                        {sigEntry.signer && <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 9, color: 'rgba(140,155,175,1)', marginBottom: 4 }}>{sigEntry.signer}</div>}
                                        {sigEntry.suspicious_path && <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 9, color: '#ffd60a', marginBottom: 4 }}>⚠ Suspicious path</div>}
                                        {sigEntry.sha256 && <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 8, color: 'rgba(53,64,96,.6)', wordBreak: 'break-all', marginBottom: 8 }}>{sigEntry.sha256.slice(0, 32)}…</div>}
                                        {sigEntry.vt_url && <a href={sigEntry.vt_url} target="_blank" rel="noopener noreferrer" style={{ fontFamily: 'IBM Plex Mono', fontSize: 9, color: '#00e5ff' }}>VirusTotal →</a>}
                                    </>) : <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 10, color: 'rgba(90,107,138,1)' }}>No data — POST /api/signatures/run</div>}
                                </div>
                            )}
                            {decodedPS && (
                                <div className="rh-al-card" style={{ background: 'rgba(0,229,255,.04)', padding: '16px 18px', border: '1px solid rgba(0,229,255,.2)', boxShadow: '0 4px 24px rgba(0,229,255,.05)', animation: 'rh-al-in .35s cubic-bezier(.16,1,.3,1) .1s both' }}>
                                    <div className="rh-al-shimmer" style={{ background: 'linear-gradient(90deg,transparent,rgba(0,229,255,.06),transparent)' }} />
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 12 }}>
                                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#00e5ff" strokeWidth="2.5" strokeLinecap="round"><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0110 0v4" /></svg>
                                        <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 8, fontWeight: 700, letterSpacing: '.14em', textTransform: 'uppercase', color: '#00e5ff' }}>Decoded Payload</span>
                                    </div>
                                    <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 10, color: '#00e5ff', lineHeight: 1.8, wordBreak: 'break-all', whiteSpace: 'pre-wrap', opacity: .9 }}>
                                        {decodedPS.length > 300 ? decodedPS.slice(0, 300) + '…' : decodedPS}
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* ── IOC notes ── */}
                        {alert.ioc_notes && alert.ioc_notes.toLowerCase() !== 'none' && (
                            <div className="rh-al-card" style={{ background: 'rgba(255,214,10,.04)', padding: '14px 18px', border: '1px solid rgba(255,214,10,.18)', animation: 'rh-al-in .35s cubic-bezier(.16,1,.3,1) .12s both' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 8 }}>
                                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#ffd60a" strokeWidth="2.5" strokeLinecap="round"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
                                    <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 8, fontWeight: 700, letterSpacing: '.14em', textTransform: 'uppercase', color: '#ffd60a' }}>IOC Notes</span>
                                </div>
                                <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 11, color: 'rgba(192,200,224,.9)', lineHeight: 1.7 }}>{alert.ioc_notes}</div>
                            </div>
                        )}

                        {/* ── MITRE ── */}
                        {techniques.length > 0 && (
                            <div className="rh-al-card" style={{ background: 'rgba(196,112,255,.04)', padding: '14px 18px', border: '1px solid rgba(196,112,255,.15)', animation: 'rh-al-in .35s cubic-bezier(.16,1,.3,1) .14s both' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 10 }}>
                                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#c470ff" strokeWidth="2" strokeLinecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
                                    <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 8, fontWeight: 700, letterSpacing: '.14em', textTransform: 'uppercase', color: '#c470ff' }}>MITRE ATT&CK</span>
                                </div>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7 }}>
                                    {techniques.map((t, i) => (
                                        <span key={t.id || t} title={t.name} style={{ fontFamily: 'IBM Plex Mono', fontSize: 9, padding: '4px 10px', borderRadius: 5, background: 'rgba(196,112,255,.12)', color: '#c470ff', border: '1px solid rgba(196,112,255,.3)', animation: `rh-al-in .25s ease ${i * .05 + .14}s both`, cursor: 'default' }}>
                                            {t.id || t}{t.name && <span style={{ color: 'rgba(196,112,255,.55)', marginLeft: 6, fontWeight: 400 }}>— {t.name}</span>}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* ── Chain visual ── */}
                        {chain.length > 0 && (
                            <div className="rh-al-card" style={{ background: 'rgba(13,17,30,.95)', padding: '16px 18px', border: '1px solid rgba(255,255,255,.07)', animation: 'rh-al-in .35s cubic-bezier(.16,1,.3,1) .16s both' }}>
                                <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 8, fontWeight: 700, letterSpacing: '.14em', textTransform: 'uppercase', color: 'rgba(53,64,96,.85)', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 7 }}>
                                    <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg>
                                    Attack Chain
                                </div>
                                <div style={{ display: 'flex', flexDirection: 'column' }}>
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
                                                    <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 11, color: c, fontWeight: 600 }}>{node.name}</span>
                                                    <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 8, color: 'rgba(53,64,96,.7)', padding: '1px 5px', borderRadius: 3, background: 'rgba(255,255,255,.04)', border: '1px solid rgba(255,255,255,.06)', marginLeft: 8 }}>{node.source}</span>
                                                </div>
                                            </div>
                                        )
                                    })}
                                </div>
                            </div>
                        )}

                        {/* ── View full button ── */}
                        <button onClick={() => navigate(`/entries/${alert.entry_type}/${alert.id}`)}
                            style={{ alignSelf: 'flex-start', display: 'inline-flex', alignItems: 'center', gap: 6, fontFamily: 'IBM Plex Mono', fontSize: 11, fontWeight: 600, letterSpacing: '.08em', textTransform: 'uppercase', padding: '8px 16px', borderRadius: 6, border: '1px solid rgba(0,212,255,.4)', color: 'var(--cyan)', background: 'rgba(0,212,255,.06)', cursor: 'pointer' }}>
                            View Full Entry →
                        </button>
                    </div>
                )}

                {tab === 'chain' && <ProcessTree chain={chain} loading={chainLoading} error={null} />}

                {tab === 'intel' && (
                    <div style={{ maxWidth: 560 }}>
                        {(scoreData?.risk_indicators || []).length === 0 ? (
                            <div style={{ textAlign: 'center', padding: '48px 0', color: 'var(--text-muted)', fontFamily: 'IBM Plex Mono', fontSize: 12 }}>
                                No risk indicators — run threat scorer to generate signals.
                            </div>
                        ) : (
                            (scoreData?.risk_indicators || []).map((ind, i) => {
                                const c = ind.severity === 'critical' ? 'var(--red)' : ind.severity === 'high' ? 'var(--orange)' : 'var(--yellow)'
                                return (
                                    <div key={i} style={{
                                        padding: '12px 14px', marginBottom: 8, borderRadius: 9,
                                        background: 'rgba(15,19,32,.9)', border: '1px solid rgba(255,255,255,.07)',
                                        borderLeft: `3px solid ${c}`,
                                        opacity: 0, transform: 'translateX(-8px)',
                                        animation: `nip-in .28s cubic-bezier(.16,1,.3,1) ${i * 0.05}s forwards`,
                                    }}>
                                        <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.12em', color: c, marginBottom: 5, display: 'flex', alignItems: 'center', gap: 7 }}>
                                            <div style={{ width: 4, height: 4, borderRadius: '50%', background: c, boxShadow: `0 0 6px ${c}` }} />
                                            {ind.type?.replace(/_/g, ' ') || 'risk'}
                                        </div>
                                        <div style={{ fontSize: 11, color: 'rgba(140,155,175,1)', lineHeight: 1.55 }}>{ind.description}</div>
                                    </div>
                                )
                            })
                        )}
                        <style>{`@keyframes nip-in{to{opacity:1;transform:translateX(0)}}`}</style>
                    </div>
                )}

                {tab === 'details' && (
                    <div style={{ maxWidth: 600 }}>
                        {[
                            ['Name', name, true],
                            ['Path / Value', value, true],
                            ['Type', alert.entry_type, false],
                            ['IOC Notes', alert.ioc_notes, false],
                            ['Seen', alert.last_seen?.slice(0, 19), false],
                        ].map(([label, val, mono]) => val ? (
                            <div key={label} style={{ display: 'flex', gap: 16, padding: '8px 0', borderBottom: '1px solid var(--bg-border)' }}>
                                <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 10.5, color: 'var(--text-muted)', width: 90, flexShrink: 0 }}>{label}</span>
                                <span style={{ fontFamily: mono ? 'IBM Plex Mono' : 'Inter', fontSize: 11.5, color: 'var(--text-secondary)', wordBreak: 'break-all' }}>{val}</span>
                            </div>
                        ) : null)}
                        <div style={{ marginTop: 16 }}>
                            <button
                                onClick={() => navigate(`/entries/${alert.entry_type}/${alert.id}`)}
                                style={{
                                    display: 'inline-flex', alignItems: 'center', gap: 6,
                                    fontFamily: 'IBM Plex Mono', fontSize: 11, fontWeight: 600,
                                    letterSpacing: '0.08em', textTransform: 'uppercase',
                                    padding: '8px 16px', borderRadius: 6,
                                    border: '1px solid rgba(0,212,255,0.4)', color: 'var(--cyan)',
                                    background: 'rgba(0,212,255,0.06)', cursor: 'pointer',
                                }}
                            >
                                View Full Details →
                            </button>
                        </div>
                    </div>
                )}

                {tab === 'intel' && (
                    <div style={{ maxWidth: 560 }}>
                        <div style={{
                            padding: '12px 14px', borderRadius: 10, marginBottom: 12,
                            background: 'rgba(15,19,32,.9)', border: '1px solid rgba(255,255,255,.07)',
                        }}>
                            <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 9, fontWeight: 700, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 10 }}>
                                Enrichment Snapshot
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontFamily: 'IBM Plex Mono', fontSize: 11 }}>
                                <div>
                                    <div style={{ fontSize: 9, color: 'var(--text-muted)', marginBottom: 3 }}>VirusTotal</div>
                                    <div style={{ color: (alert.vt_malicious || 0) > 0 ? 'var(--red)' : 'var(--green)' }}>
                                        {(alert.vt_total || 0) > 0 ? `${alert.vt_malicious || 0}/${alert.vt_total || 0} detections` : '—'}
                                    </div>
                                </div>
                                <div>
                                    <div style={{ fontSize: 9, color: 'var(--text-muted)', marginBottom: 3 }}>Verdict</div>
                                    <div style={{ color: alert.overall_verdict === 'malicious' ? 'var(--red)' : alert.overall_verdict === 'suspicious' ? 'var(--yellow)' : alert.overall_verdict === 'clean' ? 'var(--green)' : 'var(--text-secondary)' }}>
                                        {(alert.overall_verdict || 'unknown').toUpperCase()}
                                    </div>
                                </div>
                                <div>
                                    <div style={{ fontSize: 9, color: 'var(--text-muted)', marginBottom: 3 }}>Signed</div>
                                    <div style={{ color: alert.pe_signed ? 'var(--green)' : 'var(--red)' }}>
                                        {alert.pe_signed == null ? '—' : (alert.pe_signed ? 'Yes' : 'No')}
                                    </div>
                                </div>
                                <div>
                                    <div style={{ fontSize: 9, color: 'var(--text-muted)', marginBottom: 3 }}>Compile Time</div>
                                    <div style={{ color: alert.pe_compile_suspicious ? 'var(--red)' : 'var(--text-secondary)' }}>
                                        {alert.pe_compile_suspicious ? 'Suspicious' : 'Normal/Unknown'}
                                    </div>
                                </div>
                            </div>
                        </div>
                        {(alert.enrich_indicators || []).length === 0 ? (
                            <div style={{ textAlign: 'center', padding: '48px 0', color: 'var(--text-muted)', fontFamily: 'IBM Plex Mono', fontSize: 12 }}>
                                No enrichment risk indicators for this entry.
                            </div>
                        ) : (
                            (alert.enrich_indicators || []).map((ind, i) => {
                                const c = ind.severity === 'critical' ? 'var(--red)' : ind.severity === 'high' ? 'var(--orange)' : 'var(--yellow)'
                                return (
                                    <div key={i} style={{
                                        padding: '12px 14px', marginBottom: 8, borderRadius: 9,
                                        background: 'rgba(15,19,32,.9)', border: '1px solid rgba(255,255,255,.07)',
                                        borderLeft: `3px solid ${c}`,
                                        opacity: 0, transform: 'translateX(-8px)',
                                        animation: `nip-in .28s cubic-bezier(.16,1,.3,1) ${i * 0.05}s forwards`,
                                    }}>
                                        <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.12em', color: c, marginBottom: 5, display: 'flex', alignItems: 'center', gap: 7 }}>
                                            <div style={{ width: 4, height: 4, borderRadius: '50%', background: c, boxShadow: `0 0 6px ${c}` }} />
                                            {ind.type?.replace(/_/g, ' ') || 'risk'}
                                        </div>
                                        <div style={{ fontSize: 11, color: 'rgba(140,155,175,1)', lineHeight: 1.55 }}>{ind.description}</div>
                                    </div>
                                )
                            })
                        )}
                        <style>{`@keyframes nip-in{to{opacity:1;transform:translateX(0)}}`}</style>
                    </div>
                )}
            </div>
        </div>
    )
}

// ── Main Alerts page ──────────────────────────────────────────────────────────

export function Alerts() {
    const [selected, setSelected] = useState(null)
    const [search, setSearch] = useState('')

    const { data, isLoading } = useQuery({
        queryKey: ['alerts'],
        queryFn: () => fetchAlerts(500),
        refetchInterval: 30000,
    })

    // One bulk fetch — O(1) lookup per list item, no N+1 requests
    const { data: scoresMap } = useQuery({
        queryKey: ['scores-all'],
        queryFn: fetchAllScores,
        refetchInterval: 60000,
    })

    const alerts = data?.alerts || []
    const filtered = alerts.filter(a => {
        if (!search) return true
        const q = search.toLowerCase()
        return (
            (a.name || a.task_name || a.service_name || '').toLowerCase().includes(q) ||
            (a.value_data || a.command || a.binary_path || '').toLowerCase().includes(q)
        )
    })

    const selectedAlert = selected !== null ? filtered[selected] : null

    return (
        <div style={{ display: 'flex', height: '100%', overflow: 'hidden' }}>

            <div style={{
                width: 300, flexShrink: 0,
                background: 'var(--bg-surface)',
                borderRight: '1px solid var(--bg-border)',
                display: 'flex', flexDirection: 'column',
            }}>
                <div style={{ padding: '12px 14px 10px', borderBottom: '1px solid var(--bg-border)', flexShrink: 0 }}>
                    <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 9.5, fontWeight: 600, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>
                        Persistence Entries
                    </div>
                    <input
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                        placeholder="Search entries..."
                        style={{
                            width: '100%', boxSizing: 'border-box',
                            background: 'var(--bg-raised)', border: '1px solid var(--bg-border)',
                            borderRadius: 6, color: 'var(--text-primary)',
                            fontFamily: 'IBM Plex Mono', fontSize: 12, padding: '7px 12px',
                            outline: 'none', transition: 'border-color 0.15s',
                        }}
                        onFocus={e => e.target.style.borderColor = 'rgba(0,212,255,0.4)'}
                        onBlur={e => e.target.style.borderColor = 'var(--bg-border)'}
                    />
                </div>

                <div style={{ flex: 1, overflowY: 'auto' }}>
                    {isLoading ? (
                        <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}>
                            <div className="w-5 h-5 border-2 rounded-full animate-spin"
                                style={{ borderColor: 'var(--bg-border)', borderTopColor: 'var(--cyan)' }} />
                        </div>
                    ) : filtered.length === 0 ? (
                        <div style={{ textAlign: 'center', padding: 40, fontFamily: 'IBM Plex Mono', fontSize: 11, color: 'var(--text-muted)' }}>
                            No entries found
                        </div>
                    ) : (
                        filtered.map((alert, i) => {
                            const scoreEntry = scoresMap?.get(`${alert.entry_type}/${alert.id}`)
                            return (
                                <EntryListItem
                                    key={i} index={i}
                                    alert={alert}
                                    score={scoreEntry?.score ?? null}
                                    active={selected === i}
                                    onClick={() => setSelected(i)}
                                />
                            )
                        })
                    )}
                </div>

                <div style={{
                    padding: '8px 14px', borderTop: '1px solid var(--bg-border)',
                    display: 'flex', justifyContent: 'space-between', flexShrink: 0,
                    fontFamily: 'IBM Plex Mono', fontSize: 10, color: 'var(--text-muted)',
                }}>
                    <span>{filtered.length} entries</span>
                    <span style={{ color: 'var(--red)' }}>
                        {scoresMap
                            ? [...scoresMap.values()].filter(s => scoreToSeverity(s.score) === 'critical').length
                            : alerts.filter(a => a.severity === 'critical').length
                        } critical
                    </span>
                </div>
            </div>

            <AlertDetail alert={selectedAlert} />
        </div>
    )
}