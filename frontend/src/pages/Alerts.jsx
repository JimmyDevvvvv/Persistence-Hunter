// src/pages/Alerts.jsx
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
    fetchAlerts, fetchChain, fetchScore, fetchAllScores,
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
        { key: 'chain', label: 'Attack Chain', count: chain.length },
        { key: 'intel', label: 'Intel', count: (alert.enrich_indicators || []).length },
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
                {tab === 'chain' && <ProcessTree chain={chain} loading={chainLoading} error={null} />}

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