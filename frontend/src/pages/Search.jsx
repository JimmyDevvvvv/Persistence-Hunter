// src/pages/Search.jsx
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { search } from '../api/client'

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

const PRESETS = [
    'powershell -enc', 'AppData\\Roaming', 'C:\\malware',
    'http://', 'schtasks', 'reg.exe', 'rundll32', 'mshta',
]

export function Search() {
    const navigate = useNavigate()
    const [query,   setQuery]   = useState('')
    const [results, setResults] = useState(null)
    const [loading, setLoading] = useState(false)
    const [error,   setError]   = useState(null)

    async function handleSearch(e) {
        e.preventDefault()
        if (!query.trim()) return
        setLoading(true)
        setError(null)
        try {
            const data = await search(query.trim())
            setResults(data)
        } catch {
            setError('Search failed')
        } finally {
            setLoading(false)
        }
    }

    return (
        <div className="space-y-6 animate-slide-up max-w-4xl">

            {/* ── Header ── */}
            <div>
                <h1 className="font-display text-3xl font-bold gradient-text"
                    style={{ letterSpacing: '0.04em' }}>
                    Threat Hunt
                </h1>
                <p className="font-mono text-[11px] mt-1" style={{ color: 'var(--text-muted)' }}>
                    Search across all persistence entries and process telemetry
                </p>
            </div>

            {/* ── Search box ── */}
            <form onSubmit={handleSearch}>
                <div className="flex gap-3">
                    <div className="flex-1 relative">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                            strokeWidth="2" strokeLinecap="round"
                            style={{
                                position: 'absolute', left: 13, top: '50%', transform: 'translateY(-50%)',
                                color: 'var(--text-muted)', pointerEvents: 'none',
                            }}>
                            <circle cx="11" cy="11" r="7" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
                        </svg>
                        <input
                            value={query}
                            onChange={e => setQuery(e.target.value)}
                            placeholder="Search process names, paths, command lines, hashes..."
                            className="input-field"
                            style={{ paddingLeft: 36, fontSize: 13, height: 44 }}
                        />
                    </div>
                    <button
                        type="submit"
                        disabled={loading || !query.trim()}
                        className="btn-glow"
                        style={{ height: 44, paddingLeft: 20, paddingRight: 20 }}
                    >
                        {loading ? (
                            <div className="w-4 h-4 rounded-full animate-spin"
                                style={{ border: '2px solid rgba(0,212,255,0.3)', borderTopColor: 'var(--cyan)' }} />
                        ) : (
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                                <circle cx="11" cy="11" r="7" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
                            </svg>
                        )}
                        Hunt
                    </button>
                </div>
            </form>

            {/* ── Preset queries ── */}
            <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-[10px] tracking-widest uppercase" style={{ color: 'var(--text-muted)' }}>
                    Quick:
                </span>
                {PRESETS.map(p => (
                    <button
                        key={p}
                        onClick={() => setQuery(p)}
                        className="font-mono text-[10px] px-2.5 py-1.5 rounded border transition-all"
                        style={{
                            borderColor: 'var(--bg-border)',
                            color: 'var(--text-muted)',
                            background: 'var(--bg-raised)',
                        }}
                        onMouseEnter={e => {
                            e.currentTarget.style.borderColor = 'rgba(0,212,255,0.3)'
                            e.currentTarget.style.color = 'var(--text-secondary)'
                            e.currentTarget.style.background = 'rgba(0,212,255,0.05)'
                        }}
                        onMouseLeave={e => {
                            e.currentTarget.style.borderColor = 'var(--bg-border)'
                            e.currentTarget.style.color = 'var(--text-muted)'
                            e.currentTarget.style.background = 'var(--bg-raised)'
                        }}
                    >
                        {p}
                    </button>
                ))}
            </div>

            {/* ── Error ── */}
            {error && (
                <div className="flex items-center gap-2 font-mono text-xs p-3 rounded"
                    style={{ background: 'rgba(255,53,96,0.08)', border: '1px solid rgba(255,53,96,0.25)', color: 'var(--red)' }}>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                        <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
                    </svg>
                    {error}
                </div>
            )}

            {/* ── Results ── */}
            {results && (
                <div className="space-y-4 animate-slide-up">
                    <div className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>
                        <span style={{ color: 'var(--cyan)' }}>{results.count}</span> persistence matches ·{' '}
                        <span style={{ color: 'var(--text-secondary)' }}>{results.proc_count}</span> process events
                    </div>

                    {/* Persistence matches */}
                    {results.results.length > 0 && (
                        <div className="panel">
                            <div className="panel-header">
                                <span className="panel-label">Persistence Matches</span>
                                <span className="font-mono text-[9px] px-1.5 py-0.5 rounded"
                                    style={{ background: 'rgba(0,212,255,0.08)', color: 'var(--cyan)', border: '1px solid rgba(0,212,255,0.2)' }}>
                                    {results.count}
                                </span>
                            </div>
                            <div>
                                {results.results.map((r, i) => (
                                    <div
                                        key={i}
                                        onClick={() => navigate(`/entries/${r.entry_type}/${r.id}`)}
                                        className={`flex items-center gap-3 px-5 py-2.5 cursor-pointer table-row stagger-${Math.min(i + 1, 5)}`}
                                        style={{ borderBottom: i < results.results.length - 1 ? '1px solid var(--bg-border)' : 'none' }}
                                    >
                                        <SevBadge severity={r.severity} />
                                        <span className="font-mono text-[10px] w-16 uppercase" style={{ color: 'var(--text-muted)' }}>{r.entry_type}</span>
                                        <span className="font-mono text-xs w-40 truncate" style={{ color: 'var(--text-primary)' }}>{r.name}</span>
                                        <span className="font-mono text-[10px] truncate flex-1" style={{ color: 'var(--text-muted)' }}>
                                            {r.value?.slice(0, 80)}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Process event hits */}
                    {results.proc_hits?.length > 0 && (
                        <div className="panel">
                            <div className="panel-header">
                                <span className="panel-label">Process Events</span>
                                <span className="font-mono text-[9px] px-1.5 py-0.5 rounded"
                                    style={{ background: 'rgba(255,255,255,0.04)', color: 'var(--text-muted)', border: '1px solid var(--bg-border)' }}>
                                    {results.proc_count}
                                </span>
                            </div>
                            <div>
                                {results.proc_hits.map((r, i) => (
                                    <div key={i} className="px-5 py-3"
                                        style={{ borderBottom: i < results.proc_hits.length - 1 ? '1px solid var(--bg-border)' : 'none' }}>
                                        <div className="flex items-center gap-3 mb-1">
                                            <span className="font-mono text-xs w-36 truncate" style={{ color: 'var(--text-secondary)' }}>
                                                {r.process_name}
                                            </span>
                                            <span className="font-mono text-[10px]" style={{ color: 'var(--text-muted)' }}>
                                                PID {r.pid}
                                            </span>
                                            <span className="font-mono text-[9px]" style={{ color: 'var(--text-muted)', opacity: 0.6 }}>
                                                {r.event_time?.slice(0, 19)}
                                            </span>
                                        </div>
                                        <div className="font-mono text-[10px] truncate" style={{ color: 'var(--text-muted)' }}>
                                            {r.command_line?.slice(0, 120)}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {results.count === 0 && results.proc_count === 0 && (
                        <div className="flex flex-col items-center justify-center py-16 gap-3"
                            style={{ color: 'var(--text-muted)' }}>
                            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" opacity="0.2">
                                <circle cx="11" cy="11" r="7" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
                            </svg>
                            <div className="text-center">
                                <div className="font-mono text-xs mb-1">No results found</div>
                                <div className="font-mono text-[10px]" style={{ opacity: 0.6 }}>for "{query}"</div>
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    )
}