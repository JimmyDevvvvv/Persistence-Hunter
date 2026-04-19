// src/components/layout/TopBar.jsx
import { useState, useEffect } from 'react'
import { triggerScan, fetchScanStatus } from '../../api/client'

function LiveClock() {
    const [time, setTime] = useState(new Date())
    useEffect(() => {
        const id = setInterval(() => setTime(new Date()), 1000)
        return () => clearInterval(id)
    }, [])
    return (
        <span className="font-mono text-[11px]" style={{ color: 'var(--text-muted)', letterSpacing: '0.05em' }}>
            {time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
        </span>
    )
}

export function TopBar({ onScanComplete }) {
    const [job, setJob] = useState(null)
    const [running, setRunning] = useState(false)

    async function handleScan() {
        if (running) return
        setRunning(true)
        try {
            const { job_id } = await triggerScan({
                hours: 24,
                entry_types: ['registry', 'task', 'service'],
                enrich: false,
            })
            setJob({ stage: 'Initializing...', progress: 0 })
            const interval = setInterval(async () => {
                const s = await fetchScanStatus(job_id)
                setJob({ stage: s.stage, progress: s.progress })
                if (s.status === 'done' || s.status === 'error') {
                    clearInterval(interval)
                    setRunning(false)
                    onScanComplete?.()
                    setTimeout(() => setJob(null), 3000)
                }
            }, 1500)
        } catch {
            setRunning(false)
        }
    }

    return (
        <header
            className="flex items-center px-5 shrink-0 animate-fade-in"
            style={{
                height: 48,
                background: 'var(--bg-surface)',
                borderBottom: '1px solid var(--bg-border)',
                position: 'relative',
            }}
        >
            {/* Animated bottom border glow */}
            <div style={{
                position: 'absolute', bottom: -1, left: 0, right: 0, height: 1,
                background: 'linear-gradient(90deg, transparent, rgba(0,212,255,0.3), transparent)',
                backgroundSize: '200% 100%',
                animation: 'slide-gradient 4s infinite linear',
            }} />
            {/* ── Brand ── */}
            <div className="flex items-center gap-3 flex-1">
                <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full animate-pulse"
                        style={{ background: 'var(--red)', boxShadow: '0 0 6px var(--red)' }} />
                    <span className="font-mono font-bold text-sm tracking-widest"
                        style={{ color: 'var(--cyan)', letterSpacing: '0.15em' }}>
                        PERSISTENCE
                    </span>
                    <span className="font-mono font-bold text-sm tracking-widest"
                        style={{ color: 'var(--text-secondary)', letterSpacing: '0.15em' }}>
                        HUNTER
                    </span>
                    <span style={{ color: 'var(--bg-border)', margin: '0 6px' }}>|</span>
                    <span className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>
                        Attack Chain Visualizer
                    </span>
                </div>

                {/* Scan progress */}
                {job && (
                    <div className="flex items-center gap-3 ml-4 animate-fade-in">
                        <div className="w-3 h-3 border-2 rounded-full animate-spin"
                            style={{ borderColor: 'var(--bg-border)', borderTopColor: 'var(--cyan)' }} />
                        <span className="font-mono text-[11px]" style={{ color: 'var(--cyan)' }}>{job.stage}</span>
                        <div className="w-20 h-0.5 rounded-full overflow-hidden" style={{ background: 'var(--bg-border)' }}>
                            <div className="h-full rounded-full transition-all duration-500"
                                style={{ width: `${job.progress}%`, background: 'var(--cyan)' }} />
                        </div>
                        <span className="font-mono text-[10px]" style={{ color: 'var(--text-muted)' }}>{job.progress}%</span>
                    </div>
                )}
            </div>

            {/* ── Right ── */}
            <div className="flex items-center gap-3">
                <LiveClock />
                <div style={{ width: 1, height: 16, background: 'var(--bg-border)' }} />
                <button
                    onClick={handleScan}
                    disabled={running}
                    className="btn-glow"
                    style={{ paddingLeft: 20, paddingRight: 20, height: 32 }}
                >
                    {running ? (
                        <div className="w-3 h-3 rounded-full animate-spin"
                            style={{ border: '1.5px solid rgba(0,212,255,0.3)', borderTopColor: 'var(--cyan)' }} />
                    ) : (
                        <svg width="9" height="9" viewBox="0 0 24 24" fill="currentColor">
                            <polygon points="5,3 19,12 5,21" />
                        </svg>
                    )}
                    {running ? 'Scanning' : 'Scan'}
                </button>
            </div>
        </header>
    )
}