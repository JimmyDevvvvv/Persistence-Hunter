// src/pages/Dashboard.jsx
// Animated dashboard with donut chart, particle bg, animated stats
import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { fetchStats, fetchAlerts } from '../api/client'

// ── Animated counter ──────────────────────────────────────────
function useCountUp(target, duration = 1000) {
    const [val, setVal] = useState(0)
    const started = useRef(false)
    useEffect(() => {
        if (started.current || typeof target !== 'number') return
        started.current = true
        const start = performance.now()
        const tick = (now) => {
            const p = Math.min((now - start) / duration, 1)
            const e = 1 - Math.pow(1 - p, 4)
            setVal(Math.round(e * target))
            if (p < 1) requestAnimationFrame(tick)
        }
        requestAnimationFrame(tick)
    }, [target, duration])
    return typeof target === 'number' ? val : (target ?? 0)
}

// ── Donut chart ───────────────────────────────────────────────
function DonutChart({ data, size = 160 }) {
    const canvasRef = useRef(null)
    const rafRef = useRef(null)

    useEffect(() => {
        if (!canvasRef.current || !data?.length) return
        const cv = canvasRef.current
        const ctx = cv.getContext('2d')
        const DPR = 2
        cv.width = size * DPR
        cv.height = size * DPR
        cv.style.width = size + 'px'
        cv.style.height = size + 'px'
        ctx.scale(DPR, DPR)

        const cx = size / 2
        const cy = size / 2
        const R = size / 2 - 12
        const r = R * 0.62
        const total = data.reduce((s, d) => s + d.value, 0)
        if (!total) return

        let prog = 0
        if (rafRef.current) cancelAnimationFrame(rafRef.current)

        function loop() {
            ctx.clearRect(0, 0, size, size)
            prog = Math.min(prog + 0.035, 1)
            const e3 = 1 - Math.pow(1 - prog, 3)

            let startAngle = -Math.PI / 2
            const gap = 0.03

            data.forEach(seg => {
                const pct = (seg.value / total) * e3
                const arc = pct * Math.PI * 2 - gap
                if (arc <= 0) return

                // Segment
                ctx.beginPath()
                ctx.moveTo(cx, cy)
                ctx.arc(cx, cy, R, startAngle + gap / 2, startAngle + arc + gap / 2)
                ctx.closePath()
                ctx.fillStyle = seg.color + '22'
                ctx.fill()

                // Arc stroke
                ctx.beginPath()
                ctx.arc(cx, cy, R - 8, startAngle + gap / 2, startAngle + arc + gap / 2)
                ctx.strokeStyle = seg.color
                ctx.lineWidth = 14
                ctx.lineCap = 'round'
                ctx.globalAlpha = 0.85
                ctx.stroke()
                ctx.globalAlpha = 1

                startAngle += arc + gap
            })

            // Donut hole
            ctx.beginPath()
            ctx.arc(cx, cy, r, 0, Math.PI * 2)
            ctx.fillStyle = '#0c0f18'
            ctx.fill()

            // Center text
            if (prog >= 0.8) {
                const alpha = (prog - 0.8) / 0.2
                ctx.globalAlpha = alpha
                ctx.textAlign = 'center'
                ctx.textBaseline = 'middle'
                ctx.font = `700 ${Math.round(size * 0.18)}px "JetBrains Mono",monospace`
                ctx.fillStyle = data[0]?.color || '#00e5ff'
                ctx.fillText(total, cx, cy - 4)
                ctx.font = `400 ${Math.round(size * 0.07)}px "JetBrains Mono",monospace`
                ctx.fillStyle = 'rgba(106,117,144,.8)'
                ctx.fillText('TOTAL', cx, cy + size * 0.1)
                ctx.globalAlpha = 1
            }

            if (prog < 1) rafRef.current = requestAnimationFrame(loop)
        }

        rafRef.current = requestAnimationFrame(loop)
        return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current) }
    }, [data, size])

    return <canvas ref={canvasRef} />
}

// ── Stat card ─────────────────────────────────────────────────
function StatCard({ label, value, sub, color, onClick }) {
    const animated = useCountUp(typeof value === 'number' ? value : 0)
    const show = typeof value === 'number' ? animated : (value ?? '—')
    const c = color || '#00e5ff'

    return (
        <div onClick={onClick}
            style={{
                background: 'rgba(15,19,32,.9)', border: '1px solid rgba(255,255,255,.07)',
                borderRadius: 8, padding: 16, position: 'relative', overflow: 'hidden',
                cursor: onClick ? 'pointer' : 'default',
                transition: 'transform .2s,border-color .25s',
            }}
            onMouseEnter={e => { if (onClick) { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.borderColor = `${c}30` } }}
            onMouseLeave={e => { e.currentTarget.style.transform = ''; e.currentTarget.style.borderColor = 'rgba(255,255,255,.07)' }}
        >
            {/* Top shimmer */}
            <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 1, background: `linear-gradient(90deg,transparent,${c},transparent)`, opacity: .5 }} />
            {/* Corner */}
            <div style={{ position: 'absolute', top: 0, right: 0, width: 0, height: 0, borderStyle: 'solid', borderWidth: '0 16px 16px 0', borderColor: `transparent ${c} transparent transparent`, opacity: .25 }} />
            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 32, fontWeight: 700, color: c, marginBottom: 6, lineHeight: 1 }}>
                {show}
            </div>
            <div style={{ fontSize: 11, color: 'rgba(90,107,138,1)', marginBottom: 2 }}>{label}</div>
            {sub && <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: 'var(--dim)' }}>{sub}</div>}
        </div>
    )
}

// ── Mini sparkline ────────────────────────────────────────────
function Sparkline({ values, color }) {
    const ref = useRef(null)
    useEffect(() => {
        if (!ref.current || !values?.length) return
        const cv = ref.current
        const ctx = cv.getContext('2d')
        const W = cv.width = 80, H = cv.height = 28
        const max = Math.max(...values, 1)
        const step = W / (values.length - 1)
        ctx.clearRect(0, 0, W, H)
        // Fill
        ctx.beginPath()
        values.forEach((v, i) => {
            const x = i * step, y = H - (v / max) * (H - 4) - 2
            i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y)
        })
        ctx.lineTo((values.length - 1) * step, H)
        ctx.lineTo(0, H)
        ctx.closePath()
        ctx.fillStyle = color + '18'
        ctx.fill()
        // Line
        ctx.beginPath()
        values.forEach((v, i) => {
            const x = i * step, y = H - (v / max) * (H - 4) - 2
            i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y)
        })
        ctx.strokeStyle = color
        ctx.lineWidth = 1.5
        ctx.stroke()
    }, [values, color])
    return <canvas ref={ref} style={{ display: 'block' }} />
}

// ── Main dashboard ────────────────────────────────────────────
export function Dashboard() {
    const navigate = useNavigate()
    const { data: stats, isLoading } = useQuery({
        queryKey: ['stats'], queryFn: fetchStats, refetchInterval: 30000,
    })
    const { data: alertsData } = useQuery({
        queryKey: ['alerts-dash'], queryFn: () => fetchAlerts(10), refetchInterval: 30000,
    })

    if (isLoading) return (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 12 }}>
            <svg width="20" height="20" viewBox="0 0 20 20">
                <circle cx="10" cy="10" r="8" fill="none" stroke="rgba(0,229,255,.15)" strokeWidth="2" />
                <circle cx="10" cy="10" r="8" fill="none" stroke="var(--cyan)" strokeWidth="2"
                    strokeLinecap="round" strokeDasharray="12 38"
                    style={{ transformOrigin: '50% 50%', animation: 'rh-spin .75s linear infinite' }} />
                <style>{`@keyframes rh-spin{to{transform:rotate(360deg)}}`}</style>
            </svg>
            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: 'var(--dim)' }}>Loading...</span>
        </div>
    )

    const s = stats || {}
    const tot = s.totals || {}
    const el = s.event_log || {}
    const enr = s.enrichment || {}
    const reg = s.registry || {}
    const tsk = s.tasks || {}
    const svc = s.services || {}

    const totalAll = (tot.registry || 0) + (tot.tasks || 0) + (tot.services || 0)

    const donutData = [
        { label: 'Critical', value: tot.critical || 0, color: '#ff2055' },
        { label: 'High', value: tot.high || 0, color: '#ff7700' },
        { label: 'Medium', value: (reg.medium || 0) + (tsk.medium || 0) + (svc.medium || 0), color: '#ffd60a' },
        { label: 'Low', value: (reg.low || 0) + (tsk.low || 0) + (svc.low || 0), color: '#00e676' },
    ].filter(d => d.value > 0)

    const alerts = alertsData?.alerts || []
    const sevC = { critical: '#ff2055', high: '#ff7700', medium: '#ffd60a', low: '#00e676' }

    return (
        <div style={{ overflowY: 'auto', height: '100%', padding: '22px 26px' }}>
            <style>{`
        @keyframes dash-in { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }
        .dash-section { animation: dash-in .35s ease both; }
      `}</style>

            {/* Header */}
            <div className="dash-section" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
                <div>
                    <h1 style={{ fontFamily: "'Space Grotesk','DM Sans',sans-serif", fontSize: 22, fontWeight: 700, color: 'var(--white)', letterSpacing: '-.01em' }}>
                        Overview
                    </h1>
                    <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'var(--dim)', marginTop: 2 }}>
                        {new Date().toLocaleString()} · reghunt.db
                    </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--green)', boxShadow: '0 0 6px var(--green)', animation: 'pulse 2s ease-in-out infinite' }} />
                    <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: 'var(--green)', letterSpacing: '.1em' }}>LIVE</span>
                </div>
            </div>

            {/* Main grid */}
            <div className="dash-section" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 200px', gap: 12, marginBottom: 16, animationDelay: '.05s' }}>
                <StatCard label="Critical Findings" value={tot.critical || 0} color="#ff2055" sub="Requires immediate action" onClick={() => navigate('/alerts')} />
                <StatCard label="High Severity" value={tot.high || 0} color="#ff7700" sub="Review recommended" onClick={() => navigate('/alerts')} />
                <StatCard label="Total Entries" value={totalAll} color="#00e5ff" sub={`${tot.registry || 0} reg · ${tot.tasks || 0} tasks · ${tot.services || 0} svc`} onClick={() => navigate('/entries')} />

                {/* Donut chart card */}
                <div style={{ background: 'rgba(15,19,32,.9)', border: '1px solid rgba(255,255,255,.07)', borderRadius: 8, padding: 12, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
                    <DonutChart data={donutData} size={120} />
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'center' }}>
                        {donutData.map(d => (
                            <div key={d.label} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                                <div style={{ width: 6, height: 6, borderRadius: '50%', background: d.color, flexShrink: 0 }} />
                                <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, color: 'var(--dim)' }}>{d.label}</span>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* Event log stats */}
            <div className="dash-section" style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12, marginBottom: 16, animationDelay: '.1s' }}>
                <StatCard label="Sysmon Events" value={el.sysmon_events || 0} color="#00e676" sub="Event ID 1 + 13" />
                <StatCard label="Process Events" value={el.process_events || 0} color="#00e676" sub="Event ID 4688" />
                <StatCard label="Chains Built" value={enr.chains_built || 0} color="#00e5ff" sub="Attack chains" />
                <StatCard label="Enriched Entries" value={enr.enriched_entries || 0} color="#c470ff" sub="File + threat intel" />
            </div>

            {/* Severity breakdown bars */}
            <div className="dash-section" style={{ background: 'rgba(15,19,32,.9)', border: '1px solid rgba(255,255,255,.07)', borderRadius: 8, padding: 16, marginBottom: 16, animationDelay: '.15s' }}>
                <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700, letterSpacing: '.18em', textTransform: 'uppercase', color: 'var(--dim)', marginBottom: 12 }}>
                    Severity Distribution
                </div>
                {[
                    { label: 'Critical', value: tot.critical || 0, color: '#ff2055' },
                    { label: 'High', value: tot.high || 0, color: '#ff7700' },
                    { label: 'Medium', value: (reg.medium || 0) + (tsk.medium || 0) + (svc.medium || 0), color: '#ffd60a' },
                    { label: 'Low', value: (reg.low || 0) + (tsk.low || 0) + (svc.low || 0), color: '#00e676' },
                ].map((row, i) => {
                    const pct = totalAll > 0 ? (row.value / totalAll) * 100 : 0
                    return (
                        <div key={row.label} style={{ marginBottom: 10, animation: `dash-in .4s ease ${i * .06 + .15}s both` }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                                <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: 'var(--mid)' }}>{row.label}</span>
                                <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: row.color }}>{row.value}</span>
                            </div>
                            <div style={{ height: 4, background: 'rgba(255,255,255,.05)', borderRadius: 2, overflow: 'hidden' }}>
                                <div style={{ height: '100%', width: 0, background: row.color, borderRadius: 2, boxShadow: `0 0 8px ${row.color}60`, transition: `width 1.2s cubic-bezier(.16,1,.3,1) ${i * .1}s`, animation: `bar-grow .8s ease ${i * .1 + .2}s both` }} />
                            </div>
                            <style>{`.bar-width-${i}{width:${pct}% !important} @keyframes bar-grow{from{width:0}to{width:${pct}%}}`}</style>
                        </div>
                    )
                })}
            </div>

            {/* Recent alerts */}
            <div className="dash-section" style={{ background: 'rgba(15,19,32,.9)', border: '1px solid rgba(255,255,255,.07)', borderRadius: 8, overflow: 'hidden', animationDelay: '.2s' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', borderBottom: '1px solid rgba(255,255,255,.07)' }}>
                    <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700, letterSpacing: '.18em', textTransform: 'uppercase', color: 'var(--dim)' }}>
                        Recent Alerts
                    </span>
                    <button onClick={() => navigate('/alerts')}
                        style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: 'var(--cyan)', background: 'none', border: 'none', cursor: 'pointer' }}>
                        View all →
                    </button>
                </div>
                {alerts.map((a, i) => {
                    const name = a.name || a.task_name || a.service_name || '?'
                    const value = a.value_data || a.command || a.binary_path || ''
                    const c = sevC[a.severity] || 'var(--dim)'
                    return (
                        <div key={i} onClick={() => navigate(`/entries/${a.entry_type}/${a.id}`)}
                            style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '10px 16px', borderBottom: '1px solid rgba(255,255,255,.05)', cursor: 'pointer', transition: 'background .12s', animation: `dash-in .3s ease ${i * .04 + .25}s both` }}
                            onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,.03)'}
                            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                            <div style={{ width: 6, height: 6, borderRadius: '50%', background: c, flexShrink: 0, boxShadow: a.severity === 'critical' ? `0 0 6px ${c}` : 'none' }} />
                            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: 'var(--dim)', width: 60, flexShrink: 0 }}>{a.entry_type}</span>
                            <span style={{ fontFamily: "'Space Grotesk','DM Sans',sans-serif", fontSize: 12, fontWeight: 600, color: 'var(--white)', flexShrink: 0, width: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{name}</span>
                            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: 'var(--dim)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{value.slice(0, 70)}</span>
                            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, color: c, flexShrink: 0, fontWeight: 700, letterSpacing: '.08em' }}>{a.severity.toUpperCase()}</span>
                        </div>
                    )
                })}
            </div>
        </div>
    )
}