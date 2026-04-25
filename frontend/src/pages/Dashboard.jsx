// src/pages/Dashboard.jsx
import { useEffect, useRef, useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { fetchStats, fetchAlerts, fetchAllScores, fetchSummaryStats, scoreToSeverity, SCORE_COLOR, SCORE_LABEL } from '../api/client'

// ── Count-up hook ──────────────────────────────────────────────────────────────
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

// ── Donut chart ────────────────────────────────────────────────────────────────
function DonutChart({ data, size = 160 }) {
    const canvasRef = useRef(null)
    const dataKey = useMemo(() => data.map(d => `${d.label}:${d.value}`).join(','), [data])
    useEffect(() => {
        if (!canvasRef.current || !data?.length) return
        const cv = canvasRef.current
        const ctx = cv.getContext('2d')
        const DPR = 2
        cv.width = size * DPR; cv.height = size * DPR
        cv.style.width = size + 'px'; cv.style.height = size + 'px'
        ctx.scale(DPR, DPR)
        const cx = size / 2, cy = size / 2
        const R = size / 2 - 10
        const r = R * 0.6
        const total = data.reduce((s, d) => s + d.value, 0)
        if (!total) return
        let prog = 0
        let raf = null
        let done = false
        function loop() {
            if (done) return
            ctx.clearRect(0, 0, size, size)
            prog = Math.min(prog + 0.03, 1)
            const e3 = 1 - Math.pow(1 - prog, 3)
            let startAngle = -Math.PI / 2
            const gap = 0.025
            data.forEach(seg => {
                const pct = (seg.value / total) * e3
                const arc = pct * Math.PI * 2 - gap
                if (arc <= 0) return
                ctx.shadowColor = seg.color; ctx.shadowBlur = 12
                ctx.beginPath()
                ctx.arc(cx, cy, R - 8, startAngle + gap / 2, startAngle + arc + gap / 2)
                ctx.strokeStyle = seg.color; ctx.lineWidth = 14
                ctx.lineCap = 'round'; ctx.globalAlpha = 0.9
                ctx.stroke()
                ctx.shadowBlur = 0; ctx.globalAlpha = 1
                startAngle += arc + gap
            })
            ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI * 2)
            ctx.fillStyle = '#0b0e1a'; ctx.fill()
            if (prog >= 0.7) {
                const alpha = Math.min((prog - 0.7) / 0.3, 1)
                ctx.globalAlpha = alpha; ctx.textAlign = 'center'; ctx.textBaseline = 'middle'
                ctx.font = `700 ${Math.round(size * 0.2)}px "JetBrains Mono",monospace`
                ctx.fillStyle = data[0]?.color || '#00e5ff'
                ctx.shadowColor = data[0]?.color; ctx.shadowBlur = 16
                ctx.fillText(total, cx, cy - 5)
                ctx.shadowBlur = 0
                ctx.font = `400 ${Math.round(size * 0.07)}px "JetBrains Mono",monospace`
                ctx.fillStyle = 'rgba(106,117,144,.8)'
                ctx.fillText('TOTAL', cx, cy + size * 0.12)
                ctx.globalAlpha = 1
            }
            if (prog < 1) {
                raf = requestAnimationFrame(loop)
            }
            // prog === 1 — animation complete, do nothing more
        }
        raf = requestAnimationFrame(loop)
        return () => { done = true; if (raf) cancelAnimationFrame(raf) }
    }, [dataKey, size])
    return <canvas ref={canvasRef} />
}

// ── Sparkline bar chart ────────────────────────────────────────────────────────
function BarSparkline({ data, color, height = 40 }) {
    const canvasRef = useRef(null)
    const dataKey = useMemo(() => data.join(','), [data])
    useEffect(() => {
        if (!canvasRef.current || !data?.length) return
        const cv = canvasRef.current
        const ctx = cv.getContext('2d')
        const W = cv.offsetWidth || 200, H = height
        const DPR = 2
        cv.width = W * DPR; cv.height = H * DPR
        cv.style.width = W + 'px'; cv.style.height = H + 'px'
        ctx.scale(DPR, DPR)
        const max = Math.max(...data, 1)
        const bw = W / data.length - 2
        let prog = 0
        let raf = null
        let done = false
        function loop() {
            if (done) return
            ctx.clearRect(0, 0, W, H)
            prog = Math.min(prog + 0.04, 1)
            data.forEach((v, i) => {
                const bh = (v / max) * H * prog
                const x = i * (bw + 2)
                const grad = ctx.createLinearGradient(0, H - bh, 0, H)
                grad.addColorStop(0, color + 'cc')
                grad.addColorStop(1, color + '22')
                ctx.fillStyle = grad
                ctx.shadowColor = color; ctx.shadowBlur = 6
                ctx.beginPath()
                ctx.roundRect(x, H - bh, bw, bh, 2)
                ctx.fill()
                ctx.shadowBlur = 0
            })
            if (prog < 1) raf = requestAnimationFrame(loop)
        }
        raf = requestAnimationFrame(loop)
        return () => { done = true; if (raf) cancelAnimationFrame(raf) }
    }, [dataKey, color, height])
    return <canvas ref={canvasRef} style={{ width: '100%', height }} />
}

// ── Hero stat card ─────────────────────────────────────────────────────────────
function HeroCard({ label, value, sub, color, onClick, delay = 0, spark }) {
    const animated = useCountUp(typeof value === 'number' ? value : 0)
    const show = typeof value === 'number' ? animated : (value ?? '—')
    const c = color || '#00e5ff'
    return (
        <div onClick={onClick} style={{
            background: `linear-gradient(135deg, ${c}0d 0%, rgba(13,17,30,.95) 60%)`,
            border: `1px solid ${c}28`,
            borderRadius: 12, padding: '18px 20px',
            position: 'relative', overflow: 'hidden',
            cursor: onClick ? 'pointer' : 'default',
            transition: 'transform .2s, box-shadow .25s, border-color .25s',
            animation: `dash-in .4s cubic-bezier(.16,1,.3,1) ${delay}s both`,
            boxShadow: `0 4px 24px ${c}0a`,
        }}
            onMouseEnter={e => { if (onClick) { e.currentTarget.style.transform = 'translateY(-3px)'; e.currentTarget.style.borderColor = `${c}55`; e.currentTarget.style.boxShadow = `0 8px 32px ${c}18` } }}
            onMouseLeave={e => { e.currentTarget.style.transform = ''; e.currentTarget.style.borderColor = `${c}28`; e.currentTarget.style.boxShadow = `0 4px 24px ${c}0a` }}
        >
            {/* shimmer */}
            <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 1, background: `linear-gradient(90deg,transparent,${c}80,transparent)` }} />
            {/* corner */}
            <div style={{ position: 'absolute', top: 0, right: 0, width: 0, height: 0, borderStyle: 'solid', borderWidth: '0 20px 20px 0', borderColor: `transparent ${c}35 transparent transparent` }} />
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 10 }}>
                <div>
                    <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 34, fontWeight: 700, color: c, lineHeight: 1, textShadow: `0 0 24px ${c}50`, marginBottom: 6 }}>{show}</div>
                    <div style={{ fontSize: 11, color: 'rgba(90,107,138,1)', fontFamily: "'Space Grotesk',sans-serif" }}>{label}</div>
                    {sub && <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: 'rgba(53,64,96,.8)', marginTop: 2 }}>{sub}</div>}
                </div>
            </div>
            {spark && spark.length > 0 && (
                <div style={{ marginTop: 8, opacity: .7 }}>
                    <BarSparkline data={spark} color={c} height={32} />
                </div>
            )}
        </div>
    )
}

// ── Mini stat ─────────────────────────────────────────────────────────────────
function MiniStat({ label, value, color, delay = 0 }) {
    const animated = useCountUp(typeof value === 'number' ? value : 0)
    const c = color || '#00e5ff'
    return (
        <div style={{
            background: 'rgba(13,17,30,.9)', border: '1px solid rgba(255,255,255,.06)',
            borderRadius: 10, padding: '14px 16px',
            animation: `dash-in .35s cubic-bezier(.16,1,.3,1) ${delay}s both`,
            position: 'relative', overflow: 'hidden',
        }}>
            <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 1, background: `linear-gradient(90deg,transparent,${c}50,transparent)` }} />
            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 22, fontWeight: 700, color: c, marginBottom: 4 }}>{animated}</div>
            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, color: 'rgba(53,64,96,.8)', textTransform: 'uppercase', letterSpacing: '.1em' }}>{label}</div>
        </div>
    )
}

// ── Coverage bar ──────────────────────────────────────────────────────────────
function CoverageBar({ label, value, total, color, delay = 0 }) {
    const barRef = useRef(null)
    const pct = total > 0 ? Math.round((value / total) * 100) : 0
    useEffect(() => {
        if (!barRef.current) return
        barRef.current.style.width = '0%'
        const t = setTimeout(() => {
            if (barRef.current) {
                barRef.current.style.transition = 'width 1s cubic-bezier(.16,1,.3,1)'
                barRef.current.style.width = pct + '%'
            }
        }, delay * 1000 + 300)
        return () => clearTimeout(t)
    }, [pct, delay])
    return (
        <div style={{ animation: `dash-in .35s ease ${delay}s both` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                    <div style={{ width: 6, height: 6, borderRadius: '50%', background: color, boxShadow: `0 0 5px ${color}` }} />
                    <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: 'rgba(140,155,175,1)' }}>{label}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, fontWeight: 700, color }}>{value}</span>
                    <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, color: 'rgba(53,64,96,.7)' }}>{pct}%</span>
                </div>
            </div>
            <div style={{ height: 5, background: 'rgba(255,255,255,.04)', borderRadius: 3, overflow: 'hidden' }}>
                <div ref={barRef} style={{ height: '100%', background: `linear-gradient(90deg,${color},${color}88)`, borderRadius: 3, boxShadow: `0 0 8px ${color}60` }} />
            </div>
        </div>
    )
}

// ── Vertical bar column ───────────────────────────────────────────────────────
function VertBar({ item, totalAll, index }) {
    const barRef = useRef(null)
    const pct = totalAll > 0 ? (item.value / totalAll) * 100 : 0
    useEffect(() => {
        if (!barRef.current) return
        barRef.current.style.height = '0%'
        const t = setTimeout(() => {
            if (barRef.current) {
                barRef.current.style.transition = 'height 1s cubic-bezier(.16,1,.3,1)'
                barRef.current.style.height = `${Math.max(pct, 2)}%`
            }
        }, index * 80 + 400)
        return () => clearTimeout(t)
    }, [pct, index])
    return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
            <div style={{ width: '100%', height: 80, background: 'rgba(255,255,255,.04)', borderRadius: 6, overflow: 'hidden', display: 'flex', alignItems: 'flex-end' }}>
                <div ref={barRef} style={{ width: '100%', background: `linear-gradient(0deg,${item.color},${item.color}55)`, borderRadius: '4px 4px 0 0', boxShadow: `0 0 12px ${item.color}40` }} />
            </div>
            <div style={{ textAlign: 'center' }}>
                <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 18, fontWeight: 700, color: item.color, lineHeight: 1 }}>{item.value}</div>
                <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, color: 'rgba(90,107,138,1)', marginTop: 2 }}>{item.label}</div>
                <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 7, color: 'rgba(53,64,96,.6)' }}>score {item.range}</div>
            </div>
        </div>
    )
}
export function Dashboard() {
    const navigate = useNavigate()
    const [time, setTime] = useState(new Date())

    useEffect(() => {
        const t = setInterval(() => setTime(new Date()), 1000)
        return () => clearInterval(t)
    }, [])

    const { data: stats, isLoading } = useQuery({
        queryKey: ['stats'], queryFn: fetchStats, refetchInterval: 30000,
    })
    const { data: alertsData } = useQuery({
        queryKey: ['alerts-dash'], queryFn: () => fetchAlerts(20), refetchInterval: 30000,
    })
    const { data: scoresMap } = useQuery({
        queryKey: ['scores-all'], queryFn: fetchAllScores, refetchInterval: 60000,
    })
    const { data: summaryStats } = useQuery({
        queryKey: ['summary-stats'], queryFn: fetchSummaryStats, refetchInterval: 30000,
    })

    if (isLoading) return (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 12 }}>
            <div style={{ width: 16, height: 16, borderRadius: '50%', border: '2px solid rgba(0,229,255,.2)', borderTopColor: '#00e5ff', animation: 'spin .7s linear infinite' }} />
            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: 'rgba(90,107,138,1)' }}>Loading telemetry...</span>
            <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
        </div>
    )

    const reg = stats?.registry || {}
    const tsk = stats?.tasks || {}
    const svc = stats?.services || {}
    const tot = stats?.totals || {}
    const el = stats?.event_log || {}
    const enr = stats?.enrichment || {}
    const nbl = stats?.new_since_baseline || {}

    const totalAll = (tot.registry || 0) + (tot.tasks || 0) + (tot.services || 0)

    const allScores = scoresMap ? [...scoresMap.values()] : []
    const scoreCritical = allScores.filter(s => scoreToSeverity(s.score) === 'critical').length || (tot.critical || 0)
    const scoreHigh = allScores.filter(s => scoreToSeverity(s.score) === 'high').length || (tot.high || 0)
    const scoreMedium = allScores.filter(s => scoreToSeverity(s.score) === 'medium').length || 0
    const scoreLow = allScores.filter(s => scoreToSeverity(s.score) === 'low').length || 0

    const donutData = [
        { label: 'Critical', value: scoreCritical, color: '#ff2055' },
        { label: 'High', value: scoreHigh, color: '#ff7700' },
        { label: 'Medium', value: scoreMedium, color: '#ffd60a' },
        { label: 'Low', value: scoreLow, color: '#00e676' },
    ].filter(d => d.value > 0)

    const alerts = alertsData?.alerts || []
    const newTotal = nbl.total || 0

    // Stable sparklines — derived from real data, no random
    const critSpark = useMemo(() => {
        const base = scoreCritical || 0
        return [base, base, base, base, base, base, base, base]
    }, [scoreCritical])

    const highSpark = useMemo(() => {
        const base = scoreHigh || 0
        return [base, base, base, base, base, base, base, base]
    }, [scoreHigh])

    // Coverage bars
    const coverageItems = [
        { label: 'Registry Run Keys', value: tot.registry || 0, total: totalAll || 1, color: '#00e5ff' },
        { label: 'Scheduled Tasks', value: tot.tasks || 0, total: totalAll || 1, color: '#c470ff' },
        { label: 'Services', value: tot.services || 0, total: totalAll || 1, color: '#ff7722' },
    ]

    return (
        <div style={{ overflowY: 'auto', height: '100%', padding: '20px 24px' }}>
            <style>{`
                @keyframes dash-in{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
                @keyframes rh-scan{0%{left:-60%}100%{left:160%}}
                @keyframes rh-live{0%,100%{opacity:1;box-shadow:0 0 4px #00e676}50%{opacity:.6;box-shadow:0 0 10px #00e676}}
            `}</style>

            {/* ── Header ── */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 22, animation: 'dash-in .35s ease' }}>
                <div>
                    <h1 style={{ fontFamily: "'Space Grotesk',sans-serif", fontSize: 24, fontWeight: 700, color: 'rgba(238,242,255,.97)', letterSpacing: '-.01em', marginBottom: 3 }}>
                        Threat Overview
                    </h1>
                    <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'rgba(53,64,96,.8)' }}>
                        {time.toLocaleString()} · reghunt.db
                    </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                    {newTotal > 0 && (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '6px 12px', borderRadius: 6, background: 'rgba(255,32,85,.08)', border: '1px solid rgba(255,32,85,.25)' }}>
                            <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#ff2055', animation: 'rh-live 1.5s ease-in-out infinite' }} />
                            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: '#ff2055', fontWeight: 700 }}>
                                {newTotal} NEW SINCE BASELINE
                            </span>
                        </div>
                    )}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#00e676', animation: 'rh-live 2s ease-in-out infinite' }} />
                        <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: '#00e676', letterSpacing: '.12em' }}>LIVE</span>
                    </div>
                </div>
            </div>

            {/* ── Hero stat cards ── */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 12, marginBottom: 14 }}>
                <HeroCard label="Critical Findings" value={scoreCritical} color="#ff2055" sub="Threat score ≥ 80" onClick={() => navigate('/alerts')} delay={0} spark={critSpark} />
                <HeroCard label="High Risk" value={scoreHigh} color="#ff7722" sub="Threat score 60–79" onClick={() => navigate('/alerts')} delay={0.04} spark={highSpark} />
                <HeroCard label="New Since Baseline" value={newTotal} color={newTotal > 0 ? '#ff2055' : '#00e676'} sub={newTotal === 0 ? 'System clean' : 'Requires investigation'} onClick={() => navigate('/alerts')} delay={0.08} />
                <HeroCard label="Total Entries" value={totalAll} color="#00e5ff" sub={`${tot.registry || 0} reg · ${tot.tasks || 0} tasks · ${tot.services || 0} svc`} onClick={() => navigate('/entries')} delay={0.12} />
            </div>

            {/* ── Middle row: donut + coverage + mini stats ── */}
            <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr 1fr', gap: 12, marginBottom: 14 }}>

                {/* Donut */}
                <div style={{
                    background: 'rgba(13,17,30,.92)', border: '1px solid rgba(255,255,255,.07)',
                    borderRadius: 12, padding: '16px 14px',
                    display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12,
                    animation: 'dash-in .4s ease .16s both',
                }}>
                    <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700, letterSpacing: '.16em', textTransform: 'uppercase', color: 'rgba(53,64,96,.85)', alignSelf: 'flex-start' }}>Score Distribution</div>
                    <DonutChart data={donutData} size={130} />
                    <div style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: 5 }}>
                        {donutData.map(d => (
                            <div key={d.label} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                    <div style={{ width: 6, height: 6, borderRadius: '50%', background: d.color, boxShadow: `0 0 4px ${d.color}` }} />
                                    <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: 'rgba(90,107,138,1)' }}>{d.label}</span>
                                </div>
                                <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, fontWeight: 700, color: d.color }}>{d.value}</span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Coverage breakdown */}
                <div style={{
                    background: 'rgba(13,17,30,.92)', border: '1px solid rgba(255,255,255,.07)',
                    borderRadius: 12, padding: '16px 18px',
                    animation: 'dash-in .4s ease .2s both',
                }}>
                    <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700, letterSpacing: '.16em', textTransform: 'uppercase', color: 'rgba(53,64,96,.85)', marginBottom: 16 }}>
                        Persistence Coverage
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                        {coverageItems.map((item, i) => (
                            <CoverageBar key={item.label} {...item} delay={i * 0.06 + 0.2} />
                        ))}
                    </div>
                    <div style={{ marginTop: 16, paddingTop: 12, borderTop: '1px solid rgba(255,255,255,.05)', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                        <div>
                            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, color: 'rgba(53,64,96,.7)', textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 3 }}>Chains Built</div>
                            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 18, fontWeight: 700, color: '#00e5ff' }}>{enr.chains_built || 0}</div>
                        </div>
                        <div>
                            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, color: 'rgba(53,64,96,.7)', textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 3 }}>Scored</div>
                            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 18, fontWeight: 700, color: '#c470ff' }}>{enr.enriched_entries || 0}</div>
                        </div>
                    </div>
                </div>

                {/* Event telemetry */}
                <div style={{
                    background: 'rgba(13,17,30,.92)', border: '1px solid rgba(255,255,255,.07)',
                    borderRadius: 12, padding: '16px 18px',
                    animation: 'dash-in .4s ease .24s both',
                }}>
                    <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700, letterSpacing: '.16em', textTransform: 'uppercase', color: 'rgba(53,64,96,.85)', marginBottom: 16 }}>
                        Event Telemetry
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                        {[
                            { label: 'Sysmon Events', value: el.sysmon_events || 0, color: '#00e676', sub: 'ID 1 + 13 + FileCreate' },
                            { label: 'Process Events', value: el.process_events || 0, color: '#00e5ff', sub: 'Event ID 4688' },
                        ].map(({ label, value, color, sub }) => (
                            <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 12px', borderRadius: 8, background: `${color}08`, border: `1px solid ${color}15` }}>
                                <div style={{ width: 3, height: 36, borderRadius: 2, background: color, boxShadow: `0 0 6px ${color}` }} />
                                <div>
                                    <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 20, fontWeight: 700, color, lineHeight: 1, marginBottom: 3 }}>
                                        {value.toLocaleString()}
                                    </div>
                                    <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, color: 'rgba(53,64,96,.8)', textTransform: 'uppercase', letterSpacing: '.06em' }}>{label}</div>
                                    <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, color: 'rgba(53,64,96,.5)' }}>{sub}</div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* ── Severity distribution bars ── */}
            <div style={{
                background: 'rgba(13,17,30,.92)', border: '1px solid rgba(255,255,255,.07)',
                borderRadius: 12, padding: '16px 18px', marginBottom: 14,
                animation: 'dash-in .4s ease .28s both',
            }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
                    <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700, letterSpacing: '.16em', textTransform: 'uppercase', color: 'rgba(53,64,96,.85)' }}>
                        Threat Score Distribution
                    </div>
                    <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: 'rgba(53,64,96,.6)' }}>
                        {totalAll} total entries
                    </div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12 }}>
                    {[
                        { label: 'Critical', value: scoreCritical, color: '#ff2055', range: '≥ 80' },
                        { label: 'High', value: scoreHigh, color: '#ff7722', range: '60–79' },
                        { label: 'Medium', value: scoreMedium, color: '#ffd60a', range: '35–59' },
                        { label: 'Low', value: scoreLow, color: '#00e676', range: '< 35' },
                    ].map((item, i) => (
                        <VertBar key={item.label} item={item} totalAll={totalAll} index={i} />
                    ))}
                </div>
            </div>

            {/* ── Recent alerts ── */}
            <div style={{
                background: 'rgba(13,17,30,.92)', border: '1px solid rgba(255,255,255,.07)',
                borderRadius: 12, overflow: 'hidden',
                animation: 'dash-in .4s ease .32s both',
            }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 18px', borderBottom: '1px solid rgba(255,255,255,.06)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700, letterSpacing: '.16em', textTransform: 'uppercase', color: 'rgba(53,64,96,.85)' }}>
                            Recent Persistence Alerts
                        </span>
                        <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, padding: '1px 6px', borderRadius: 3, background: 'rgba(0,229,255,.08)', color: '#00e5ff', border: '1px solid rgba(0,229,255,.15)' }}>
                            {alerts.length}
                        </span>
                    </div>
                    <button onClick={() => navigate('/alerts')}
                        style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: '#00e5ff', background: 'none', border: 'none', cursor: 'pointer', letterSpacing: '.06em' }}>
                        View all →
                    </button>
                </div>
                {/* Table head */}
                <div style={{ display: 'grid', gridTemplateColumns: '6px 70px 80px 160px 1fr 90px', gap: 12, padding: '8px 18px', borderBottom: '1px solid rgba(255,255,255,.04)' }}>
                    {['', 'Type', 'Severity', 'Name', 'Value / Path', 'Score'].map(h => (
                        <span key={h} style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, color: 'rgba(53,64,96,.6)', textTransform: 'uppercase', letterSpacing: '.08em' }}>{h}</span>
                    ))}
                </div>
                {alerts.slice(0, 12).map((a, i) => {
                    const name = a.name || a.task_name || a.service_name || '?'
                    const value = a.value_data || a.command || a.binary_path || ''
                    const scoreEntry = scoresMap?.get(`${a.entry_type}/${a.id}`)
                    const score = scoreEntry?.score ?? null
                    const sev = scoreToSeverity(score) || a.severity
                    const c = SCORE_COLOR[sev] || 'rgba(90,107,138,.7)'
                    const label = SCORE_LABEL[sev] || (a.severity?.toUpperCase() || '—')
                    return (
                        <div key={i}
                            onClick={() => navigate(`/entries/${a.entry_type}/${a.id}`)}
                            style={{ display: 'grid', gridTemplateColumns: '6px 70px 80px 160px 1fr 90px', gap: 12, padding: '9px 18px', borderBottom: i < Math.min(alerts.length, 12) - 1 ? '1px solid rgba(255,255,255,.04)' : 'none', cursor: 'pointer', transition: 'background .12s', animation: `dash-in .3s ease ${i * .03 + .33}s both` }}
                            onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,.025)'}
                            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                        >
                            <div style={{ display: 'flex', alignItems: 'center' }}>
                                <div style={{ width: 5, height: 5, borderRadius: '50%', background: c, boxShadow: sev === 'critical' ? `0 0 5px ${c}` : 'none', flexShrink: 0 }} />
                            </div>
                            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: 'rgba(90,107,138,1)', display: 'flex', alignItems: 'center', textTransform: 'uppercase' }}>{a.entry_type}</span>
                            <span style={{ display: 'flex', alignItems: 'center' }}>
                                <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700, padding: '2px 6px', borderRadius: 3, background: `${c}15`, color: c, border: `1px solid ${c}30`, letterSpacing: '.06em' }}>
                                    {label}
                                </span>
                            </span>
                            <span style={{ fontFamily: "'Space Grotesk',sans-serif", fontSize: 12, fontWeight: 600, color: 'rgba(238,242,255,.9)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'flex', alignItems: 'center' }}>{name}</span>
                            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: 'rgba(90,107,138,.8)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'flex', alignItems: 'center' }}>{value.slice(0, 80)}</span>
                            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, fontWeight: 700, color: c, display: 'flex', alignItems: 'center', textShadow: score >= 80 ? `0 0 8px ${c}60` : 'none' }}>
                                {score != null ? score : '—'}
                            </span>
                        </div>
                    )
                })}
            </div>
        </div>
    )
}