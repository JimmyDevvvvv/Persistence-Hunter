// src/components/features/ProcessTree.jsx
// Canvas-based animated process tree — matches the reference HTML design
import { useEffect, useRef, useState } from 'react'

const NODE_TYPES = {
    system: { fill: 'rgba(58,66,96,.12)', stroke: '#3a4260', glyph: '⚙', gc: '#3a4260' },
    normal: { fill: 'rgba(0,229,255,.07)', stroke: '#00e5ff', glyph: '>_', gc: '#00e5ff' },
    suspicious: { fill: 'rgba(255,119,0,.09)', stroke: '#ff7700', glyph: '⚠', gc: '#ff7700' },
    malicious: { fill: 'rgba(255,32,85,.1)', stroke: '#ff2055', glyph: '☠', gc: '#ff2055' },
    unknown: { fill: 'rgba(58,66,96,.08)', stroke: '#3a4260', glyph: '?', gc: '#3a4260' },
}

function buildNodeInfo(node) {
    return [
        ['Process', node.name || '?', 'c'],
        node.user ? ['User', node.user, ''] : null,
        node.pid ? ['PID', String(node.pid), ''] : null,
        node.source ? ['Source', node.source, ''] : null,
        node.cmdline ? ['Command', node.cmdline.slice(0, 80) + (node.cmdline.length > 80 ? '...' : ''), ''] : null,
        node.action ? ['Action', node.action.label.slice(0, 80), 'r'] : null,
    ].filter(Boolean)
}

export function ProcessTree({ chain, loading, error }) {
    const canvasRef = useRef(null)
    const containerRef = useRef(null)
    const rafRef = useRef(null)
    const [selectedInfo, setSelectedInfo] = useState(null)
    const [selectedIdx, setSelectedIdx] = useState(-1)
    const hovRef = useRef(-1)
    const selRef = useRef(-1)

    useEffect(() => {
        if (!chain?.length || !canvasRef.current || !containerRef.current) return

        const cv = canvasRef.current
        const cont = containerRef.current
        const ctx = cv.getContext('2d')

        let W = cont.clientWidth - 180
        let H = cont.clientHeight || 260
        cv.width = W * 2
        cv.height = H * 2
        cv.style.width = W + 'px'
        cv.style.height = H + 'px'
        ctx.scale(2, 2)

        const nodes = chain
        const n = nodes.length
        const sp = Math.min(140, (W - 80) / Math.max(n, 1))
        const sx = (W - sp * (n - 1)) / 2
        const Y = H / 2
        const R = 38

        // Flow particles along edges
        const particles = []
        for (let i = 0; i < n - 1; i++) {
            for (let k = 0; k < 4; k++) {
                particles.push({
                    edge: i,
                    t: Math.random(),
                    speed: 0.003 + Math.random() * 0.003,
                    size: 1.2 + Math.random() * 0.8,
                })
            }
        }

        let prog = 0
        if (rafRef.current) cancelAnimationFrame(rafRef.current)

        function loop() {
            ctx.clearRect(0, 0, W, H)
            prog = Math.min(prog + 0.04, 1)
            const e3 = 1 - Math.pow(1 - prog, 3)
            const now = Date.now()

            // Draw edges
            for (let i = 0; i < n - 1; i++) {
                const x1 = sx + i * sp + R + 4
                const x2 = sx + (i + 1) * sp - R - 4
                const drawX2 = x1 + (x2 - x1) * Math.max(0, Math.min(1, e3 * n - i))
                const isFlag = nodes[i + 1]?.type === 'malicious' || nodes[i + 1]?.type === 'suspicious'

                ctx.save()
                ctx.beginPath()
                ctx.moveTo(x1, Y)
                ctx.lineTo(drawX2, Y)
                ctx.strokeStyle = isFlag ? 'rgba(255,32,85,.4)' : 'rgba(255,255,255,.1)'
                ctx.lineWidth = isFlag ? 1.5 : 1
                if (isFlag) ctx.setLineDash([5, 4])
                ctx.stroke()
                ctx.setLineDash([])

                // Arrowhead
                if (drawX2 >= x2 - 0.5) {
                    ctx.beginPath()
                    ctx.moveTo(x2 + 2, Y)
                    ctx.lineTo(x2 - 5, Y - 4)
                    ctx.lineTo(x2 - 5, Y + 4)
                    ctx.closePath()
                    ctx.fillStyle = isFlag ? 'rgba(255,32,85,.7)' : 'rgba(255,255,255,.25)'
                    ctx.fill()
                }
                ctx.restore()
            }

            // Flow particles
            if (prog >= 1) {
                particles.forEach(p => {
                    p.t += p.speed
                    if (p.t > 1) p.t -= 1
                    const i = p.edge
                    const x1 = sx + i * sp + R + 4
                    const x2 = sx + (i + 1) * sp - R - 4
                    const px = x1 + (x2 - x1) * p.t
                    const isFlag = nodes[i + 1]?.type === 'malicious' || nodes[i + 1]?.type === 'suspicious'
                    ctx.beginPath()
                    ctx.arc(px, Y, p.size, 0, Math.PI * 2)
                    ctx.fillStyle = isFlag ? 'rgba(255,32,85,.85)' : 'rgba(0,229,255,.65)'
                    ctx.fill()
                    // Trail
                    ctx.beginPath()
                    ctx.moveTo(px - 10 * p.speed * 50, Y)
                    ctx.lineTo(px, Y)
                    ctx.strokeStyle = isFlag ? 'rgba(255,32,85,.2)' : 'rgba(0,229,255,.15)'
                    ctx.lineWidth = 1
                    ctx.stroke()
                })
            }

            // Draw nodes
            for (let i = 0; i < n; i++) {
                const na = Math.max(0, Math.min(1, e3 * n * 1.2 - i))
                if (na <= 0) continue
                const nx = sx + i * sp
                const node = nodes[i]
                const c = NODE_TYPES[node.type] || NODE_TYPES.normal
                const isH = hovRef.current === i
                const isSel = selRef.current === i
                const isTarget = !!node.action
                const scale = na * (isH || isSel ? 1.1 : 1)

                ctx.save()
                ctx.translate(nx, Y)
                ctx.scale(scale, scale)
                ctx.globalAlpha = na

                // Pulsing aura for writer/malicious nodes
                if (isTarget || node.type === 'malicious') {
                    const pulse = (Math.sin(now / 600 + i) + 1) / 2
                    const auraR = R + 10 + pulse * 6
                    ctx.beginPath()
                    ctx.arc(0, 0, auraR, 0, Math.PI * 2)
                    ctx.strokeStyle = isTarget
                        ? `rgba(255,32,85,${0.08 + pulse * 0.18})`
                        : `rgba(0,229,255,${0.04 + pulse * 0.1})`
                    ctx.lineWidth = 1.5
                    ctx.setLineDash([4, 5])
                    ctx.stroke()
                    ctx.setLineDash([])
                    ctx.beginPath()
                    ctx.arc(0, 0, R + 4, 0, Math.PI * 2)
                    ctx.fillStyle = isTarget
                        ? `rgba(255,32,85,${0.04 + pulse * 0.06})`
                        : `rgba(0,229,255,${0.02 + pulse * 0.04})`
                    ctx.fill()
                }

                // Hop label above
                if (i > 0) {
                    ctx.font = '400 8px "JetBrains Mono",monospace'
                    ctx.textAlign = 'center'
                    ctx.textBaseline = 'middle'
                    ctx.fillStyle = 'rgba(58,66,96,.7)'
                    ctx.globalAlpha = na * 0.8
                    ctx.fillText(`HOP ${i}`, 0, -R - 12)
                    ctx.globalAlpha = na
                }

                // Selection ring
                if (isSel) {
                    ctx.beginPath()
                    ctx.arc(0, 0, R + 7, 0, Math.PI * 2)
                    ctx.strokeStyle = 'rgba(0,229,255,.6)'
                    ctx.lineWidth = 1.5
                    ctx.stroke()
                }

                // Main circle
                ctx.beginPath()
                ctx.arc(0, 0, R, 0, Math.PI * 2)
                ctx.fillStyle = c.fill
                ctx.fill()
                ctx.strokeStyle = c.stroke
                ctx.lineWidth = isH || isSel ? 2 : 1.5
                ctx.globalAlpha = na * (isH || isSel ? 1 : 0.8)
                ctx.stroke()
                ctx.globalAlpha = na

                // Glyph
                ctx.font = '600 14px "JetBrains Mono",monospace'
                ctx.textAlign = 'center'
                ctx.textBaseline = 'middle'
                ctx.fillStyle = c.gc
                ctx.fillText(node.name?.slice(0, 3) || c.glyph, 0, 0)

                // Label below
                ctx.globalAlpha = na * 0.95
                ctx.font = '600 11px "Space Grotesk","DM Sans",sans-serif'
                ctx.fillStyle = 'rgba(238,242,255,.95)'
                ctx.fillText(node.name || '?', 0, R + 15)
                ctx.font = '400 9px "JetBrains Mono",monospace'
                ctx.fillStyle = 'rgba(106,117,144,.8)'
                const userLabel = node.user ? node.user.split('\\').pop() : ''
                ctx.fillText(userLabel, 0, R + 27)
                if (node.pid) {
                    ctx.fillStyle = 'rgba(58,66,96,.6)'
                    ctx.fillText(node.pid, 0, -R - 12)
                }
                ctx.globalAlpha = 1
                ctx.restore()
            }

            rafRef.current = requestAnimationFrame(loop)
        }

        // Mouse interaction
        cv.onmousemove = ev => {
            const rect = cv.getBoundingClientRect()
            const mx = ev.clientX - rect.left
            const my = ev.clientY - rect.top
            let h = -1
            for (let i = 0; i < n; i++) {
                if (Math.hypot(mx - (sx + i * sp), my - Y) <= R + 6) { h = i; break }
            }
            if (h !== hovRef.current) {
                hovRef.current = h
                cv.style.cursor = h >= 0 ? 'pointer' : 'default'
            }
        }
        cv.onmouseleave = () => { hovRef.current = -1; cv.style.cursor = 'default' }
        cv.onclick = ev => {
            const rect = cv.getBoundingClientRect()
            const mx = ev.clientX - rect.left
            const my = ev.clientY - rect.top
            for (let i = 0; i < n; i++) {
                if (Math.hypot(mx - (sx + i * sp), my - Y) <= R + 6) {
                    selRef.current = i
                    setSelectedIdx(i)
                    setSelectedInfo(buildNodeInfo(nodes[i]))
                    return
                }
            }
        }

        rafRef.current = requestAnimationFrame(loop)
        return () => {
            if (rafRef.current) cancelAnimationFrame(rafRef.current)
        }
    }, [chain])

    if (loading) return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '40px 20px', color: 'var(--dim)' }}>
            <svg width="20" height="20" viewBox="0 0 20 20">
                <circle cx="10" cy="10" r="8" fill="none" stroke="rgba(0,229,255,.15)" strokeWidth="2" />
                <circle cx="10" cy="10" r="8" fill="none" stroke="var(--cyan)" strokeWidth="2"
                    strokeLinecap="round" strokeDasharray="12 38"
                    style={{ transformOrigin: '50% 50%', animation: 'rh-spin 0.75s linear infinite' }} />
                <style>{`@keyframes rh-spin{to{transform:rotate(360deg)}}`}</style>
            </svg>
            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: 'var(--dim)' }}>
                Building attack chain...
            </span>
        </div>
    )

    if (error) return (
        <div style={{ padding: '24px 20px', fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: 'var(--red)' }}>
            ✗ Failed to load chain
        </div>
    )

    if (!chain?.length) return (
        <div style={{ padding: '24px 20px', fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: 'var(--dim)' }}>
            No chain data available
        </div>
    )

    return (
        <div ref={containerRef} style={{ position: 'relative', height: '100%', display: 'flex', flexDirection: 'column' }}>
            {/* Canvas area */}
            <div style={{ flex: 1, position: 'relative', minHeight: 200 }}>
                <canvas ref={canvasRef} style={{ position: 'absolute', inset: 0 }} />

                {/* Node inspector panel — right side */}
                <div style={{
                    position: 'absolute', right: 0, top: 0, bottom: 0, width: 175,
                    background: 'rgba(12,15,24,.92)', borderLeft: '1px solid rgba(255,255,255,.07)',
                    padding: '14px 13px', overflowY: 'auto', backdropFilter: 'blur(10px)',
                }}>
                    <div style={{
                        fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700,
                        letterSpacing: '.18em', textTransform: 'uppercase', color: 'var(--dim)',
                        marginBottom: 12, paddingBottom: 8, borderBottom: '1px solid rgba(255,255,255,.05)',
                    }}>
                        Node Details
                    </div>
                    {!selectedInfo ? (
                        <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: 'var(--dim)' }}>
                            click a node to inspect
                        </div>
                    ) : (
                        selectedInfo.map(([k, v, c], i) => (
                            <div key={i} style={{
                                marginBottom: 10, opacity: 0, transform: 'translateX(6px)',
                                animation: `nip-in .25s ease ${i * 0.05}s forwards`,
                            }}>
                                <style>{`@keyframes nip-in{to{opacity:1;transform:translateX(0)}}`}</style>
                                <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, color: 'var(--dim)', marginBottom: 2, textTransform: 'uppercase', letterSpacing: '.08em' }}>
                                    {k}
                                </div>
                                <div style={{
                                    fontFamily: "'JetBrains Mono',monospace", fontSize: 9,
                                    color: c === 'c' ? 'var(--cyan)' : c === 'r' ? 'var(--red)' : c === 'g' ? 'var(--green)' : 'var(--mid)',
                                    wordBreak: 'break-all', lineHeight: 1.45,
                                }}>
                                    {v}
                                </div>
                            </div>
                        ))
                    )}
                </div>
            </div>
        </div>
    )
}