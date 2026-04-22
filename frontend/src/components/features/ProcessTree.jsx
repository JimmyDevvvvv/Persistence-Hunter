// src/components/features/ProcessTree.jsx
import { useEffect, useRef, useState, useCallback } from 'react'

const NODE_TYPES = {
    system:     { fill: 'rgba(58,66,96,.14)',  stroke: '#3a4260', gc: '#3a4260' },
    normal:     { fill: 'rgba(0,229,255,.08)', stroke: '#00e5ff', gc: '#00e5ff' },
    suspicious: { fill: 'rgba(255,119,0,.12)', stroke: '#ff7700', gc: '#ff7700' },
    malicious:  { fill: 'rgba(255,32,85,.13)', stroke: '#ff2055', gc: '#ff2055' },
    unknown:    { fill: 'rgba(58,66,96,.08)',  stroke: '#3a4260', gc: '#3a4260' },
}

const INTEGRITY_COLOR = {
    system: '#c470ff',
    high:   '#ff7700',
    medium: '#00e5ff',
    low:    '#00e676',
}

const PROC_GLYPHS = [
    [/^powershell(\.exe)?$/i, 'PS'],
    [/^pwsh(\.exe)?$/i,       'PS'],
    [/^cmd(\.exe)?$/i,        'CMD'],
    [/^reg(\.exe)?$/i,        'REG'],
    [/^explorer(\.exe)?$/i,   'EXP'],
    [/^wscript(\.exe)?$/i,    'WSH'],
    [/^cscript(\.exe)?$/i,    'CS'],
    [/^rundll32(\.exe)?$/i,   'R32'],
    [/^mshta(\.exe)?$/i,      'HTA'],
    [/^schtasks(\.exe)?$/i,   'SCH'],
    [/^sc(\.exe)?$/i,         'SC'],
    [/^msiexec(\.exe)?$/i,    'MSI'],
    [/^certutil(\.exe)?$/i,   'CRT'],
    [/^regsvr32(\.exe)?$/i,   'RSV'],
    [/^wmic(\.exe)?$/i,       'WMI'],
    [/^svchost(\.exe)?$/i,    'SVC'],
    [/^lsass(\.exe)?$/i,      'LSS'],
    [/^services(\.exe)?$/i,   'SER'],
]

function glyphForProcess(name) {
    const base = String(name || '').split(/[\\/]/).pop()
    for (const [re, g] of PROC_GLYPHS) if (re.test(base)) return g
    return (base || '?').slice(0, 3).toUpperCase()
}

function fmtHash(h) {
    if (!h) return null
    const s = String(h)
    return s.length <= 16 ? s : `${s.slice(0, 8)}…${s.slice(-6)}`
}

// Normalise base_collector node field names
function normaliseNode(node) {
    const hashes = node.hashes || {}
    return {
        ...node,
        name:      node.process_name  || node.name     || '?',
        path:      node.image_path    || node.process_path || node.path || '',
        user:      node.user_name     || node.user      || '',
        cmdline:   node.command_line  || node.cmdline   || '',
        pid:       node.pid,
        ppid:      node.parent_pid    || node.ppid,
        integrity: node.integrity_level || node.integrity || '',
        hashes,
        source:    node._source_table || node.writer_source || node.source || '',
        type:      node.node_type     || node.type      || 'normal',
        action:    node.action,
    }
}

function buildNodeInfo(raw) {
    const node  = normaliseNode(raw)
    const h     = node.hashes || {}
    const sha256 = h.SHA256 || h.SHA_256 || h.sha256
    const md5    = h.MD5    || h.md5
    const sha1   = h.SHA1   || h.SHA_1  || h.sha1
    const intCol = INTEGRITY_COLOR[(node.integrity || '').toLowerCase()] || 'rgba(140,155,175,1)'

    return {
        name: node.name, cmdline: node.cmdline,
        integrity: node.integrity, integrityColor: intCol,
        type: node.type,
        items: [
            { k:'pid',       label:'PID',       v: node.pid  ? String(node.pid)  : null },
            { k:'ppid',      label:'PPID',      v: node.ppid ? String(node.ppid) : null },
            { k:'user',      label:'User',      v: node.user  || null },
            { k:'integrity', label:'Integrity', v: node.integrity || null, color: intCol },
            { k:'source',    label:'Source',    v: node.source || null },
            { k:'path',      label:'Image',     v: node.path  || null, mono:true, small:true },
            { k:'sha256',    label:'SHA-256',   v: sha256 ? fmtHash(sha256) : null, mono:true, copy:sha256 },
            { k:'md5',       label:'MD5',       v: md5    ? fmtHash(md5)    : null, mono:true, copy:md5 },
            { k:'sha1',      label:'SHA-1',     v: sha1   ? fmtHash(sha1)   : null, mono:true, copy:sha1 },
            node.action ? { k:'action', label:'Action', v:(node.action?.label||'').slice(0,120), color:'#ff2055' } : null,
        ].filter(r => r && r.v),
    }
}

// ── Canvas ──────────────────────────────────────────────────────────────────
function TreeCanvas({ chain, onSelect, selectedIdx }) {
    const canvasRef    = useRef(null)
    const containerRef = useRef(null)
    const rafRef       = useRef(null)
    const hovRef       = useRef(-1)
    const selRef       = useRef(selectedIdx ?? -1)

    useEffect(() => { selRef.current = selectedIdx ?? -1 }, [selectedIdx])

    useEffect(() => {
        if (!chain?.length || !canvasRef.current || !containerRef.current) return
        const cv   = canvasRef.current
        const cont = containerRef.current
        const ctx  = cv.getContext('2d')
        const nodes = chain.map(normaliseNode)
        const n     = nodes.length
        const DPR   = window.devicePixelRatio || 2

        function resize() {
            const W = cont.clientWidth
            const H = cont.clientHeight || 220
            cv.width  = W * DPR; cv.height = H * DPR
            cv.style.width = W+'px'; cv.style.height = H+'px'
            ctx.setTransform(DPR, 0, 0, DPR, 0, 0)
            return { W, H }
        }
        let { W, H } = resize()

        const R  = Math.max(22, Math.min(34, (W - 80) / n / 2 - 4))
        const sp = Math.min(130, (W - 60) / Math.max(n - 1, 1))
        const sx = (W - sp * (n - 1)) / 2
        const Y  = H / 2

        const particles = []
        for (let i = 0; i < n - 1; i++) {
            for (let k = 0; k < 5; k++) {
                particles.push({ edge:i, t:Math.random(), speed:0.002+Math.random()*0.003, size:0.9+Math.random()*0.9 })
            }
        }

        let prog = 0
        if (rafRef.current) cancelAnimationFrame(rafRef.current)

        function draw() {
            ctx.clearRect(0, 0, W, H)
            prog = Math.min(prog + 0.032, 1)
            const e3  = 1 - Math.pow(1 - prog, 3)
            const now = Date.now()

            // Edges
            for (let i = 0; i < n - 1; i++) {
                const x1 = sx + i * sp + R + 3
                const x2 = sx + (i+1) * sp - R - 3
                const drawX2 = x1 + (x2-x1) * Math.max(0, Math.min(1, e3 * n * 1.1 - i))
                const isBad  = ['malicious','suspicious'].includes(nodes[i+1]?.type)

                ctx.save()
                if (isBad && drawX2 >= x2 - 1) { ctx.shadowColor = '#ff205580'; ctx.shadowBlur = 8 }
                ctx.beginPath(); ctx.moveTo(x1, Y); ctx.lineTo(drawX2, Y)
                ctx.strokeStyle = isBad ? 'rgba(255,32,85,.5)' : 'rgba(0,229,255,.2)'
                ctx.lineWidth = isBad ? 1.5 : 1
                if (isBad) ctx.setLineDash([5,4])
                ctx.stroke(); ctx.setLineDash([]); ctx.shadowBlur = 0

                if (drawX2 >= x2 - 0.5) {
                    ctx.beginPath(); ctx.moveTo(x2+2,Y); ctx.lineTo(x2-5,Y-3.5); ctx.lineTo(x2-5,Y+3.5); ctx.closePath()
                    ctx.fillStyle = isBad ? 'rgba(255,32,85,.85)' : 'rgba(0,229,255,.4)'
                    ctx.fill()
                }
                ctx.restore()
            }

            // Particles
            if (prog >= 1) {
                particles.forEach(p => {
                    p.t += p.speed; if (p.t > 1) p.t -= 1
                    const i  = p.edge
                    const x1 = sx + i * sp + R + 3
                    const x2 = sx + (i+1) * sp - R - 3
                    const px = x1 + (x2-x1) * p.t
                    const isBad = ['malicious','suspicious'].includes(nodes[i+1]?.type)
                    ctx.beginPath(); ctx.arc(px, Y, p.size, 0, Math.PI*2)
                    ctx.fillStyle = isBad ? `rgba(255,32,85,${0.55+p.size*0.2})` : `rgba(0,229,255,${0.45+p.size*0.15})`
                    ctx.fill()
                    ctx.beginPath(); ctx.moveTo(px - 14*p.speed*40, Y); ctx.lineTo(px, Y)
                    ctx.strokeStyle = isBad ? 'rgba(255,32,85,.14)' : 'rgba(0,229,255,.12)'
                    ctx.lineWidth = 1; ctx.stroke()
                })
            }

            // Nodes
            for (let i = 0; i < n; i++) {
                const na = Math.max(0, Math.min(1, e3 * n * 1.3 - i))
                if (na <= 0) continue
                const nx    = sx + i * sp
                const node  = nodes[i]
                const c     = NODE_TYPES[node.type] || NODE_TYPES.normal
                const isH   = hovRef.current === i
                const isSel = selRef.current === i
                const isBad = node.type === 'malicious' || !!node.action
                const pulse = (Math.sin(now / 700 + i * 1.3) + 1) / 2
                const intCol = INTEGRITY_COLOR[(node.integrity || '').toLowerCase()]

                ctx.save(); ctx.translate(nx, Y); ctx.globalAlpha = na

                // Outer pulse aura
                if (isBad) {
                    const auraR = R + 10 + pulse * 9
                    ctx.beginPath(); ctx.arc(0, 0, auraR, 0, Math.PI*2)
                    ctx.strokeStyle = node.type === 'malicious'
                        ? `rgba(255,32,85,${0.05+pulse*0.18})`
                        : `rgba(255,119,0,${0.05+pulse*0.14})`
                    ctx.lineWidth = 1.5; ctx.setLineDash([3,5]); ctx.stroke(); ctx.setLineDash([])
                }

                // Selection ring
                if (isSel) {
                    ctx.beginPath(); ctx.arc(0, 0, R+8, 0, Math.PI*2)
                    ctx.strokeStyle = c.stroke+'bb'; ctx.lineWidth = 2
                    ctx.shadowColor = c.stroke; ctx.shadowBlur = 16; ctx.stroke(); ctx.shadowBlur = 0
                } else if (isH) {
                    ctx.beginPath(); ctx.arc(0, 0, R+5, 0, Math.PI*2)
                    ctx.strokeStyle = c.stroke+'44'; ctx.lineWidth = 1; ctx.stroke()
                }

                // Main fill
                ctx.beginPath(); ctx.arc(0, 0, R, 0, Math.PI*2)
                ctx.fillStyle = c.fill; ctx.fill()
                ctx.strokeStyle = c.stroke
                ctx.lineWidth = isH||isSel ? 2 : 1.5
                ctx.globalAlpha = na * (isH||isSel ? 1 : 0.78)
                if (isBad) { ctx.shadowColor = c.stroke; ctx.shadowBlur = 9 }
                ctx.stroke(); ctx.shadowBlur = 0; ctx.globalAlpha = na

                // Integrity ring (thin inner)
                if (intCol) {
                    ctx.beginPath(); ctx.arc(0, 0, R-5, 0, Math.PI*2)
                    ctx.strokeStyle = intCol+'50'; ctx.lineWidth = 2; ctx.stroke()
                }

                // Glyph
                const glyphPx = R > 28 ? 11 : 9
                ctx.font = `700 ${glyphPx}px "JetBrains Mono",monospace`
                ctx.textAlign = 'center'; ctx.textBaseline = 'middle'
                ctx.fillStyle = c.gc
                if (isBad) { ctx.shadowColor = c.gc; ctx.shadowBlur = 7 }
                ctx.fillText(glyphForProcess(node.name), 0, 0); ctx.shadowBlur = 0

                // PID top
                if (node.pid) {
                    ctx.font = `400 7px "JetBrains Mono",monospace`
                    ctx.fillStyle = 'rgba(58,66,96,.6)'; ctx.globalAlpha = na * 0.65
                    ctx.fillText(`PID ${node.pid}`, 0, -R-10); ctx.globalAlpha = na
                }

                // Name below
                ctx.font = `600 10px "Space Grotesk","DM Sans",sans-serif`
                ctx.fillStyle = 'rgba(238,242,255,.95)'; ctx.globalAlpha = na * 0.92
                ctx.fillText(node.name || '?', 0, R+14)

                // Integrity / user sub-label
                const sub = node.integrity || (node.user ? node.user.split('\\').pop() : '')
                if (sub) {
                    ctx.font = `400 8px "JetBrains Mono",monospace`
                    ctx.fillStyle = intCol || 'rgba(106,117,144,.7)'
                    ctx.fillText(sub, 0, R+25)
                }

                ctx.globalAlpha = 1; ctx.restore()
            }

            rafRef.current = requestAnimationFrame(draw)
        }

        function hit(mx, my) {
            for (let i = 0; i < n; i++) if (Math.hypot(mx-(sx+i*sp), my-Y) <= R+7) return i
            return -1
        }
        cv.onmousemove = ev => {
            const r = cv.getBoundingClientRect()
            const h = hit(ev.clientX - r.left, ev.clientY - r.top)
            if (h !== hovRef.current) { hovRef.current = h; cv.style.cursor = h >= 0 ? 'pointer' : 'default' }
        }
        cv.onmouseleave = () => { hovRef.current = -1; cv.style.cursor = 'default' }
        cv.onclick = ev => {
            const r = cv.getBoundingClientRect()
            const h = hit(ev.clientX - r.left, ev.clientY - r.top)
            if (h >= 0) { selRef.current = h; onSelect(h, nodes[h]) }
        }

        rafRef.current = requestAnimationFrame(draw)
        return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current) }
    }, [chain])

    return (
        <div ref={containerRef} style={{ width:'100%', height:'100%', position:'relative' }}>
            <canvas ref={canvasRef} style={{ position:'absolute', inset:0, width:'100%', height:'100%' }} />
        </div>
    )
}

// ── Inspector ────────────────────────────────────────────────────────────────
function Inspector({ info, onCopy }) {
    const typeColor = { malicious:'#ff2055', suspicious:'#ff7700', normal:'#00e5ff', system:'#3a4260' }[info?.type] || '#5a6b8a'

    if (!info) return (
        <div style={{ display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', height:'100%', gap:10, padding:'20px 16px', textAlign:'center' }}>
            <div style={{ width:32, height:32, borderRadius:'50%', border:'1px dashed rgba(58,66,96,.55)', display:'flex', alignItems:'center', justifyContent:'center' }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="rgba(58,66,96,.75)" strokeWidth="2">
                    <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
                </svg>
            </div>
            <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:'rgba(58,66,96,.85)', lineHeight:1.7 }}>
                Click a node<br/>to inspect
            </div>
        </div>
    )

    return (
        <div style={{ padding:'10px 12px', display:'flex', flexDirection:'column', gap:9 }}>
            <style>{`@keyframes ni-in{from{opacity:0;transform:translateX(7px)}to{opacity:1;transform:translateX(0)}}`}</style>

            {/* Header badge */}
            <div style={{ borderRadius:8, padding:'8px 10px', background:`${typeColor}0f`, border:`1px solid ${typeColor}28`, animation:'ni-in .2s ease' }}>
                <div style={{ display:'flex', alignItems:'center', gap:6, marginBottom:4 }}>
                    <div style={{ width:6, height:6, borderRadius:'50%', background:typeColor, boxShadow:`0 0 8px ${typeColor}` }} />
                    <span style={{ fontFamily:"'Space Grotesk',sans-serif", fontSize:11, fontWeight:700, color:'rgba(238,242,255,.95)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                        {info.name}
                    </span>
                </div>
                <div style={{ display:'flex', alignItems:'center', gap:5, flexWrap:'wrap' }}>
                    <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:7, fontWeight:700, letterSpacing:'.12em', textTransform:'uppercase', color:typeColor }}>
                        {info.type}
                    </span>
                    {info.integrity && (
                        <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:7, padding:'1px 5px', borderRadius:3, background:`${info.integrityColor}18`, border:`1px solid ${info.integrityColor}35`, color:info.integrityColor }}>
                            {info.integrity}
                        </span>
                    )}
                </div>
            </div>

            {/* Command line */}
            {info.cmdline && (
                <div style={{ borderRadius:7, padding:'8px 10px', background:'rgba(15,19,32,.9)', border:'1px solid rgba(255,255,255,.07)', animation:'ni-in .22s ease .04s both' }}>
                    <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:5 }}>
                        <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:7, letterSpacing:'.12em', textTransform:'uppercase', color:'rgba(0,229,255,.65)' }}>⌘ cmdline</span>
                        <button onClick={() => onCopy(info.cmdline)} style={{ border:'1px solid rgba(0,229,255,.22)', background:'rgba(0,229,255,.06)', color:'#00e5ff', borderRadius:4, padding:'1px 6px', fontFamily:"'JetBrains Mono',monospace", fontSize:7, cursor:'pointer' }}>
                            Copy
                        </button>
                    </div>
                    <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:8, color:'rgba(192,200,224,.85)', whiteSpace:'pre-wrap', wordBreak:'break-word', lineHeight:1.6, maxHeight:80, overflowY:'auto' }}>
                        {info.cmdline}
                    </div>
                </div>
            )}

            {/* Fields */}
            {info.items.length > 0 && (
                <div style={{ borderRadius:7, overflow:'hidden', border:'1px solid rgba(255,255,255,.06)', background:'rgba(15,19,32,.9)', animation:'ni-in .24s ease .07s both' }}>
                    {info.items.map((row, i) => (
                        <div key={row.k+i} style={{ padding:'5px 9px', borderBottom: i < info.items.length-1 ? '1px solid rgba(255,255,255,.04)' : 'none', display:'flex', alignItems:'flex-start', justifyContent:'space-between', gap:6 }}>
                            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:7, color:'rgba(58,66,96,.85)', textTransform:'uppercase', letterSpacing:'.07em', flexShrink:0, paddingTop:1 }}>
                                {row.label}
                            </span>
                            <div style={{ display:'flex', alignItems:'center', gap:4, minWidth:0 }}>
                                <span style={{ fontFamily: row.mono ? "'JetBrains Mono',monospace" : "'Space Grotesk',sans-serif", fontSize: row.small ? 7 : 8, color: row.color || (row.mono ? 'rgba(0,229,255,.85)' : 'rgba(140,155,175,1)'), wordBreak:'break-all', textAlign:'right' }}>
                                    {row.v}
                                </span>
                                {row.copy && (
                                    <button onClick={() => onCopy(row.copy)} style={{ flexShrink:0, border:'1px solid rgba(255,255,255,.07)', background:'rgba(255,255,255,.03)', color:'rgba(106,117,144,.8)', borderRadius:4, padding:'1px 4px', fontFamily:"'JetBrains Mono',monospace", fontSize:7, cursor:'pointer' }}>⎘</button>
                                )}
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    )
}

// ── Breadcrumb ───────────────────────────────────────────────────────────────
function Breadcrumb({ chain, selectedIdx, onSelect }) {
    const nodes = (chain || []).map(normaliseNode)
    if (!nodes.length) return null
    const tc = n => ({ malicious:'#ff2055', suspicious:'#ff7700', normal:'#00e5ff', system:'#3a4260' }[n?.type] || '#5a6b8a')

    return (
        <div style={{ display:'flex', alignItems:'center', flexWrap:'wrap', gap:2, padding:'5px 12px', borderTop:'1px solid rgba(255,255,255,.05)', background:'rgba(9,12,21,.55)', backdropFilter:'blur(8px)' }}>
            {nodes.map((node, i) => (
                <div key={i} style={{ display:'flex', alignItems:'center', gap:2 }}>
                    <button onClick={() => onSelect(i, node)} style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:8, padding:'2px 7px', borderRadius:4, cursor:'pointer', border:`1px solid ${selectedIdx===i ? tc(node)+'55' : 'rgba(255,255,255,.06)'}`, background: selectedIdx===i ? `${tc(node)}12` : 'transparent', color: selectedIdx===i ? tc(node) : 'rgba(106,117,144,.75)', transition:'all .15s' }}>
                        {node.name || '?'}
                    </button>
                    {i < nodes.length - 1 && (
                        <svg width="7" height="7" viewBox="0 0 24 24" fill="none" stroke="rgba(58,66,96,.5)" strokeWidth="2.5"><path d="M9 18l6-6-6-6"/></svg>
                    )}
                </div>
            ))}
        </div>
    )
}

// ── Copy toast ───────────────────────────────────────────────────────────────
function CopyToast({ show }) {
    return (
        <div style={{ position:'absolute', bottom:52, left:'50%', transform:`translateX(-50%) translateY(${show?0:8}px)`, opacity:show?1:0, transition:'all .2s ease', background:'rgba(0,229,255,.12)', border:'1px solid rgba(0,229,255,.3)', borderRadius:6, padding:'4px 12px', pointerEvents:'none', zIndex:10, fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:'#00e5ff', whiteSpace:'nowrap' }}>
            ✓ Copied to clipboard
        </div>
    )
}

// ── Legend ───────────────────────────────────────────────────────────────────
function Legend() {
    const items = [
        { color:'#3a4260', label:'System' },
        { color:'#00e5ff', label:'Normal' },
        { color:'#ff7700', label:'Suspicious' },
        { color:'#ff2055', label:'Malicious' },
    ]
    const int = [
        { color:'#c470ff', label:'SYSTEM' },
        { color:'#ff7700', label:'HIGH' },
        { color:'#00e5ff', label:'MED' },
        { color:'#00e676', label:'LOW' },
    ]
    return (
        <div style={{ display:'flex', alignItems:'center', gap:16, padding:'5px 14px', borderBottom:'1px solid rgba(255,255,255,.05)', background:'rgba(9,12,21,.4)' }}>
            <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                {items.map(({ color, label }) => (
                    <div key={label} style={{ display:'flex', alignItems:'center', gap:4 }}>
                        <div style={{ width:7, height:7, borderRadius:'50%', background:color, boxShadow:`0 0 5px ${color}80` }} />
                        <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:7, color:'rgba(58,66,96,.8)', textTransform:'uppercase', letterSpacing:'.06em' }}>{label}</span>
                    </div>
                ))}
            </div>
            <div style={{ width:1, height:12, background:'rgba(255,255,255,.06)' }} />
            <div style={{ display:'flex', alignItems:'center', gap:3 }}>
                <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:7, color:'rgba(58,66,96,.55)', textTransform:'uppercase', letterSpacing:'.06em', marginRight:4 }}>Integrity:</span>
                {int.map(({ color, label }) => (
                    <span key={label} style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:7, padding:'1px 5px', borderRadius:3, background:`${color}14`, border:`1px solid ${color}30`, color }}>{label}</span>
                ))}
            </div>
        </div>
    )
}

// ── Main ─────────────────────────────────────────────────────────────────────
export function ProcessTree({ chain, loading, error }) {
    const [selectedIdx,  setSelectedIdx]  = useState(null)
    const [selectedInfo, setSelectedInfo] = useState(null)
    const [copyShow,     setCopyShow]     = useState(false)
    const copyTimer = useRef(null)

    const handleSelect = useCallback((idx, rawNode) => {
        setSelectedIdx(idx); setSelectedInfo(buildNodeInfo(rawNode))
    }, [])

    const handleCopy = useCallback(text => {
        navigator.clipboard?.writeText(text)
        setCopyShow(true); clearTimeout(copyTimer.current)
        copyTimer.current = setTimeout(() => setCopyShow(false), 1800)
    }, [])

    if (loading) return (
        <div style={{ display:'flex', alignItems:'center', gap:12, padding:'40px 24px' }}>
            <svg width="18" height="18" viewBox="0 0 20 20">
                <circle cx="10" cy="10" r="8" fill="none" stroke="rgba(0,229,255,.15)" strokeWidth="2"/>
                <circle cx="10" cy="10" r="8" fill="none" stroke="#00e5ff" strokeWidth="2" strokeLinecap="round" strokeDasharray="12 38" style={{ transformOrigin:'50% 50%', animation:'rh-spin .75s linear infinite' }}/>
                <style>{`@keyframes rh-spin{to{transform:rotate(360deg)}}`}</style>
            </svg>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:11, color:'rgba(90,107,138,1)' }}>Building attack chain…</span>
        </div>
    )

    if (error) return (
        <div style={{ padding:'24px', fontFamily:"'JetBrains Mono',monospace", fontSize:11, color:'#ff2055' }}>✗ Failed to load chain</div>
    )

    if (!chain?.length) return (
        <div style={{ padding:'24px', fontFamily:"'JetBrains Mono',monospace", fontSize:11, color:'rgba(90,107,138,1)' }}>No chain data available</div>
    )

    return (
        <div style={{ position:'relative', height:'100%', display:'flex', flexDirection:'column', overflow:'hidden' }}>
            <Legend />

            <div style={{ flex:1, display:'flex', minHeight:0, position:'relative' }}>
                {/* Canvas */}
                <div style={{ flex:1, position:'relative', minWidth:0 }}>
                    <TreeCanvas chain={chain} onSelect={handleSelect} selectedIdx={selectedIdx} />
                    <CopyToast show={copyShow} />
                </div>

                {/* Inspector */}
                <div style={{ width:188, flexShrink:0, borderLeft:'1px solid rgba(255,255,255,.06)', background:'rgba(10,13,22,.88)', backdropFilter:'blur(14px)', display:'flex', flexDirection:'column', overflow:'hidden' }}>
                    <div style={{ padding:'7px 12px', borderBottom:'1px solid rgba(255,255,255,.05)', fontFamily:"'JetBrains Mono',monospace", fontSize:7, fontWeight:700, letterSpacing:'.18em', textTransform:'uppercase', color:'rgba(53,64,96,.85)', display:'flex', alignItems:'center', gap:5 }}>
                        <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="rgba(53,64,96,.85)" strokeWidth="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
                        Node Details
                    </div>
                    <div style={{ flex:1, overflowY:'auto' }}>
                        <Inspector info={selectedInfo} onCopy={handleCopy} />
                    </div>
                </div>
            </div>

            <Breadcrumb chain={chain} selectedIdx={selectedIdx} onSelect={handleSelect} />
        </div>
    )
}