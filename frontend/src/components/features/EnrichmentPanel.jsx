// src/components/features/EnrichmentPanel.jsx
import { useEffect, useRef } from 'react'

const ACCENT = {
    red:    '#ff2055',
    green:  '#00e676',
    yellow: '#ffd60a',
    cyan:   '#00e5ff',
    purple: '#c470ff',
}

function Row({ label, value, mono = false, accent, small = false }) {
    const color = ACCENT[accent] || 'rgba(140,155,175,1)'
    const show  = value === null || value === undefined || value === '' ? '—' : value
    const isEmpty = show === '—'
    return (
        <div
            style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', gap:14, padding:'6px 0', borderBottom:'1px solid rgba(255,255,255,.04)', transition:'background .12s', cursor:'default' }}
            onMouseEnter={e => e.currentTarget.style.background='rgba(255,255,255,.02)'}
            onMouseLeave={e => e.currentTarget.style.background='transparent'}
        >
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, flexShrink:0, width:110, color:'rgba(53,64,96,.85)', textTransform:'uppercase', letterSpacing:'.06em' }}>
                {label}
            </span>
            <span style={{ fontFamily: mono ? "'JetBrains Mono',monospace" : "'Space Grotesk',sans-serif", fontSize: small ? 9 : 10, textAlign:'right', wordBreak:'break-all', color: isEmpty ? 'rgba(53,64,96,.5)' : color, opacity: isEmpty ? 0.5 : 1 }}>
                {show}
            </span>
        </div>
    )
}

function Section({ title, children, delay = 0, icon }) {
    const ref = useRef(null)
    useEffect(() => {
        const el = ref.current
        if (!el) return
        el.style.opacity = '0'; el.style.transform = 'translateY(8px)'
        const t = setTimeout(() => {
            el.style.transition = 'opacity .38s ease, transform .38s ease'
            el.style.opacity = '1'; el.style.transform = 'translateY(0)'
        }, delay)
        return () => clearTimeout(t)
    }, [delay])

    return (
        <div ref={ref} style={{ marginBottom:11 }}>
            <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:8, fontWeight:700, letterSpacing:'.16em', textTransform:'uppercase', color:'rgba(53,64,96,.85)', marginBottom:6, paddingLeft:2, display:'flex', alignItems:'center', gap:6 }}>
                {icon && <span style={{ opacity:.7 }}>{icon}</span>}
                {title}
            </div>
            <div style={{ background:'rgba(13,17,30,.92)', border:'1px solid rgba(255,255,255,.07)', borderRadius:8, overflow:'hidden' }}>
                <div style={{ padding:'0 13px' }}>
                    {children}
                </div>
            </div>
        </div>
    )
}

function RiskIndicator({ indicator, index }) {
    const c = indicator.severity === 'critical' ? '#ff2055' : indicator.severity === 'high' ? '#ff7722' : '#ffd60a'
    const ref = useRef(null)
    useEffect(() => {
        const el = ref.current
        if (!el) return
        el.style.opacity = '0'; el.style.transform = 'translateX(-7px)'
        const t = setTimeout(() => {
            el.style.transition = 'opacity .3s ease, transform .3s ease'
            el.style.opacity = '1'; el.style.transform = 'translateX(0)'
        }, index * 70)
        return () => clearTimeout(t)
    }, [index])

    return (
        <div ref={ref} style={{ padding:'10px 13px', borderRadius:8, background:'rgba(13,17,30,.92)', borderLeft:`3px solid ${c}`, border:`1px solid rgba(255,255,255,.07)`, borderLeftWidth:3, borderLeftColor:c, marginBottom:7, transition:'box-shadow .25s', cursor:'default' }}
            onMouseEnter={e => e.currentTarget.style.boxShadow=`0 0 18px ${c}18`}
            onMouseLeave={e => e.currentTarget.style.boxShadow='none'}
        >
            <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:8, fontWeight:700, textTransform:'uppercase', letterSpacing:'.12em', color:c, marginBottom:5, display:'flex', alignItems:'center', gap:6 }}>
                <span style={{ width:5, height:5, borderRadius:'50%', background:c, boxShadow:`0 0 6px ${c}`, flexShrink:0, display:'inline-block', animation: indicator.severity==='critical' ? 'rh-pip-pulse 1.8s ease-in-out infinite' : 'none' }} />
                {indicator.type.replace(/_/g, ' ')}
            </div>
            <div style={{ fontSize:11, color:'rgba(140,155,175,1)', lineHeight:1.55 }}>
                {indicator.description}
            </div>
        </div>
    )
}

function VTBar({ malicious, total }) {
    const pct = total > 0 ? (malicious / total) * 100 : 0
    const color = malicious > 0 ? '#ff2055' : '#00e676'
    const ref = useRef(null)
    useEffect(() => {
        if (!ref.current) return
        ref.current.style.width = '0%'
        setTimeout(() => { if (ref.current) { ref.current.style.transition = 'width .9s cubic-bezier(.16,1,.3,1)'; ref.current.style.width = pct + '%' } }, 80)
    }, [pct])
    return (
        <div style={{ marginTop:5 }}>
            <div style={{ height:2, background:'rgba(255,255,255,.05)', borderRadius:2, overflow:'hidden' }}>
                <div ref={ref} style={{ height:'100%', background:color, borderRadius:2, boxShadow:`0 0 6px ${color}60` }} />
            </div>
        </div>
    )
}

export function EnrichmentPanel({ enrichment, hideRisk = false }) {
    if (!enrichment) return (
        <>
            <style>{`@keyframes rh-bolt-float{0%,100%{transform:translateY(0) scale(1);opacity:.15}50%{transform:translateY(-6px) scale(1.05);opacity:.25}}`}</style>
            <div style={{ display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', padding:'64px 0', gap:14, textAlign:'center' }}>
                <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="rgba(0,229,255,.3)" strokeWidth="1.5" strokeLinecap="round" style={{ animation:'rh-bolt-float 3s ease-in-out infinite' }}>
                    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
                </svg>
                <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:11, color:'rgba(90,107,138,1)' }}>No enrichment data</div>
                <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:'rgba(53,64,96,1)' }}>Trigger enrichment to analyse this entry</div>
            </div>
        </>
    )

    const { risk_indicators = [] } = enrichment

    return (
        <>
            <style>{`
                @keyframes rh-pip-pulse{0%,100%{box-shadow:0 0 4px #ff2055}50%{box-shadow:0 0 12px #ff2055,0 0 20px rgba(255,32,85,.3)}}
            `}</style>
            <div style={{ display:'flex', flexDirection:'column', gap:0, maxWidth:680 }}>

                {!hideRisk && risk_indicators.length > 0 && (
                    <div style={{ marginBottom:18 }}>
                        <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:8, fontWeight:700, letterSpacing:'.16em', textTransform:'uppercase', color:'rgba(53,64,96,.85)', marginBottom:8, display:'flex', alignItems:'center', gap:8 }}>
                            Risk Indicators
                            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:8, padding:'1px 6px', borderRadius:3, background:'rgba(255,32,85,.1)', color:'#ff2055', border:'1px solid rgba(255,32,85,.25)' }}>
                                {risk_indicators.length}
                            </span>
                        </div>
                        {risk_indicators.map((ind, i) => <RiskIndicator key={i} indicator={ind} index={i} />)}
                    </div>
                )}

                {enrichment.sha256 && (
                    <Section title="Hashes" delay={80} icon="#">
                        <Row label="SHA-256" value={enrichment.sha256} mono accent="cyan" small />
                        <Row label="SHA-1"   value={enrichment.sha1}   mono accent="cyan" small />
                        <Row label="MD5"     value={enrichment.md5}    mono accent="cyan" small />
                    </Section>
                )}

                <Section title="File Info" delay={150} icon="📄">
                    <Row label="Exists"    value={enrichment.file_exists ? 'Yes' : 'Not found'} accent={enrichment.file_exists ? 'green' : 'red'} />
                    <Row label="Size"      value={enrichment.file_size ? `${(enrichment.file_size/1024).toFixed(1)} KB` : null} />
                    <Row label="Signed"    value={enrichment.pe_signed ? 'Yes' : 'No'} accent={enrichment.pe_signed ? 'green' : 'red'} />
                    <Row label="Publisher" value={enrichment.pe_publisher} />
                    <Row label="PE"        value={enrichment.pe_is_pe ? 'Yes' : 'No'} />
                    <Row label="Compiled"  value={enrichment.pe_compile_time?.slice(0,10)} accent={enrichment.pe_compile_suspicious ? 'red' : undefined} mono />
                    <Row label="Entropy"   value={enrichment.pe_entropy_high ? 'High ⚠' : 'Normal'} accent={enrichment.pe_entropy_high ? 'yellow' : 'green'} />
                </Section>

                {(enrichment.vt_found !== null || enrichment.mb_found !== null) && (
                    <Section title="Threat Intel" delay={220} icon="🛡">
                        {enrichment.vt_total > 0 && (
                            <div style={{ padding:'6px 0', borderBottom:'1px solid rgba(255,255,255,.04)' }}>
                                <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', gap:14 }}>
                                    <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:'rgba(53,64,96,.85)', textTransform:'uppercase', letterSpacing:'.06em' }}>VirusTotal</span>
                                    <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:10, color: enrichment.vt_malicious > 0 ? '#ff2055' : '#00e676' }}>
                                        {enrichment.vt_malicious}/{enrichment.vt_total}
                                    </span>
                                </div>
                                <VTBar malicious={enrichment.vt_malicious} total={enrichment.vt_total} />
                            </div>
                        )}
                        {enrichment.mb_found !== null && (
                            <Row label="MalwareBazaar" value={enrichment.mb_found ? `Hit — ${enrichment.mb_signature || 'unknown'}` : 'Not found'} accent={enrichment.mb_found ? 'red' : 'green'} />
                        )}
                        <Row
                            label="Verdict"
                            value={(enrichment.overall_verdict || 'unknown').toUpperCase()}
                            mono
                            accent={enrichment.overall_verdict === 'malicious' ? 'red' : enrichment.overall_verdict === 'suspicious' ? 'yellow' : enrichment.overall_verdict === 'clean' ? 'green' : undefined}
                        />
                    </Section>
                )}
            </div>
        </>
    )
}