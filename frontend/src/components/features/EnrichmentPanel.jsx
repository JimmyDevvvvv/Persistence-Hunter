// src/components/features/EnrichmentPanel.jsx
import { useEffect, useRef } from 'react'

const ACCENT_COLORS = {
    red: '#ff2055',
    green: '#00e676',
    yellow: '#ffd60a',
    cyan: '#00e5ff',
}

function Row({ label, value, mono = false, accent }) {
    const color = ACCENT_COLORS[accent] || 'rgba(140,155,175,1)'
    return (
        <div style={{
            display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between',
            gap: 16, padding: '8px 0',
            borderBottom: '1px solid rgba(255,255,255,0.05)',
            transition: 'background 0.15s',
        }}
            onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
        >
            <span style={{
                fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace",
                fontSize: 10, flexShrink: 0, width: 120, color: 'rgba(53,64,96,1)',
                textTransform: 'uppercase', letterSpacing: '0.06em',
            }}>
                {label}
            </span>
            <span style={{
                fontFamily: mono ? "'JetBrains Mono','IBM Plex Mono',monospace" : "'Space Grotesk',sans-serif",
                fontSize: 10, textAlign: 'right', wordBreak: 'break-all', color,
            }}>
                {value ?? '—'}
            </span>
        </div>
    )
}

function Section({ title, children, delay = 0 }) {
    const ref = useRef(null)
    useEffect(() => {
        const el = ref.current
        if (!el) return
        el.style.opacity = '0'
        el.style.transform = 'translateY(8px)'
        const t = setTimeout(() => {
            el.style.transition = 'opacity 0.4s ease, transform 0.4s ease'
            el.style.opacity = '1'
            el.style.transform = 'translateY(0)'
        }, delay)
        return () => clearTimeout(t)
    }, [delay])

    return (
        <div ref={ref} style={{ marginBottom: 12 }}>
            <div style={{
                fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace",
                fontSize: 8, fontWeight: 700, letterSpacing: '0.18em',
                textTransform: 'uppercase', color: 'rgba(53,64,96,1)',
                marginBottom: 6, paddingLeft: 2,
            }}>
                {title}
            </div>
            <div style={{
                background: 'rgba(15,19,32,0.9)',
                border: '1px solid rgba(255,255,255,0.07)',
                borderRadius: 8, overflow: 'hidden',
            }}>
                <div style={{ padding: '0 14px' }}>
                    {children}
                </div>
            </div>
        </div>
    )
}

function RiskIndicator({ indicator, index }) {
    const sevColor = indicator.severity === 'critical' ? '#ff2055'
        : indicator.severity === 'high' ? '#ff7722'
            : '#ffd60a'
    const ref = useRef(null)

    useEffect(() => {
        const el = ref.current
        if (!el) return
        el.style.opacity = '0'
        el.style.transform = 'translateX(-8px)'
        const t = setTimeout(() => {
            el.style.transition = 'opacity 0.35s ease, transform 0.35s ease'
            el.style.opacity = '1'
            el.style.transform = 'translateX(0)'
        }, index * 80)
        return () => clearTimeout(t)
    }, [index])

    return (
        <div
            ref={ref}
            style={{
                padding: '12px 14px',
                borderRadius: 8,
                background: 'rgba(15,19,32,0.9)',
                borderLeft: `3px solid ${sevColor}`,
                border: `1px solid rgba(255,255,255,0.07)`,
                borderLeftWidth: 3,
                borderLeftColor: sevColor,
                marginBottom: 8,
                transition: 'box-shadow 0.3s, border-color 0.3s',
                cursor: 'default',
            }}
            onMouseEnter={e => {
                e.currentTarget.style.boxShadow = `0 0 16px ${sevColor}18`
                e.currentTarget.style.borderRightColor = `${sevColor}20`
            }}
            onMouseLeave={e => {
                e.currentTarget.style.boxShadow = 'none'
                e.currentTarget.style.borderRightColor = 'rgba(255,255,255,0.07)'
            }}
        >
            <div style={{
                fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace",
                fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
                letterSpacing: '0.12em', color: sevColor, marginBottom: 5,
                display: 'flex', alignItems: 'center', gap: 6,
            }}>
                <span style={{
                    width: 5, height: 5, borderRadius: '50%',
                    background: sevColor, boxShadow: `0 0 6px ${sevColor}`,
                    flexShrink: 0,
                    animation: indicator.severity === 'critical' ? 'rh-pip-pulse 1.8s ease-in-out infinite' : 'none',
                }} />
                {indicator.type.replace(/_/g, ' ')}
            </div>
            <div style={{ fontSize: 11, color: 'rgba(140,155,175,1)', lineHeight: 1.55 }}>
                {indicator.description}
            </div>
        </div>
    )
}

export function EnrichmentPanel({ enrichment }) {
    if (!enrichment) {
        return (
            <>
                <style>{`
                    @keyframes rh-pip-pulse { 0%,100%{box-shadow:0 0 4px #ff2055}50%{box-shadow:0 0 12px #ff2055,0 0 20px rgba(255,32,85,0.3)} }
                    @keyframes rh-bolt-float { 0%,100%{transform:translateY(0) scale(1);opacity:0.15} 50%{transform:translateY(-6px) scale(1.05);opacity:0.25} }
                `}</style>
                <div style={{
                    display: 'flex', flexDirection: 'column', alignItems: 'center',
                    justifyContent: 'center', padding: '64px 0', gap: 14, textAlign: 'center',
                }}>
                    <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="rgba(0,229,255,0.3)"
                        strokeWidth="1.5" strokeLinecap="round"
                        style={{ animation: 'rh-bolt-float 3s ease-in-out infinite' }}>
                        <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
                    </svg>
                    <div style={{ fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace", fontSize: 11, color: 'rgba(90,107,138,1)' }}>
                        No enrichment data
                    </div>
                    <div style={{ fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace", fontSize: 9, color: 'rgba(53,64,96,1)' }}>
                        Trigger enrichment to analyse this file
                    </div>
                </div>
            </>
        )
    }

    const { risk_indicators = [] } = enrichment

    return (
        <>
            <style>{`
                @keyframes rh-pip-pulse { 0%,100%{box-shadow:0 0 4px #ff2055}50%{box-shadow:0 0 12px #ff2055,0 0 20px rgba(255,32,85,0.3)} }
            `}</style>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 0, maxWidth: 680 }}>

                {risk_indicators.length > 0 && (
                    <div style={{ marginBottom: 20 }}>
                        <div style={{
                            fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace",
                            fontSize: 8, fontWeight: 700, letterSpacing: '0.18em',
                            textTransform: 'uppercase', color: 'rgba(53,64,96,1)', marginBottom: 8,
                            display: 'flex', alignItems: 'center', gap: 8,
                        }}>
                            Risk Indicators
                            <span style={{
                                fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace",
                                fontSize: 8, padding: '1px 6px', borderRadius: 3,
                                background: 'rgba(255,32,85,0.1)', color: '#ff2055',
                                border: '1px solid rgba(255,32,85,0.25)',
                            }}>
                                {risk_indicators.length}
                            </span>
                        </div>
                        {risk_indicators.map((ind, i) => (
                            <RiskIndicator key={i} indicator={ind} index={i} />
                        ))}
                    </div>
                )}

                {enrichment.sha256 && (
                    <Section title="File Hashes" delay={100}>
                        <Row label="MD5" value={enrichment.md5} mono accent="cyan" />
                        <Row label="SHA1" value={enrichment.sha1} mono accent="cyan" />
                        <Row label="SHA256" value={enrichment.sha256} mono accent="cyan" />
                    </Section>
                )}

                <Section title="File Info" delay={200}>
                    <Row label="Exists" value={enrichment.file_exists ? 'Yes' : 'Not found'} accent={enrichment.file_exists ? 'green' : 'red'} />
                    <Row label="Size" value={enrichment.file_size ? `${(enrichment.file_size / 1024).toFixed(1)} KB` : null} />
                    <Row label="Signed" value={enrichment.pe_signed ? 'Yes' : 'No'} accent={enrichment.pe_signed ? 'green' : 'red'} />
                    <Row label="Publisher" value={enrichment.pe_publisher} />
                    <Row label="PE" value={enrichment.pe_is_pe ? 'Yes' : 'No'} />
                    <Row label="Compile Time" value={enrichment.pe_compile_time?.slice(0, 10)} accent={enrichment.pe_compile_suspicious ? 'red' : undefined} mono />
                    <Row label="Architecture" value={enrichment.pe_is_64bit ? '64-bit' : enrichment.pe_is_pe ? '32-bit' : null} />
                </Section>

                {(enrichment.vt_found !== null || enrichment.mb_found !== null) && (
                    <Section title="Threat Intel" delay={300}>
                        {enrichment.vt_total > 0 && (
                            <Row label="VirusTotal" value={`${enrichment.vt_malicious}/${enrichment.vt_total} detections`} accent={enrichment.vt_malicious > 0 ? 'red' : 'green'} />
                        )}
                        {enrichment.mb_found !== null && (
                            <Row label="MalwareBazaar" value={enrichment.mb_found ? `Hit — ${enrichment.mb_signature || 'unknown'}` : 'Not found'} accent={enrichment.mb_found ? 'red' : 'green'} />
                        )}
                        <Row label="Verdict"
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