// src/components/features/ThreatScore.jsx
// Animated threat score ring + APT attribution panel
import { useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { fetchScore, triggerScores } from '../../api/client'

// ── APT group background knowledge ─────────────────────────────
const APT_INTEL = {
    'APT29': {
        aka: ['Cozy Bear', 'The Dukes', 'NOBELIUM'],
        nation: 'Russia', flag: '🇷🇺',
        color: '#c470ff',
        summary: 'Russian SVR intelligence unit. Responsible for SolarWinds (2020), DNC breach (2016), COVID vaccine research theft. Specialises in living-off-the-land techniques, stealthy persistence, and long-dwell operations spanning years.',
        ttps: ['PowerShell persistence', 'IFEO hijacking', 'Scheduled task abuse', 'Supply chain compromise'],
    },
    'APT32': {
        aka: ['OceanLotus', 'SeaLotus'],
        nation: 'Vietnam', flag: '🇻🇳',
        color: '#00e5ff',
        summary: 'Vietnamese state-sponsored group targeting Southeast Asian governments, foreign corporations operating in Vietnam, and journalists. Known for macro-based initial access and AppData persistence patterns.',
        ttps: ['AppData Run key persistence', 'Macro-based delivery', 'Cobalt Strike deployment'],
    },
    'APT41': {
        aka: ['Double Dragon', 'Winnti', 'BARIUM'],
        nation: 'China', flag: '🇨🇳',
        color: '#ff7700',
        summary: 'Dual-purpose Chinese group conducting both espionage for the MSS and financially-motivated cybercrime. Notable for supply chain attacks (CCleaner, ASUS Live Update), ransomware, and exploiting internet-facing applications.',
        ttps: ['Service installation persistence', 'LOLBin chains', 'Supply chain injection', 'Ransomware deployment'],
    },
    'Lazarus': {
        aka: ['HIDDEN COBRA', 'Guardians of Peace'],
        nation: 'North Korea', flag: '🇰🇵',
        color: '#ff2055',
        summary: 'North Korean RGB-linked group, arguably the most prolific nation-state threat actor. Behind $2B+ in cryptocurrency theft, WannaCry ransomware, Sony Pictures hack, and extensive financial sector targeting. Uses Temp-directory service binaries and name masquerading extensively.',
        ttps: ['Temp directory service binaries', 'Name masquerading', 'Encoded scheduled tasks', 'Cryptocurrency theft'],
    },
    'FIN7': {
        aka: ['Carbanak', 'Navigator Group'],
        nation: 'Russia/Ukraine', flag: '🇷🇺',
        color: '#ffd60a',
        summary: 'Financially-motivated criminal group with nation-state sophistication. Responsible for $1B+ in theft from financial institutions and retailers. Known for IFEO hijacks, cmd→sc.exe service persistence, and highly targeted spearphishing.',
        ttps: ['IFEO accessibility hijack', 'cmd.exe→sc.exe service install', 'Carbanak malware framework'],
    },
    'Kimsuky': {
        aka: ['Velvet Chollima', 'Black Banshee'],
        nation: 'North Korea', flag: '🇰🇵',
        color: '#ff2055',
        summary: 'North Korean reconnaissance unit focused on policy institutes, think tanks, and Korean peninsula affairs. Conducts long-term intelligence gathering via encoded PowerShell tasks and spearphishing. Often masquerades as Windows infrastructure.',
        ttps: ['Hidden PowerShell scheduled tasks', 'WindowsUpdate masquerading', 'Base64-encoded payloads'],
    },
    'Cobalt Group': {
        aka: ['GOLD KINGSWOOD'],
        nation: 'Unknown (CIS)', flag: '🌐',
        color: '#00e676',
        summary: 'Financially-motivated group targeting financial institutions globally. Masters of PowerShell→schtasks persistence chains. Named for their heavy use of Cobalt Strike framework. Active since 2016, responsible for ATM jackpotting attacks.',
        ttps: ['PowerShell→schtasks chains', 'Cobalt Strike framework', 'ATM malware', 'LOLBin execution'],
    },
    'Sandworm': {
        aka: ['Voodoo Bear', 'IRIDIUM', 'Electrum'],
        nation: 'Russia', flag: '🇷🇺',
        color: '#c470ff',
        summary: 'Russian GRU Unit 74455. Responsible for the most destructive cyberattacks in history: NotPetya ($10B damage), Ukrainian power grid attacks, and Olympic Destroyer. Specialises in destructive wiper malware and ICS/SCADA targeting.',
        ttps: ['Scripting engine to registry persistence', 'Destructive malware deployment', 'Supply chain attacks'],
    },
    'TA505': {
        aka: ['Hive0065'],
        nation: 'Russia/CIS', flag: '🇷🇺',
        color: '#ffd60a',
        summary: 'Prolific financially-motivated group responsible for distributing more malware than almost any other actor. Operates Clop ransomware and has distributed Dridex, Locky, and FlawedAmmyy. Known for encoded task payloads at scale.',
        ttps: ['Mass phishing campaigns', 'Encoded scheduled task payloads', 'Clop ransomware', 'Dridex banking trojan'],
    },
}

// ── Score ring canvas ────────────────────────────────────────────
function ScoreRing({ score, size = 80 }) {
    const ref = useRef(null)

    useEffect(() => {
        if (!ref.current || score == null) return
        const cv = ref.current
        const ctx = cv.getContext('2d')
        const DPR = 2
        cv.width = size * DPR
        cv.height = size * DPR
        ctx.scale(DPR, DPR)

        const cx = size / 2
        const cy = size / 2
        const R = size / 2 - 6
        const color = score >= 80 ? '#ff2055' : score >= 60 ? '#ff7700' : score >= 40 ? '#ffd60a' : '#00e676'

        let prog = 0
        const target = score / 100
        let rafId

        function draw() {
            ctx.clearRect(0, 0, size, size)

            // Track
            ctx.beginPath()
            ctx.arc(cx, cy, R, 0, Math.PI * 2)
            ctx.strokeStyle = 'rgba(255,255,255,.06)'
            ctx.lineWidth = 5
            ctx.stroke()

            // Glow arc
            const start = -Math.PI / 2
            const end = start + Math.PI * 2 * prog

            if (prog > 0) {
                ctx.save()
                ctx.shadowColor = color
                ctx.shadowBlur = 12
                ctx.beginPath()
                ctx.arc(cx, cy, R, start, end)
                ctx.strokeStyle = color
                ctx.lineWidth = 5
                ctx.lineCap = 'round'
                ctx.stroke()
                ctx.restore()
            }

            // Score text
            const alpha = Math.min(prog / target, 1)
            ctx.globalAlpha = alpha
            ctx.textAlign = 'center'
            ctx.textBaseline = 'middle'
            ctx.fillStyle = color
            ctx.font = `700 ${Math.round(size * 0.22)}px "JetBrains Mono",monospace`
            ctx.fillText(Math.round(prog * 100), cx, cy - 3)
            ctx.font = `400 ${Math.round(size * 0.1)}px "JetBrains Mono",monospace`
            ctx.fillStyle = 'rgba(106,117,144,.8)'
            ctx.fillText('/100', cx, cy + size * 0.14)
            ctx.globalAlpha = 1
        }

        function animate() {
            prog = Math.min(prog + 0.018, target)
            draw()
            if (prog < target) rafId = requestAnimationFrame(animate)
        }
        animate()
        return () => cancelAnimationFrame(rafId)
    }, [score, size])

    return <canvas ref={ref} style={{ width: size, height: size, display: 'block' }} />
}

// ── APT group badge ──────────────────────────────────────────────
function APTBadge({ group, onClick, active }) {
    const intel = APT_INTEL[group] || { color: '#5a6b8a', flag: '🌐', nation: 'Unknown' }
    return (
        <button
            onClick={onClick}
            style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '4px 10px', borderRadius: 4, cursor: 'pointer',
                border: `1px solid ${active ? intel.color : intel.color + '40'}`,
                background: active ? intel.color + '18' : 'transparent',
                transition: 'all .2s',
            }}
        >
            <span style={{ fontSize: 12 }}>{intel.flag}</span>
            <span style={{
                fontFamily: "'JetBrains Mono',monospace", fontSize: 9, fontWeight: 700,
                color: intel.color, letterSpacing: '.06em',
            }}>
                {group}
            </span>
        </button>
    )
}

// ── APT intel panel ──────────────────────────────────────────────
function APTIntelPanel({ group, sig }) {
    const intel = APT_INTEL[group]
    const color = intel?.color || '#5a6b8a'

    return (
        <div style={{
            borderRadius: 8, overflow: 'hidden',
            border: `1px solid ${color}30`,
            background: `linear-gradient(135deg, ${color}08 0%, rgba(15,19,32,.95) 60%)`,
            animation: 'apt-in .3s ease',
        }}>
            <style>{`@keyframes apt-in{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}`}</style>

            {/* Header */}
            <div style={{
                padding: '12px 14px', borderBottom: `1px solid ${color}20`,
                display: 'flex', alignItems: 'center', gap: 10,
            }}>
                <span style={{ fontSize: 22 }}>{intel?.flag || '🌐'}</span>
                <div>
                    <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 12, fontWeight: 700, color }}>
                        {group}
                    </div>
                    <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: 'rgba(106,117,144,.8)', marginTop: 1 }}>
                        {intel?.aka?.join(' · ') || 'Unknown aliases'} · {intel?.nation || 'Unknown'}
                    </div>
                </div>
            </div>

            {/* Summary */}
            {intel?.summary && (
                <div style={{ padding: '10px 14px', borderBottom: `1px solid ${color}15` }}>
                    <div style={{
                        fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700,
                        letterSpacing: '.14em', textTransform: 'uppercase', color: 'rgba(53,64,96,1)',
                        marginBottom: 5,
                    }}>
                        Background
                    </div>
                    <div style={{ fontSize: 11, color: 'rgba(140,155,175,1)', lineHeight: 1.6 }}>
                        {intel.summary}
                    </div>
                </div>
            )}

            {/* Why matched */}
            {sig && (
                <div style={{ padding: '10px 14px', borderBottom: `1px solid ${color}15` }}>
                    <div style={{
                        fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700,
                        letterSpacing: '.14em', textTransform: 'uppercase', color: 'rgba(53,64,96,1)',
                        marginBottom: 5,
                    }}>
                        Why This Matches
                    </div>
                    <div style={{
                        fontSize: 11, color, lineHeight: 1.6,
                        padding: '8px 10px', background: color + '10', borderRadius: 5,
                        border: `1px solid ${color}25`,
                    }}>
                        {sig.description}
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 8 }}>
                        {sig.mitre?.map(m => (
                            <span key={m} style={{
                                fontFamily: "'JetBrains Mono',monospace", fontSize: 8, padding: '2px 6px',
                                borderRadius: 3, background: 'rgba(196,112,255,.1)', color: '#c470ff',
                                border: '1px solid rgba(196,112,255,.25)',
                            }}>{m}</span>
                        ))}
                    </div>
                </div>
            )}

            {/* TTPs */}
            {intel?.ttps && (
                <div style={{ padding: '10px 14px' }}>
                    <div style={{
                        fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700,
                        letterSpacing: '.14em', textTransform: 'uppercase', color: 'rgba(53,64,96,1)',
                        marginBottom: 6,
                    }}>
                        Known TTPs
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                        {intel.ttps.map((t, i) => (
                            <div key={i} style={{
                                display: 'flex', alignItems: 'center', gap: 7, fontSize: 10,
                                color: 'rgba(140,155,175,1)',
                                animation: `nip-in .2s ease ${i * .05}s both`,
                            }}>
                                <div style={{ width: 4, height: 4, borderRadius: '50%', background: color, flexShrink: 0 }} />
                                {t}
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    )
}

// ── Score breakdown bar ──────────────────────────────────────────
function BreakdownBar({ delta, description }) {
    const color = delta >= 30 ? '#ff2055' : delta >= 20 ? '#ff7700' : delta >= 10 ? '#ffd60a' : '#00e676'
    const ref = useRef(null)

    useEffect(() => {
        if (!ref.current) return
        ref.current.style.width = '0'
        setTimeout(() => {
            if (ref.current) {
                ref.current.style.transition = 'width .8s cubic-bezier(.16,1,.3,1)'
                ref.current.style.width = `${Math.min(delta, 40) / 40 * 100}%`
            }
        }, 50)
    }, [delta])

    return (
        <div style={{ marginBottom: 8 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                <span style={{
                    fontFamily: "'JetBrains Mono',monospace", fontSize: 9,
                    color: 'rgba(140,155,175,1)',
                }}>
                    {description}
                </span>
                <span style={{
                    fontFamily: "'JetBrains Mono',monospace", fontSize: 9, fontWeight: 700, color,
                }}>
                    +{delta}
                </span>
            </div>
            <div style={{ height: 2, background: 'rgba(255,255,255,.05)', borderRadius: 2, overflow: 'hidden' }}>
                <div ref={ref} style={{ height: '100%', background: color, borderRadius: 2, boxShadow: `0 0 6px ${color}60` }} />
            </div>
        </div>
    )
}

// ── Main component ───────────────────────────────────────────────
export function ThreatScorePanel({ entryType, entryId, hideRiskIndicators = false, hideBreakdown = false }) {
    const [activeGroup, setActiveGroup] = useState(null)
    const [isScoring, setIsScoring] = useState(false)
    const queryClient = useQueryClient()

    const { data, isLoading } = useQuery({
        queryKey: ['score', entryType, entryId],
        queryFn: () => fetchScore(entryType, entryId),
        enabled: !!entryType && !!entryId,
    })

    const handleRunScorer = async () => {
        setIsScoring(true)
        try {
            await triggerScores()
            await queryClient.invalidateQueries({ queryKey: ['score'] })
        } catch (e) {
            console.error('Failed to run scorer', e)
        } finally {
            setIsScoring(false)
        }
    }

    if (isLoading) return (
        <div style={{ padding: '32px 20px', display: 'flex', justifyContent: 'center' }}>
            <svg width="20" height="20" viewBox="0 0 20 20">
                <circle cx="10" cy="10" r="8" fill="none" stroke="rgba(0,229,255,.15)" strokeWidth="2" />
                <circle cx="10" cy="10" r="8" fill="none" stroke="var(--cyan)" strokeWidth="2"
                    strokeLinecap="round" strokeDasharray="12 38"
                    style={{ transformOrigin: '50% 50%', animation: 'rh-spin .75s linear infinite' }} />
                <style>{`@keyframes rh-spin{to{transform:rotate(360deg)}}`}</style>
            </svg>
        </div>
    )

    if (data?.score == null) return (
        <div style={{ padding: '32px 20px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16 }}>
            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: 'rgba(140,155,175,1)' }}>
                No score data available for this entry.
            </div>
            <button
                onClick={handleRunScorer}
                disabled={isScoring}
                style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '8px 16px', borderRadius: 6,
                    background: isScoring ? 'rgba(0,229,255,0.05)' : 'rgba(0,229,255,0.1)',
                    border: '1px solid rgba(0,229,255,0.3)',
                    color: 'var(--cyan)', fontFamily: "'JetBrains Mono',monospace", fontSize: 10, fontWeight: 700,
                    textTransform: 'uppercase', letterSpacing: '.1em', cursor: isScoring ? 'not-allowed' : 'pointer',
                    transition: 'all .2s'
                }}
            >
                {isScoring ? (
                    <>
                        <svg width="12" height="12" viewBox="0 0 20 20">
                            <circle cx="10" cy="10" r="8" fill="none" stroke="rgba(0,229,255,.2)" strokeWidth="2" />
                            <circle cx="10" cy="10" r="8" fill="none" stroke="var(--cyan)" strokeWidth="2"
                                strokeLinecap="round" strokeDasharray="12 38"
                                style={{ transformOrigin: '50% 50%', animation: 'rh-spin .75s linear infinite' }} />
                        </svg>
                        Scoring...
                    </>
                ) : (
                    <>
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <polygon points="5 3 19 12 5 21 5 3"></polygon>
                        </svg>
                        Run Threat Scorer
                    </>
                )}
            </button>
            <style>{`@keyframes rh-spin{to{transform:rotate(360deg)}}`}</style>
        </div>
    )

    const { score, breakdown = [], apt_matches = [], risk_indicators = [] } = data
    const allGroups = [...new Set(apt_matches.flatMap(m => m.apt_groups || []))]
    const activeMatch = activeGroup
        ? apt_matches.find(m => m.apt_groups?.includes(activeGroup))
        : null

    const scoreColor = score >= 80 ? '#ff2055' : score >= 60 ? '#ff7700' : score >= 40 ? '#ffd60a' : '#00e676'
    const scoreLabel = score >= 80 ? 'CRITICAL THREAT' : score >= 60 ? 'HIGH RISK' : score >= 40 ? 'SUSPICIOUS' : 'LOW RISK'

    return (
        <div style={{ maxWidth: 680, display: 'flex', flexDirection: 'column', gap: 16 }}>
            <style>{`@keyframes nip-in{to{opacity:1;transform:translateX(0)}}`}</style>

            {/* ── Score header ── */}
            <div style={{
                display: 'flex', alignItems: 'center', gap: 20,
                padding: '16px 18px', borderRadius: 10,
                background: `linear-gradient(135deg, ${scoreColor}10 0%, rgba(15,19,32,.9) 70%)`,
                border: `1px solid ${scoreColor}30`,
            }}>
                <ScoreRing score={score} size={80} />
                <div style={{ flex: 1 }}>
                    <div style={{
                        fontFamily: "'JetBrains Mono',monospace", fontSize: 10, fontWeight: 700,
                        letterSpacing: '.18em', color: scoreColor, marginBottom: 4,
                    }}>
                        {scoreLabel}
                    </div>
                    <div style={{ fontSize: 12, color: 'rgba(192,200,224,.8)', lineHeight: 1.5, marginBottom: 8 }}>
                        Composite threat score based on {breakdown.length} evaluated factors
                        {allGroups.length > 0 && ` including ${allGroups.length} APT attribution signal${allGroups.length > 1 ? 's' : ''}`}.
                    </div>
                    {allGroups.length > 0 && (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                            {allGroups.map(g => (
                                <APTBadge
                                    key={g}
                                    group={g}
                                    active={activeGroup === g}
                                    onClick={() => setActiveGroup(activeGroup === g ? null : g)}
                                />
                            ))}
                        </div>
                    )}
                </div>
            </div>

            {/* ── APT intel panel (expands on group click) ── */}
            {activeGroup && (
                <APTIntelPanel group={activeGroup} sig={activeMatch} />
            )}

            {/* ── Risk indicators ── */}
            {!hideRiskIndicators && risk_indicators.length > 0 && (
                <div>
                    <div style={{
                        fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700,
                        letterSpacing: '.18em', textTransform: 'uppercase',
                        color: 'rgba(53,64,96,1)', marginBottom: 8,
                        display: 'flex', alignItems: 'center', gap: 8,
                    }}>
                        Risk Indicators
                        <span style={{
                            fontFamily: "'JetBrains Mono',monospace", fontSize: 8, padding: '1px 6px',
                            borderRadius: 3, background: 'rgba(255,32,85,.1)', color: '#ff2055',
                            border: '1px solid rgba(255,32,85,.25)',
                        }}>{risk_indicators.length}</span>
                    </div>
                    {risk_indicators.map((ind, i) => {
                        const c = ind.severity === 'critical' ? '#ff2055' : ind.severity === 'high' ? '#ff7722' : '#ffd60a'
                        return (
                            <div key={i} style={{
                                padding: '10px 12px', borderRadius: 7, marginBottom: 6,
                                background: 'rgba(15,19,32,.9)', border: `1px solid rgba(255,255,255,.07)`,
                                borderLeft: `3px solid ${c}`,
                                opacity: 0, transform: 'translateX(-8px)',
                                animation: `nip-in .3s ease ${i * .07}s forwards`,
                            }}>
                                <div style={{
                                    fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700,
                                    textTransform: 'uppercase', letterSpacing: '.12em', color: c, marginBottom: 4,
                                    display: 'flex', alignItems: 'center', gap: 5,
                                }}>
                                    <div style={{
                                        width: 4, height: 4, borderRadius: '50%', background: c,
                                        boxShadow: `0 0 5px ${c}`,
                                        animation: ind.severity === 'critical' ? 'rh-pip-pulse 1.8s ease-in-out infinite' : 'none',
                                    }} />
                                    {ind.type?.replace(/_/g, ' ')}
                                    {ind.apt_groups && (
                                        <span style={{ marginLeft: 6, color: 'rgba(106,117,144,.7)', fontWeight: 400 }}>
                                            — {ind.apt_groups.slice(0, 3).join(', ')}
                                        </span>
                                    )}
                                </div>
                                <div style={{ fontSize: 11, color: 'rgba(140,155,175,1)', lineHeight: 1.5 }}>
                                    {ind.description}
                                </div>
                            </div>
                        )
                    })}
                </div>
            )}

            {/* ── Score breakdown ── */}
            {!hideBreakdown && breakdown.length > 0 && (
                <div>
                    <div style={{
                        fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700,
                        letterSpacing: '.18em', textTransform: 'uppercase',
                        color: 'rgba(53,64,96,1)', marginBottom: 10,
                    }}>
                        Score Breakdown
                    </div>
                    <div style={{
                        padding: '12px 14px', borderRadius: 8,
                        background: 'rgba(15,19,32,.9)', border: '1px solid rgba(255,255,255,.07)',
                    }}>
                        {breakdown
                            .sort((a, b) => b.delta - a.delta)
                            .map((b, i) => (
                                <BreakdownBar key={i} {...b} />
                            ))
                        }
                    </div>
                </div>
            )}
        </div>
    )
}