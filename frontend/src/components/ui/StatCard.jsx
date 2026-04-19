// src/components/ui/StatCard.jsx
import { useEffect, useRef, useState } from 'react'

const ACCENT = {
    cyan: { color: '#00e5ff', glow: 'rgba(0,229,255,0.15)', bar: '#00e5ff' },
    red: { color: '#ff2055', glow: 'rgba(255,32,85,0.15)', bar: '#ff2055' },
    orange: { color: '#ff7722', glow: 'rgba(255,119,34,0.15)', bar: '#ff7722' },
    green: { color: '#00e676', glow: 'rgba(0,230,118,0.15)', bar: '#00e676' },
    purple: { color: '#c470ff', glow: 'rgba(196,112,255,0.15)', bar: '#c470ff' },
}

function useCountUp(target, duration = 1200) {
    const [val, setVal] = useState(0)
    const started = useRef(false)
    const ref = useRef(null)

    useEffect(() => {
        if (started.current || typeof target !== 'number') return
        started.current = true
        const start = performance.now()
        const step = (now) => {
            const p = Math.min((now - start) / duration, 1)
            const eased = 1 - Math.pow(1 - p, 4)
            setVal(Math.round(eased * target))
            if (p < 1) ref.current = requestAnimationFrame(step)
        }
        ref.current = requestAnimationFrame(step)
        return () => cancelAnimationFrame(ref.current)
    }, [target, duration])

    return typeof target === 'number' ? val : target
}

export function StatCard({ label, value, sub, accent = 'cyan', onClick, barWidth }) {
    const a = ACCENT[accent] || ACCENT.cyan
    const displayed = useCountUp(typeof value === 'number' ? value : NaN)
    const show = typeof value === 'number' ? displayed : (value ?? '—')

    return (
        <>
            <style>{`
                .rh-stat-card {
                    background: rgba(15,19,32,0.9);
                    border: 1px solid rgba(255,255,255,0.07);
                    border-radius: 8px;
                    padding: 16px;
                    position: relative;
                    overflow: hidden;
                    transition: transform 0.2s, border-color 0.25s, box-shadow 0.25s;
                    user-select: none;
                }
                .rh-stat-card[data-clickable="true"] { cursor: pointer; }
                .rh-stat-card[data-clickable="true"]:hover {
                    transform: translateY(-2px);
                }
                .rh-stat-card[data-clickable="true"]:active { transform: scale(0.97); }
                .rh-stat-card-shimmer {
                    position: absolute;
                    top: 0; left: 0; right: 0;
                    height: 1px;
                    opacity: 0.6;
                    transition: opacity 0.3s;
                }
                .rh-stat-card:hover .rh-stat-card-shimmer { opacity: 1; }
                .rh-stat-card-corner {
                    position: absolute;
                    top: 0; right: 0;
                    width: 0; height: 0;
                    border-style: solid;
                    border-width: 0 18px 18px 0;
                    opacity: 0.3;
                    transition: opacity 0.3s;
                }
                .rh-stat-card:hover .rh-stat-card-corner { opacity: 0.6; }
                .rh-stat-num {
                    font-family: 'JetBrains Mono', 'IBM Plex Mono', monospace;
                    font-size: 32px;
                    font-weight: 700;
                    line-height: 1;
                    margin-bottom: 6px;
                    transition: text-shadow 0.3s;
                }
                .rh-stat-card:hover .rh-stat-num {
                    text-shadow: 0 0 20px currentColor;
                }
                .rh-stat-label {
                    font-size: 11px;
                    color: rgba(90,107,138,1);
                    margin-bottom: 2px;
                    font-family: 'Space Grotesk', sans-serif;
                }
                .rh-stat-sub {
                    font-family: 'JetBrains Mono', 'IBM Plex Mono', monospace;
                    font-size: 9px;
                    color: rgba(53,64,96,1);
                }
                .rh-stat-bar {
                    position: absolute;
                    bottom: 0; left: 0;
                    height: 2px;
                    border-radius: 0 0 8px 8px;
                    transition: width 1.2s cubic-bezier(0.16,1,0.3,1), box-shadow 0.3s;
                }
                .rh-stat-card:hover .rh-stat-bar {
                    box-shadow: 0 0 8px currentColor;
                }
            `}</style>
            <div
                className="rh-stat-card"
                data-clickable={!!onClick}
                onClick={onClick}
                style={{ '--accent': a.color }}
            >
                {/* Top shimmer line */}
                <div
                    className="rh-stat-card-shimmer"
                    style={{ background: `linear-gradient(90deg, transparent, ${a.color}, transparent)` }}
                />
                {/* Corner accent */}
                <div
                    className="rh-stat-card-corner"
                    style={{ borderColor: `transparent ${a.color} transparent transparent` }}
                />
                <div className="rh-stat-num" style={{ color: a.color }}>
                    {show}
                </div>
                <div className="rh-stat-label">{label}</div>
                {sub && <div className="rh-stat-sub">{sub}</div>}
                {/* Bottom bar */}
                {barWidth != null && (
                    <div
                        className="rh-stat-bar"
                        style={{ width: barWidth, background: a.bar, color: a.bar }}
                    />
                )}
            </div>
        </>
    )
}