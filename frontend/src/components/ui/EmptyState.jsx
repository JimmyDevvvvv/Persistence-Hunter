// src/components/ui/EmptyState.jsx

const VARIANTS = {
    default: { ring1: 'rgba(0,229,255,0.15)', ring2: 'rgba(196,112,255,0.12)', core: '#00e5ff' },
    danger: { ring1: 'rgba(255,32,85,0.15)', ring2: 'rgba(255,119,34,0.12)', core: '#ff2055' },
    muted: { ring1: 'rgba(90,107,138,0.2)', ring2: 'rgba(90,107,138,0.12)', core: '#5a6b8a' },
}

export function EmptyState({ icon, message, sub, variant = 'default' }) {
    const v = VARIANTS[variant] || VARIANTS.default

    return (
        <>
            <style>{`
                @keyframes rh-orbit1 { to { transform: rotate(360deg); } }
                @keyframes rh-orbit2 { to { transform: rotate(-360deg); } }
                @keyframes rh-core-pulse {
                    0%, 100% { opacity: 0.4; transform: scale(0.8); }
                    50%       { opacity: 1;   transform: scale(1.15); }
                }
                .rh-empty {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    padding: 48px 24px;
                    gap: 16px;
                    text-align: center;
                    animation: rh-empty-in 0.4s ease forwards;
                }
                @keyframes rh-empty-in {
                    from { opacity: 0; transform: translateY(8px); }
                    to   { opacity: 1; transform: translateY(0); }
                }
                .rh-orbit-wrap {
                    position: relative;
                    width: 72px;
                    height: 72px;
                }
                .rh-ring {
                    position: absolute;
                    border-radius: 50%;
                    border: 1px dashed;
                }
                .rh-ring-1 {
                    inset: 0;
                    animation: rh-orbit1 7s linear infinite;
                }
                .rh-ring-2 {
                    inset: 10px;
                    animation: rh-orbit2 5s linear infinite;
                }
                .rh-ring-3 {
                    inset: 22px;
                    border-style: solid;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .rh-orbit-dot {
                    position: absolute;
                    width: 5px;
                    height: 5px;
                    border-radius: 50%;
                    top: -3px;
                    left: 50%;
                    transform: translateX(-50%);
                }
                .rh-orbit-dot-2 {
                    top: auto;
                    bottom: -3px;
                }
                .rh-core-dot {
                    width: 8px;
                    height: 8px;
                    border-radius: 50%;
                    animation: rh-core-pulse 2.2s ease-in-out infinite;
                }
                .rh-empty-label {
                    font-family: 'Space Grotesk', sans-serif;
                    font-size: 13px;
                    color: rgba(90,107,138,1);
                }
                .rh-empty-sub {
                    font-family: 'JetBrains Mono', 'IBM Plex Mono', monospace;
                    font-size: 9px;
                    color: rgba(53,64,96,1);
                }
            `}</style>
            <div className="rh-empty">
                {icon ? (
                    <div style={{ fontSize: 32, color: v.core, opacity: 0.3 }}>{icon}</div>
                ) : (
                    <div className="rh-orbit-wrap">
                        <div className="rh-ring rh-ring-1" style={{ borderColor: v.ring1 }}>
                            <div className="rh-orbit-dot" style={{ background: v.core, boxShadow: `0 0 6px ${v.core}` }} />
                        </div>
                        <div className="rh-ring rh-ring-2" style={{ borderColor: v.ring2 }}>
                            <div className="rh-orbit-dot rh-orbit-dot-2" style={{ background: v.ring2.replace('0.12', '1') }} />
                        </div>
                        <div className="rh-ring rh-ring-3" style={{ borderColor: v.core, background: `${v.core}08` }}>
                            <div className="rh-core-dot" style={{ background: v.core, boxShadow: `0 0 8px ${v.core}` }} />
                        </div>
                    </div>
                )}
                <div className="rh-empty-label">{message}</div>
                {sub && <div className="rh-empty-sub">{sub}</div>}
            </div>
        </>
    )
}