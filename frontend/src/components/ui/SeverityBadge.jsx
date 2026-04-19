// src/components/ui/SeverityBadge.jsx

const CFG = {
    critical: {
        label: 'CRITICAL',
        color: '#ff2055',
        bg: 'rgba(255,32,85,0.12)',
        border: 'rgba(255,32,85,0.4)',
        glow: '0 0 12px rgba(255,32,85,0.25)',
        pipAnim: 'rh-pip-critical 1.8s ease-in-out infinite',
    },
    high: {
        label: 'HIGH',
        color: '#ff7722',
        bg: 'rgba(255,119,34,0.1)',
        border: 'rgba(255,119,34,0.35)',
        glow: 'none',
        pipAnim: 'none',
    },
    medium: {
        label: 'MEDIUM',
        color: '#ffd60a',
        bg: 'rgba(255,214,10,0.08)',
        border: 'rgba(255,214,10,0.3)',
        glow: 'none',
        pipAnim: 'none',
    },
    low: {
        label: 'LOW',
        color: '#00e676',
        bg: 'rgba(0,230,118,0.07)',
        border: 'rgba(0,230,118,0.25)',
        glow: 'none',
        pipAnim: 'none',
    },
}

export function SeverityBadge({ severity, size = 'sm' }) {
    const c = CFG[severity] || CFG.low
    const pad = size === 'xs' ? '3px 8px' : '4px 10px'
    const fontSize = size === 'xs' ? 9 : 10

    return (
        <>
            <style>{`
                @keyframes rh-pip-critical {
                    0%, 100% { box-shadow: 0 0 4px #ff2055; }
                    50%       { box-shadow: 0 0 10px #ff2055, 0 0 20px rgba(255,32,85,0.4); }
                }
                .rh-sev-badge {
                    display: inline-flex;
                    align-items: center;
                    gap: 5px;
                    font-family: 'JetBrains Mono', 'IBM Plex Mono', monospace;
                    font-weight: 700;
                    letter-spacing: 0.1em;
                    text-transform: uppercase;
                    border-radius: 4px;
                    border-style: solid;
                    border-width: 1px;
                    cursor: default;
                    position: relative;
                    overflow: hidden;
                    transition: transform 0.2s, box-shadow 0.2s;
                    white-space: nowrap;
                }
                .rh-sev-badge::before {
                    content: '';
                    position: absolute;
                    inset: 0;
                    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.06), transparent);
                    transform: translateX(-100%);
                    transition: transform 0.5s;
                }
                .rh-sev-badge:hover::before { transform: translateX(100%); }
                .rh-sev-badge:hover { transform: translateY(-1px); }
                .rh-sev-pip {
                    width: 5px;
                    height: 5px;
                    border-radius: 50%;
                    flex-shrink: 0;
                }
            `}</style>
            <span
                className="rh-sev-badge"
                style={{
                    padding: pad,
                    fontSize,
                    color: c.color,
                    background: c.bg,
                    borderColor: c.border,
                    boxShadow: c.glow,
                }}
            >
                <span
                    className="rh-sev-pip"
                    style={{
                        background: c.color,
                        animation: c.pipAnim,
                    }}
                />
                {c.label}
            </span>
        </>
    )
}