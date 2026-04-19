// src/components/features/ProcessTree.jsx
import { useState, useEffect, useRef } from 'react'

const NODE_CFG = {
    system: { border: '#3d5270', bg: 'rgba(61,82,112,0.15)', glow: 'none', color: '#3d5270', glyph: '>_' },
    normal: { border: '#448aff', bg: 'rgba(68,138,255,0.1)', glow: '0 0 18px rgba(68,138,255,0.25)', color: '#448aff', glyph: '>_' },
    suspicious: { border: '#ff7722', bg: 'rgba(255,119,34,0.1)', glow: '0 0 18px rgba(255,119,34,0.25)', color: '#ff7722', glyph: '{}' },
    malicious: { border: '#ff2055', bg: 'rgba(255,32,85,0.1)', glow: '0 0 22px rgba(255,32,85,0.35)', color: '#ff2055', glyph: '⬡' },
    unknown: { border: '#3d5270', bg: 'rgba(61,82,112,0.1)', glow: 'none', color: '#3d5270', glyph: '?' },
}

function NodeIcon({ type, size = 20 }) {
    const color = NODE_CFG[type]?.color || '#448aff'
    if (type === 'normal' || type === 'system') return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" />
        </svg>
    )
    if (type === 'suspicious') return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
            <polyline points="14 2 14 8 20 8" />
            <line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" />
        </svg>
    )
    if (type === 'malicious') return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z" />
            <polyline points="3.27 6.96 12 12.01 20.73 6.96" />
            <line x1="12" y1="22.08" x2="12" y2="12" />
        </svg>
    )
    return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10" />
            <path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
    )
}

// Animated particle flowing along the connector
function FlowParticle({ color, delay = 0 }) {
    return (
        <div style={{
            position: 'absolute',
            top: '50%',
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: color,
            boxShadow: `0 0 6px ${color}`,
            transform: 'translateY(-50%)',
            animation: `rh-flow-particle 1.6s linear ${delay}s infinite`,
            opacity: 0,
        }} />
    )
}

function Connector({ toNode, pid }) {
    const isMal = toNode?.type === 'malicious'
    const isSusp = toNode?.type === 'suspicious'
    const color = isMal ? 'rgba(255,32,85,0.55)'
        : isSusp ? 'rgba(255,119,34,0.5)'
            : 'rgba(40,60,90,0.85)'
    const partColor = isMal ? '#ff2055' : isSusp ? '#ff7722' : '#00e5ff'

    return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', alignSelf: 'flex-start', marginTop: 24 }}>
            {pid && (
                <div style={{
                    fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace",
                    fontSize: 8, color: 'rgba(53,64,96,1)', marginBottom: 4,
                    background: 'rgba(15,19,32,0.9)', padding: '1px 5px', borderRadius: 3,
                    border: '1px solid rgba(255,255,255,0.07)',
                }}>
                    {pid}
                </div>
            )}
            <div style={{ position: 'relative', width: 56, height: 10, display: 'flex', alignItems: 'center' }}>
                <div style={{ flex: 1, height: 2, background: color, borderRadius: 1 }} />
                <div style={{
                    width: 0, height: 0,
                    borderTop: '5px solid transparent',
                    borderBottom: '5px solid transparent',
                    borderLeft: `7px solid ${color}`,
                    marginLeft: -1, flexShrink: 0,
                }} />
                <FlowParticle color={partColor} delay={0} />
                <FlowParticle color={partColor} delay={0.55} />
            </div>
        </div>
    )
}

function ProcessNode({ node, index, isWriter, onClick, selected, visible }) {
    const isSelected = selected === index
    const nc = NODE_CFG[node.type] || NODE_CFG.normal
    const label = node.name || 'unknown'
    const user = node.user?.split('\\').pop() || ''

    return (
        <div
            onClick={() => onClick(index)}
            style={{
                display: 'flex', flexDirection: 'column', alignItems: 'center',
                gap: 8, cursor: 'pointer', minWidth: 80, userSelect: 'none',
                opacity: visible ? 1 : 0,
                transform: visible ? 'translateY(0) scale(1)' : 'translateY(10px) scale(0.85)',
                transition: `opacity 0.4s ease ${index * 0.08}s, transform 0.4s cubic-bezier(0.16,1,0.3,1) ${index * 0.08}s`,
            }}
        >
            <div
                style={{
                    width: 68, height: 68, borderRadius: '50%',
                    border: `${isWriter ? 3 : 2}px solid ${nc.border}`,
                    background: nc.bg,
                    boxShadow: isSelected
                        ? `0 0 0 3px rgba(0,229,255,0.25), ${nc.glow}`
                        : nc.glow,
                    outline: isSelected ? '2px solid rgba(0,229,255,0.5)' : 'none',
                    outlineOffset: 3,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    position: 'relative',
                    transition: 'transform 0.18s, box-shadow 0.18s',
                }}
                onMouseEnter={e => e.currentTarget.style.transform = 'scale(1.09)'}
                onMouseLeave={e => e.currentTarget.style.transform = 'scale(1)'}
            >
                <NodeIcon type={node.type} size={22} />

                {/* Pulsing ring for writers/malicious */}
                {(isWriter || node.type === 'malicious') && (
                    <div style={{
                        position: 'absolute', inset: -5, borderRadius: '50%',
                        border: `1.5px dashed ${nc.border}`,
                        opacity: 0.5,
                        animation: 'rh-node-spin 4s linear infinite',
                    }} />
                )}

                {/* Outer breathe ring for malicious */}
                {node.type === 'malicious' && (
                    <div style={{
                        position: 'absolute', inset: -9, borderRadius: '50%',
                        border: '1px solid rgba(255,32,85,0.25)',
                        animation: 'rh-breathe 2s ease-in-out infinite',
                    }} />
                )}
            </div>

            <div style={{ textAlign: 'center', maxWidth: 90 }}>
                <div style={{
                    fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace",
                    fontSize: 10.5, fontWeight: 600,
                    color: node.type === 'unknown' ? 'rgba(53,64,96,1)' : 'rgba(238,242,255,0.95)',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 90,
                }}>
                    {label}
                </div>
                {user && (
                    <div style={{ fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace", fontSize: 9, color: 'rgba(53,64,96,1)', marginTop: 1 }}>
                        {user}
                    </div>
                )}
                {index > 0 && (
                    <div style={{ fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace", fontSize: 8, color: 'rgba(53,64,96,0.8)', marginTop: 2, letterSpacing: '0.08em' }}>
                        HOP {index}
                    </div>
                )}
            </div>
        </div>
    )
}

export function ProcessTree({ chain, loading, error }) {
    const [selected, setSelected] = useState(null)
    const [visible, setVisible] = useState(false)

    useEffect(() => {
        if (chain?.length) {
            setVisible(false)
            const t = setTimeout(() => setVisible(true), 60)
            return () => clearTimeout(t)
        }
    }, [chain])

    if (loading) return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '32px 0', color: 'rgba(90,107,138,1)' }}>
            <svg width="18" height="18" viewBox="0 0 24 24" style={{ animation: 'rh-spin 0.75s linear infinite' }}>
                <circle cx="12" cy="12" r="9" fill="none" stroke="rgba(0,229,255,0.15)" strokeWidth="2" />
                <circle cx="12" cy="12" r="9" fill="none" stroke="#00e5ff" strokeWidth="2" strokeLinecap="round"
                    strokeDasharray="14 42" style={{ filter: 'drop-shadow(0 0 4px rgba(0,229,255,0.6))' }} />
            </svg>
            <span style={{ fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace", fontSize: 11 }}>Building chain...</span>
        </div>
    )

    if (error) return (
        <div style={{ fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace", fontSize: 11, padding: '16px 0', color: '#ff2055' }}>
            ✗ Failed to load chain
        </div>
    )

    if (!chain?.length) return (
        <div style={{ fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace", fontSize: 11, padding: '16px 0', color: 'rgba(53,64,96,1)' }}>
            No chain data available
        </div>
    )

    const selectedNode = selected !== null ? chain[selected] : null

    return (
        <>
            <style>{`
                @keyframes rh-spin          { to { transform: rotate(360deg); } }
                @keyframes rh-node-spin     { to { transform: rotate(360deg); } }
                @keyframes rh-breathe       { 0%,100% { opacity:0.2; transform:scale(0.95); } 50% { opacity:0.5; transform:scale(1.05); } }
                @keyframes rh-flow-particle {
                    0%   { left:-6px; opacity:0; }
                    15%  { opacity:1; }
                    85%  { opacity:1; }
                    100% { left:calc(100% + 2px); opacity:0; }
                }
                @keyframes rh-detail-in     { from { opacity:0; transform:translateY(6px); } to { opacity:1; transform:translateY(0); } }
                @keyframes rh-chain-scan {
                    0%   { left:-40%; }
                    100% { left:140%; }
                }
            `}</style>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                {/* Chain bar */}
                <div style={{
                    fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace",
                    fontSize: 10, color: 'rgba(53,64,96,1)',
                    padding: '7px 12px',
                    background: 'rgba(0,229,255,0.04)',
                    border: '1px solid rgba(0,229,255,0.1)',
                    borderRadius: 6,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    position: 'relative',
                }}>
                    <div style={{
                        position: 'absolute', top: 0, left: 0, bottom: 0, width: '35%',
                        background: 'linear-gradient(90deg, transparent, rgba(0,229,255,0.06), transparent)',
                        animation: 'rh-chain-scan 3s ease-in-out infinite',
                    }} />
                    <span style={{ color: 'rgba(53,64,96,1)', marginRight: 8 }}>CHAIN:</span>
                    <span style={{ color: 'rgba(140,155,175,1)' }}>{chain.map(n => n.name).join(' → ')}</span>
                </div>

                {/* Nodes */}
                <div style={{ overflowX: 'auto', paddingBottom: 16 }}>
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 0, minWidth: 'max-content', padding: '8px 4px' }}>
                        {chain.map((node, i) => (
                            <div key={i} style={{ display: 'flex', alignItems: 'flex-start' }}>
                                <ProcessNode
                                    node={node}
                                    index={i}
                                    isWriter={!!node.action}
                                    onClick={setSelected}
                                    selected={selected}
                                    visible={visible}
                                />
                                {i < chain.length - 1 && (
                                    <Connector toNode={chain[i + 1]} pid={chain[i + 1]?.pid} />
                                )}
                            </div>
                        ))}
                    </div>
                </div>

                {/* Selected node detail */}
                {selectedNode && (
                    <div style={{
                        padding: 16, borderRadius: 8,
                        border: '1px solid rgba(255,255,255,0.07)',
                        background: 'rgba(15,19,32,0.9)',
                        display: 'flex', flexDirection: 'column', gap: 10,
                        animation: 'rh-detail-in 0.2s ease forwards',
                        borderLeft: `3px solid ${NODE_CFG[selectedNode.type]?.border || '#448aff'}`,
                    }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                <div style={{
                                    width: 36, height: 36, borderRadius: '50%',
                                    border: `2px solid ${NODE_CFG[selectedNode.type]?.border || '#448aff'}`,
                                    background: NODE_CFG[selectedNode.type]?.bg || 'transparent',
                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    boxShadow: NODE_CFG[selectedNode.type]?.glow,
                                }}>
                                    <NodeIcon type={selectedNode.type} size={15} />
                                </div>
                                <div>
                                    <div style={{ fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace", fontSize: 13, fontWeight: 600, color: 'rgba(238,242,255,0.95)' }}>
                                        {selectedNode.name}
                                    </div>
                                    {selectedNode.pid && (
                                        <div style={{ fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace", fontSize: 9, color: 'rgba(53,64,96,1)', marginTop: 2 }}>
                                            PID {selectedNode.pid}{selectedNode.source ? ` · ${selectedNode.source}` : ''}
                                        </div>
                                    )}
                                </div>
                            </div>
                            <button
                                onClick={() => setSelected(null)}
                                style={{
                                    fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace",
                                    fontSize: 10, padding: '3px 8px', borderRadius: 4,
                                    color: 'rgba(53,64,96,1)', border: '1px solid rgba(255,255,255,0.07)',
                                    cursor: 'pointer', background: 'transparent', transition: 'color 0.2s, border-color 0.2s',
                                }}
                                onMouseEnter={e => { e.currentTarget.style.color = '#ff2055'; e.currentTarget.style.borderColor = 'rgba(255,32,85,0.3)' }}
                                onMouseLeave={e => { e.currentTarget.style.color = 'rgba(53,64,96,1)'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.07)' }}
                            >
                                ✕
                            </button>
                        </div>

                        {selectedNode.cmdline && (
                            <div style={{
                                fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace", fontSize: 10,
                                padding: '10px 12px', borderRadius: 6,
                                background: 'rgba(7,9,15,0.8)',
                                color: 'rgba(140,155,175,1)',
                                border: '1px solid rgba(255,255,255,0.05)',
                                wordBreak: 'break-all', lineHeight: 1.6,
                            }}>
                                {selectedNode.cmdline}
                            </div>
                        )}

                        {selectedNode.action && (
                            <div style={{
                                fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace", fontSize: 10,
                                padding: '7px 12px', borderRadius: 5,
                                background: 'rgba(0,229,255,0.05)',
                                border: '1px solid rgba(0,229,255,0.15)',
                                color: '#00e5ff',
                            }}>
                                → {selectedNode.action.label}
                            </div>
                        )}

                        {selectedNode.techniques?.length > 0 && (
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                                {selectedNode.techniques.map(t => (
                                    <span key={t.id} title={t.name} style={{
                                        fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace", fontSize: 9,
                                        padding: '2px 7px', borderRadius: 3,
                                        background: 'rgba(196,112,255,0.1)', color: '#c470ff',
                                        border: '1px solid rgba(196,112,255,0.25)',
                                    }}>
                                        {t.id}
                                    </span>
                                ))}
                            </div>
                        )}

                        {selectedNode.unknown_reason && (
                            <div style={{ fontFamily: "'JetBrains Mono','IBM Plex Mono',monospace", fontSize: 10, color: '#ffd60a' }}>
                                ⚠ {selectedNode.unknown_reason}
                            </div>
                        )}
                    </div>
                )}
            </div>
        </>
    )
}