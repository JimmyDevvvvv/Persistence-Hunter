// src/components/features/ProcessTree.jsx
// Circular node EDR-style horizontal process tree – matches reference screenshots
import { useState } from 'react'

// SVG icons inside nodes matching the reference screenshots
function NodeIcon({ type, size = 20 }) {
    const color = {
        system:     '#3d5270',
        normal:     '#3b82f6',
        suspicious: '#f97316',
        malicious:  '#ff3560',
        unknown:    '#3d5270',
    }[type] || '#3b82f6'

    if (type === 'normal' || type === 'system') {
        // Terminal prompt >_
        return (
            <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="4 17 10 11 4 5" />
                <line x1="12" y1="19" x2="20" y2="19" />
            </svg>
        )
    }
    if (type === 'suspicious') {
        // File/document icon
        return (
            <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
                <polyline points="14 2 14 8 20 8" />
                <line x1="16" y1="13" x2="8" y2="13" />
                <line x1="16" y1="17" x2="8" y2="17" />
            </svg>
        )
    }
    if (type === 'malicious') {
        // Cube/package icon
        return (
            <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z" />
                <polyline points="3.27 6.96 12 12.01 20.73 6.96" />
                <line x1="12" y1="22.08" x2="12" y2="12" />
            </svg>
        )
    }
    // Unknown
    return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10" />
            <path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
    )
}

const NODE_COLORS = {
    system:     { border: '#3d5270', bg: 'rgba(61,82,112,0.15)',  glow: 'none' },
    normal:     { border: '#3b82f6', bg: 'rgba(59,130,246,0.1)',  glow: '0 0 18px rgba(59,130,246,0.2)' },
    suspicious: { border: '#f97316', bg: 'rgba(249,115,22,0.1)', glow: '0 0 18px rgba(249,115,22,0.25)' },
    malicious:  { border: '#ff3560', bg: 'rgba(255,53,96,0.1)',  glow: '0 0 22px rgba(255,53,96,0.3)' },
    unknown:    { border: '#3d5270', bg: 'rgba(61,82,112,0.1)',  glow: 'none' },
}

function ProcessNode({ node, index, isWriter, onClick, selected }) {
    const isSelected = selected === index
    const nc = NODE_COLORS[node.type] || NODE_COLORS.normal
    const label = node.name || 'unknown'
    const user  = node.user?.split('\\').pop() || ''

    return (
        <div
            onClick={() => onClick(index)}
            style={{
                display: 'flex', flexDirection: 'column', alignItems: 'center',
                gap: 8, cursor: 'pointer', minWidth: 80, userSelect: 'none',
            }}
        >
            {/* Circle node */}
            <div
                style={{
                    width: 68, height: 68,
                    borderRadius: '50%',
                    border: `${isWriter ? 3 : 2}px solid ${nc.border}`,
                    background: nc.bg,
                    boxShadow: isSelected
                        ? `0 0 0 3px rgba(0,212,255,0.25), ${nc.glow}`
                        : nc.glow,
                    outline: isSelected ? '2px solid rgba(0,212,255,0.5)' : 'none',
                    outlineOffset: 3,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    position: 'relative',
                    transition: 'transform 0.15s, box-shadow 0.15s',
                }}
                onMouseEnter={e => e.currentTarget.style.transform = 'scale(1.07)'}
                onMouseLeave={e => e.currentTarget.style.transform = 'scale(1)'}
            >
                <NodeIcon type={node.type} size={22} />

                {/* Writer pulse ring */}
                {isWriter && (
                    <div style={{
                        position: 'absolute', inset: -3, borderRadius: '50%',
                        border: '2px solid rgba(255,53,96,0.4)',
                        animation: 'pulse 2s ease-in-out infinite',
                    }} />
                )}
            </div>

            {/* Label below node */}
            <div style={{ textAlign: 'center', maxWidth: 88 }}>
                <div style={{
                    fontFamily: 'IBM Plex Mono', fontSize: 10.5, fontWeight: 500,
                    color: node.type === 'unknown' ? 'var(--text-muted)' : 'var(--text-primary)',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    maxWidth: 88,
                }}>
                    {label}
                </div>
                {user && (
                    <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 9, color: 'var(--text-muted)', marginTop: 1 }}>
                        {user}
                    </div>
                )}
                {index > 0 && (
                    <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 9, color: 'var(--text-muted)', marginTop: 1 }}>
                        HOP {index}
                    </div>
                )}
            </div>
        </div>
    )
}

function Connector({ fromNode, toNode, pid }) {
    const toType = toNode?.type
    const color = toType === 'malicious'  ? 'rgba(255,53,96,0.5)'
        : toType === 'suspicious' ? 'rgba(249,115,22,0.45)'
            : 'rgba(40,60,90,0.8)'

    return (
        <div style={{
            display: 'flex', flexDirection: 'column', alignItems: 'center',
            alignSelf: 'flex-start', marginTop: 24, // align with node center
        }}>
            {/* PID label above the line */}
            {pid && (
                <div style={{
                    fontFamily: 'IBM Plex Mono', fontSize: 9,
                    color: 'var(--text-muted)', marginBottom: 4,
                    background: 'var(--bg-raised)', padding: '1px 5px', borderRadius: 3,
                    border: '1px solid var(--bg-border)',
                }}>
                    {pid}
                </div>
            )}
            {/* Line + arrow */}
            <div style={{ display: 'flex', alignItems: 'center', width: 56 }}>
                <div style={{ flex: 1, height: 2, background: color, borderRadius: 1 }} />
                {/* Arrow head */}
                <div style={{
                    width: 0, height: 0,
                    borderTop: '5px solid transparent',
                    borderBottom: '5px solid transparent',
                    borderLeft: `7px solid ${color}`,
                    marginLeft: -1,
                }} />
            </div>
        </div>
    )
}

export function ProcessTree({ chain, loading, error }) {
    const [selected, setSelected] = useState(null)

    if (loading) return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '32px 0', color: 'var(--text-muted)' }}>
            <div className="w-4 h-4 border-2 rounded-full animate-spin"
                style={{ borderColor: 'var(--bg-border)', borderTopColor: 'var(--cyan)' }} />
            <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 12 }}>Building chain...</span>
        </div>
    )

    if (error) return (
        <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 12, padding: '16px 0', color: 'var(--red)' }}>
            ✗ Failed to load chain
        </div>
    )

    if (!chain?.length) return (
        <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 12, padding: '16px 0', color: 'var(--text-muted)' }}>
            No chain data available
        </div>
    )

    const selectedNode = selected !== null ? chain[selected] : null

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

            {/* CHAIN summary text */}
            <div style={{
                fontFamily: 'IBM Plex Mono', fontSize: 11, color: 'var(--text-muted)',
                padding: '6px 10px', background: 'var(--bg-raised)',
                border: '1px solid var(--bg-border)', borderRadius: 6,
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>
                <span style={{ color: 'var(--text-muted)', marginRight: 6 }}>CHAIN:</span>
                <span style={{ color: '#8695a8' }}>{chain.map(n => n.name).join(' → ')}</span>
            </div>

            {/* Horizontal node tree */}
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
                            />
                            {i < chain.length - 1 && (
                                <Connector
                                    fromNode={node}
                                    toNode={chain[i + 1]}
                                    pid={chain[i + 1]?.pid}
                                />
                            )}
                        </div>
                    ))}
                </div>
            </div>

            {/* Selected node detail */}
            {selectedNode && (
                <div style={{
                    padding: 16, borderRadius: 8, border: '1px solid var(--bg-border)',
                    background: 'var(--bg-raised)', display: 'flex', flexDirection: 'column', gap: 10,
                    animation: 'fadeIn 0.15s ease-out',
                }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <div style={{
                                width: 36, height: 36, borderRadius: '50%',
                                border: `2px solid ${NODE_COLORS[selectedNode.type]?.border || '#3b82f6'}`,
                                background: NODE_COLORS[selectedNode.type]?.bg || 'transparent',
                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                            }}>
                                <NodeIcon type={selectedNode.type} size={15} />
                            </div>
                            <div>
                                <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 13, fontWeight: 500, color: 'var(--text-primary)' }}>
                                    {selectedNode.name}
                                </div>
                                {selectedNode.pid && (
                                    <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 10, color: 'var(--text-muted)' }}>
                                        PID {selectedNode.pid} · {selectedNode.source}
                                    </div>
                                )}
                            </div>
                        </div>
                        <button
                            onClick={() => setSelected(null)}
                            style={{
                                fontFamily: 'IBM Plex Mono', fontSize: 10, padding: '3px 8px', borderRadius: 4,
                                color: 'var(--text-muted)', border: '1px solid var(--bg-border)', cursor: 'pointer',
                                background: 'transparent',
                            }}
                        >
                            ✕
                        </button>
                    </div>

                    {selectedNode.cmdline && (
                        <div style={{
                            fontFamily: 'IBM Plex Mono', fontSize: 10.5,
                            padding: '10px 12px', borderRadius: 6,
                            background: 'var(--bg-base)',
                            color: 'var(--text-secondary)',
                            border: '1px solid var(--bg-border)',
                            wordBreak: 'break-all', lineHeight: 1.6,
                        }}>
                            {selectedNode.cmdline}
                        </div>
                    )}

                    {selectedNode.action && (
                        <div style={{
                            fontFamily: 'IBM Plex Mono', fontSize: 10.5,
                            padding: '8px 12px', borderRadius: 6,
                            background: 'rgba(0,212,255,0.05)',
                            border: '1px solid rgba(0,212,255,0.15)',
                            color: 'var(--cyan)',
                        }}>
                            → {selectedNode.action.label}
                        </div>
                    )}

                    {selectedNode.techniques?.length > 0 && (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                            {selectedNode.techniques.map(t => (
                                <span key={t.id} title={t.name} style={{
                                    fontFamily: 'IBM Plex Mono', fontSize: 10,
                                    padding: '2px 7px', borderRadius: 4,
                                    background: 'rgba(168,85,247,0.1)', color: '#a855f7',
                                    border: '1px solid rgba(168,85,247,0.25)',
                                }}>
                                    {t.id}
                                </span>
                            ))}
                        </div>
                    )}

                    {selectedNode.unknown_reason && (
                        <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 10.5, color: 'var(--yellow)' }}>
                            ⚠ {selectedNode.unknown_reason}
                        </div>
                    )}
                </div>
            )}
        </div>
    )
}