// src/components/features/EntryCard.jsx
import { useNavigate } from 'react-router-dom'
import { SeverityBadge } from '../ui/SeverityBadge'
import { MitreTag } from '../ui/MitreTag'

const SEV_ACCENT = {
    critical: '#ff2055',
    high: '#ff7722',
    medium: '#ffd60a',
    low: '#00e676',
}

export function EntryCard({ entry }) {
    const navigate = useNavigate()
    const type = entry.entry_type
    const name = entry.name || entry.task_name || entry.service_name || '?'
    const value = entry.value_data || entry.command || entry.binary_path || ''
    const techniques = entry.techniques || []
    const accent = SEV_ACCENT[entry.severity] || '#5a6b8a'

    return (
        <>
            <style>{`
                .rh-entry-card {
                    background: rgba(15,19,32,0.9);
                    border: 1px solid rgba(255,255,255,0.07);
                    border-radius: 8px;
                    padding: 12px 14px 12px 16px;
                    cursor: pointer;
                    position: relative;
                    overflow: hidden;
                    transition: border-color 0.2s, transform 0.2s, box-shadow 0.2s;
                }
                .rh-entry-card:hover {
                    border-color: rgba(0,229,255,0.22);
                    transform: translateY(-2px);
                    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                }
                .rh-entry-card:active { transform: scale(0.985); }
                .rh-entry-accent-bar {
                    position: absolute;
                    left: 0; top: 0; bottom: 0;
                    width: 2px;
                    border-radius: 8px 0 0 8px;
                    transition: opacity 0.3s;
                    opacity: 0.6;
                }
                .rh-entry-card:hover .rh-entry-accent-bar { opacity: 1; }
                .rh-entry-shimmer {
                    position: absolute;
                    inset: 0;
                    background: linear-gradient(135deg, rgba(0,229,255,0.04), transparent 55%);
                    opacity: 0;
                    transition: opacity 0.3s;
                }
                .rh-entry-card:hover .rh-entry-shimmer { opacity: 1; }
                .rh-entry-top {
                    display: flex;
                    align-items: center;
                    gap: 7px;
                    margin-bottom: 6px;
                }
                .rh-entry-type {
                    font-family: 'JetBrains Mono', 'IBM Plex Mono', monospace;
                    font-size: 8px;
                    color: rgba(53,64,96,1);
                    text-transform: uppercase;
                    letter-spacing: 0.1em;
                }
                .rh-entry-name {
                    font-family: 'Space Grotesk', sans-serif;
                    font-size: 12px;
                    font-weight: 600;
                    color: rgba(238,242,255,0.95);
                    flex: 1;
                    overflow: hidden;
                    text-overflow: ellipsis;
                    white-space: nowrap;
                }
                .rh-entry-val {
                    font-family: 'JetBrains Mono', 'IBM Plex Mono', monospace;
                    font-size: 9px;
                    color: rgba(53,64,96,1);
                    overflow: hidden;
                    text-overflow: ellipsis;
                    white-space: nowrap;
                    margin-bottom: 7px;
                }
                .rh-entry-tags { display: flex; flex-wrap: wrap; gap: 4px; }
                .rh-entry-arrow {
                    position: absolute;
                    right: 12px;
                    top: 50%;
                    transform: translateY(-50%) translateX(4px);
                    opacity: 0;
                    transition: opacity 0.2s, transform 0.2s;
                    color: rgba(0,229,255,0.5);
                }
                .rh-entry-card:hover .rh-entry-arrow {
                    opacity: 1;
                    transform: translateY(-50%) translateX(0);
                }
            `}</style>
            <div
                className="rh-entry-card"
                onClick={() => navigate(`/entries/${type}/${entry.id}`)}
            >
                <div className="rh-entry-accent-bar" style={{ background: accent }} />
                <div className="rh-entry-shimmer" />

                <div className="rh-entry-top">
                    <SeverityBadge severity={entry.severity} size="xs" />
                    <span className="rh-entry-type">{type}</span>
                    <span className="rh-entry-name">{name}</span>
                </div>

                <div className="rh-entry-val">{value.slice(0, 80)}</div>

                {techniques.length > 0 && (
                    <div className="rh-entry-tags">
                        {techniques.slice(0, 4).map(t => (
                            <MitreTag key={t.id} id={t.id} name={t.name} />
                        ))}
                    </div>
                )}

                <svg className="rh-entry-arrow" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                    <path d="M5 12h14M12 5l7 7-7 7" />
                </svg>
            </div>
        </>
    )
}