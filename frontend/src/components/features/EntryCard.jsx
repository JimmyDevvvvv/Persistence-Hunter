// src/components/features/EntryCard.jsx
import { useNavigate } from 'react-router-dom'
import { SeverityBadge } from '../ui/SeverityBadge'
import { MitreTag } from '../ui/MitreTag'

const SEV_ACCENT = {
    critical: '#ff2055',
    high:     '#ff7722',
    medium:   '#ffd60a',
    low:      '#00e676',
}

export function EntryCard({ entry }) {
    const navigate = useNavigate()
    const type       = entry.entry_type
    const name       = entry.name || entry.task_name || entry.service_name || '?'
    const value      = entry.value_data || entry.command || entry.binary_path || ''
    const techniques = entry.techniques || []
    const accent     = SEV_ACCENT[entry.severity] || '#5a6b8a'

    return (
        <>
            <style>{`
                .rh-ec{
                    background:rgba(13,17,30,.92);
                    border:1px solid rgba(255,255,255,.07);
                    border-radius:9px;
                    padding:11px 14px 11px 15px;
                    cursor:pointer;position:relative;overflow:hidden;
                    transition:border-color .18s,transform .18s,box-shadow .18s;
                }
                .rh-ec:hover{
                    border-color:rgba(0,229,255,.2);
                    transform:translateY(-2px);
                    box-shadow:0 6px 24px rgba(0,0,0,.35);
                }
                .rh-ec:active{transform:scale(.985);}
                .rh-ec-bar{
                    position:absolute;left:0;top:0;bottom:0;width:2px;
                    border-radius:9px 0 0 9px;opacity:.55;
                    transition:opacity .25s;
                }
                .rh-ec:hover .rh-ec-bar{opacity:1;}
                .rh-ec-shimmer{
                    position:absolute;inset:0;
                    background:linear-gradient(130deg,rgba(0,229,255,.04),transparent 55%);
                    opacity:0;transition:opacity .25s;pointer-events:none;
                }
                .rh-ec:hover .rh-ec-shimmer{opacity:1;}
                .rh-ec-arrow{
                    position:absolute;right:11px;top:50%;
                    transform:translateY(-50%) translateX(5px);
                    opacity:0;transition:opacity .18s,transform .18s;
                    color:rgba(0,229,255,.45);
                }
                .rh-ec:hover .rh-ec-arrow{opacity:1;transform:translateY(-50%) translateX(0);}
            `}</style>

            <div className="rh-ec" onClick={() => navigate(`/entries/${type}/${entry.id}`)}>
                <div className="rh-ec-bar" style={{ background: accent }} />
                <div className="rh-ec-shimmer" />

                {/* Top row */}
                <div style={{ display:'flex', alignItems:'center', gap:7, marginBottom:5 }}>
                    <SeverityBadge severity={entry.severity} size="xs" />
                    <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:8, color:'rgba(53,64,96,.9)', textTransform:'uppercase', letterSpacing:'.1em' }}>
                        {type}
                    </span>
                    <span style={{ fontFamily:"'Space Grotesk',sans-serif", fontSize:12, fontWeight:600, color:'rgba(238,242,255,.95)', flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                        {name}
                    </span>
                </div>

                {/* Value */}
                {value && (
                    <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:'rgba(53,64,96,.85)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', marginBottom:techniques.length ? 7 : 0 }}>
                        {value.slice(0, 80)}
                    </div>
                )}

                {/* MITRE tags */}
                {techniques.length > 0 && (
                    <div style={{ display:'flex', flexWrap:'wrap', gap:4 }}>
                        {techniques.slice(0, 4).map(t => (
                            <MitreTag key={t.id} id={t.id} name={t.name} />
                        ))}
                        {techniques.length > 4 && (
                            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:8, color:'rgba(58,66,96,.7)', paddingTop:2 }}>
                                +{techniques.length - 4}
                            </span>
                        )}
                    </div>
                )}

                <svg className="rh-ec-arrow" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                    <path d="M5 12h14M12 5l7 7-7 7"/>
                </svg>
            </div>
        </>
    )
}