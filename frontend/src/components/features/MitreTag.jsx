// src/components/ui/MitreTag.jsx
import { useState } from 'react'

export function MitreTag({ id, name }) {
    const [hover, setHover] = useState(false)
    return (
        <>
            <style>{`
                @keyframes rh-mt-pop{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
                .rh-mitre-tag{
                    display:inline-flex;align-items:center;gap:3px;
                    font-family:'JetBrains Mono','IBM Plex Mono',monospace;
                    font-size:8px;font-weight:700;
                    padding:2px 7px;border-radius:3px;
                    background:rgba(196,112,255,0.08);
                    border:1px solid rgba(196,112,255,0.22);
                    color:#c470ff;cursor:default;
                    transition:border-color .18s,box-shadow .18s,background .18s;
                    position:relative;overflow:visible;
                    letter-spacing:.04em;
                }
                .rh-mitre-tag:hover{
                    border-color:rgba(196,112,255,.55);
                    background:rgba(196,112,255,.14);
                    box-shadow:0 0 10px rgba(196,112,255,.2);
                }
            `}</style>
            <span
                className="rh-mitre-tag"
                onMouseEnter={() => setHover(true)}
                onMouseLeave={() => setHover(false)}
            >
                <svg width="7" height="7" viewBox="0 0 24 24" fill="none" stroke="#c470ff" strokeWidth="2.5" style={{ opacity:.7 }}>
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                {id}
                {hover && name && (
                    <div style={{
                        position:'absolute', bottom:'calc(100% + 6px)', left:'50%',
                        transform:'translateX(-50%)',
                        background:'rgba(15,19,32,.97)', border:'1px solid rgba(196,112,255,.3)',
                        borderRadius:6, padding:'5px 9px', whiteSpace:'nowrap', zIndex:50,
                        fontFamily:"'JetBrains Mono',monospace", fontSize:8, fontWeight:400,
                        color:'rgba(192,200,224,.9)', letterSpacing:'.02em',
                        boxShadow:'0 4px 20px rgba(0,0,0,.5)',
                        animation:'rh-mt-pop .15s ease',
                        pointerEvents:'none',
                    }}>
                        {name}
                    </div>
                )}
            </span>
        </>
    )
}