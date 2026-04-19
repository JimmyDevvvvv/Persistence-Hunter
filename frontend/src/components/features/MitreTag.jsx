// src/components/ui/MitreTag.jsx

export function MitreTag({ id, name }) {
    return (
        <>
            <style>{`
                .rh-mitre-tag {
                    display: inline-flex;
                    align-items: center;
                    gap: 4px;
                    font-family: 'JetBrains Mono', 'IBM Plex Mono', monospace;
                    font-size: 9px;
                    font-weight: 600;
                    padding: 3px 8px;
                    border-radius: 3px;
                    background: rgba(196,112,255,0.1);
                    border: 1px solid rgba(196,112,255,0.25);
                    color: #c470ff;
                    cursor: default;
                    transition: border-color 0.2s, box-shadow 0.2s, background 0.2s;
                    position: relative;
                    overflow: hidden;
                }
                .rh-mitre-tag::before {
                    content: '';
                    position: absolute;
                    inset: 0;
                    background: rgba(196,112,255,0.12);
                    transform: scaleX(0);
                    transform-origin: left;
                    transition: transform 0.3s ease;
                }
                .rh-mitre-tag:hover::before { transform: scaleX(1); }
                .rh-mitre-tag:hover {
                    border-color: rgba(196,112,255,0.55);
                    box-shadow: 0 0 10px rgba(196,112,255,0.2);
                }
            `}</style>
            <span className="rh-mitre-tag" title={name}>
                {id}
            </span>
        </>
    )
}