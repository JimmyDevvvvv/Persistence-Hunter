// src/components/ui/LoadingSpinner.jsx
import { useEffect, useRef } from 'react'

export function LoadingSpinner({ size = 'md' }) {
    const dims = { sm: 16, md: 24, lg: 36 }
    const strokes = { sm: 2, md: 2, lg: 3 }
    const d = dims[size] || 24
    const s = strokes[size] || 2
    const r = (d - s * 2) / 2
    const circ = 2 * Math.PI * r

    return (
        <svg
            width={d}
            height={d}
            viewBox={`0 0 ${d} ${d}`}
            style={{ flexShrink: 0 }}
        >
            {/* Track */}
            <circle
                cx={d / 2}
                cy={d / 2}
                r={r}
                fill="none"
                stroke="rgba(0,229,255,0.1)"
                strokeWidth={s}
            />
            {/* Spinning arc */}
            <circle
                cx={d / 2}
                cy={d / 2}
                r={r}
                fill="none"
                stroke="var(--cyan, #00e5ff)"
                strokeWidth={s}
                strokeLinecap="round"
                strokeDasharray={`${circ * 0.25} ${circ * 0.75}`}
                style={{
                    transformOrigin: '50% 50%',
                    animation: 'rh-spin 0.75s linear infinite',
                    filter: 'drop-shadow(0 0 4px rgba(0,229,255,0.6))',
                }}
            />
            <style>{`
                @keyframes rh-spin { to { transform: rotate(360deg); } }
            `}</style>
        </svg>
    )
}