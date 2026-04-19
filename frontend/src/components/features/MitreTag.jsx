// src/components/ui/MitreTag.jsx
export function MitreTag({ id, name }) {
    return (
        <span
            title={name}
            className="mono text-[10px] px-1.5 py-0.5 rounded border border-purple-500/30
                 bg-purple-500/10 text-purple-400 cursor-default"
        >
            {id}
        </span>
    )
}