// src/components/ui/LoadingSpinner.jsx
export function LoadingSpinner({ size = 'md' }) {
    const s = size === 'sm' ? 'w-4 h-4' : size === 'lg' ? 'w-8 h-8' : 'w-6 h-6'
    return (
        <div className={`${s} border-2 border-bg-border border-t-cyan-400 rounded-full animate-spin`} />
    )
}