// src/components/features/ScanButton.jsx
// Standalone scan button — can be embedded anywhere.
// The TopBar uses its own inline scan logic, but this component
// can be used on Dashboard or other pages if needed.
import { useState } from 'react'
import { triggerScan, fetchScanStatus } from '../../api/client'
import { LoadingSpinner } from '../ui/LoadingSpinner'

export function ScanButton({ onComplete, label = 'SCAN', hours = 24 }) {
    const [running, setRunning] = useState(false)
    const [progress, setProgress] = useState(0)
    const [stage, setStage] = useState('')

    async function handleScan() {
        if (running) return
        setRunning(true)
        setProgress(0)
        try {
            const { job_id } = await triggerScan({
                hours,
                entry_types: ['registry', 'task', 'service'],
                enrich: false,
            })

            const interval = setInterval(async () => {
                const status = await fetchScanStatus(job_id)
                setProgress(status.progress || 0)
                setStage(status.stage || '')
                if (status.status === 'done' || status.status === 'error') {
                    clearInterval(interval)
                    setRunning(false)
                    if (status.status === 'done') onComplete?.()
                }
            }, 1500)
        } catch {
            setRunning(false)
        }
    }

    return (
        <div className="flex flex-col gap-1">
            <button
                onClick={handleScan}
                disabled={running}
                className={`flex items-center gap-2 px-4 py-1.5 rounded text-xs
                    mono tracking-wider transition-all border
                    ${running
                        ? 'border-cyan-500/30 text-cyan-500/50 cursor-not-allowed'
                        : 'border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/10 hover:border-cyan-400'
                    }`}
            >
                {running ? <LoadingSpinner size="sm" /> : <span>▶</span>}
                {running ? 'SCANNING' : label}
            </button>

            {running && (
                <div className="flex items-center gap-2">
                    <div className="flex-1 h-0.5 bg-bg-border rounded-full overflow-hidden">
                        <div
                            className="h-full bg-cyan-400 transition-all duration-500 rounded-full"
                            style={{ width: `${progress}%` }}
                        />
                    </div>
                    <span className="mono text-[9px] text-slate-600 w-8 text-right">{progress}%</span>
                </div>
            )}
            {running && stage && (
                <span className="mono text-[9px] text-slate-600">{stage}</span>
            )}
        </div>
    )
}