// src/components/features/ScanButton.jsx
import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { triggerScan, fetchScanStatus } from '../../api/client'
import { LoadingSpinner } from '../ui/LoadingSpinner'

export function ScanButton({ onComplete, label = 'SCAN', hours = 24 }) {
    const [running, setRunning] = useState(false)
    const [progress, setProgress] = useState(0)
    const [stage, setStage] = useState('')
    const queryClient = useQueryClient()

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
                    if (status.status === 'done') {
                        // Invalidate everything that depends on scan results
                        await queryClient.invalidateQueries({ queryKey: ['scores-all'] })
                        await queryClient.invalidateQueries({ queryKey: ['alerts'] })
                        await queryClient.invalidateQueries({ queryKey: ['entries'] })
                        await queryClient.invalidateQueries({ queryKey: ['stats'] })
                        onComplete?.()
                    }
                }
            }, 1500)
        } catch {
            setRunning(false)
        }
    }

    return (
        <>
            <style>{`
                @keyframes rh-scan-shimmer {
                    0%, 100% { opacity: 0.25; }
                    50%       { opacity: 0.7;  }
                }
                @keyframes rh-prog-glow {
                    0%, 100% { box-shadow: 0 0 6px rgba(0,229,255,0.4); }
                    50%       { box-shadow: 0 0 14px rgba(0,229,255,0.7); }
                }
                @keyframes rh-sweep {
                    0%   { left: -40%; }
                    100% { left: 140%; }
                }
                .rh-scan-btn {
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                    font-family: 'JetBrains Mono', 'IBM Plex Mono', monospace;
                    font-size: 10px;
                    font-weight: 600;
                    letter-spacing: 0.14em;
                    text-transform: uppercase;
                    padding: 8px 18px;
                    border-radius: 6px;
                    border: 1px solid rgba(0,229,255,0.35);
                    color: #00e5ff;
                    background: rgba(0,229,255,0.05);
                    cursor: pointer;
                    position: relative;
                    overflow: hidden;
                    transition: border-color 0.25s, box-shadow 0.25s, transform 0.15s;
                    user-select: none;
                }
                .rh-scan-btn::before {
                    content: '';
                    position: absolute;
                    inset: 0;
                    background: rgba(0,229,255,0.08);
                    transform: scaleX(0);
                    transform-origin: left;
                    transition: transform 0.3s ease;
                }
                .rh-scan-btn:hover::before { transform: scaleX(1); }
                .rh-scan-btn:hover {
                    border-color: rgba(0,229,255,0.65);
                    box-shadow: 0 0 18px rgba(0,229,255,0.12);
                }
                .rh-scan-btn:active { transform: scale(0.96); }
                .rh-scan-btn.running {
                    border-color: rgba(0,229,255,0.18);
                    color: rgba(0,229,255,0.45);
                    cursor: not-allowed;
                }
                .rh-scan-btn.running::before {
                    transform: scaleX(1);
                    animation: rh-scan-shimmer 2s ease-in-out infinite;
                }
                .rh-prog-wrap {
                    display: flex;
                    flex-direction: column;
                    gap: 4px;
                    width: 100%;
                    animation: rh-empty-in 0.2s ease forwards;
                }
                @keyframes rh-empty-in {
                    from { opacity: 0; transform: translateY(4px); }
                    to   { opacity: 1; transform: translateY(0); }
                }
                .rh-prog-track {
                    width: 100%;
                    height: 2px;
                    background: rgba(255,255,255,0.07);
                    border-radius: 2px;
                    overflow: hidden;
                    position: relative;
                }
                .rh-prog-fill {
                    height: 100%;
                    background: #00e5ff;
                    border-radius: 2px;
                    transition: width 0.5s cubic-bezier(0.16,1,0.3,1);
                    animation: rh-prog-glow 1.5s ease-in-out infinite;
                    position: relative;
                }
                .rh-prog-fill::after {
                    content: '';
                    position: absolute;
                    top: 0; right: 0; bottom: 0;
                    width: 40px;
                    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4));
                }
                .rh-prog-labels {
                    display: flex;
                    justify-content: space-between;
                    font-family: 'JetBrains Mono', 'IBM Plex Mono', monospace;
                    font-size: 8px;
                    color: rgba(53,64,96,1);
                }
                .rh-prog-stage { color: rgba(90,107,138,0.8); }
            `}</style>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, alignItems: 'flex-start' }}>
                <button
                    className={`rh-scan-btn${running ? ' running' : ''}`}
                    onClick={handleScan}
                    disabled={running}
                >
                    {running ? (
                        <LoadingSpinner size="sm" />
                    ) : (
                        <svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor">
                            <polygon points="5,3 19,12 5,21" />
                        </svg>
                    )}
                    {running ? 'Scanning...' : label}
                </button>

                {running && (
                    <div className="rh-prog-wrap">
                        <div className="rh-prog-track">
                            <div className="rh-prog-fill" style={{ width: `${progress}%` }} />
                        </div>
                        <div className="rh-prog-labels">
                            <span className="rh-prog-stage">{stage || 'initializing...'}</span>
                            <span>{progress}%</span>
                        </div>
                    </div>
                )}
            </div>
        </>
    )
}