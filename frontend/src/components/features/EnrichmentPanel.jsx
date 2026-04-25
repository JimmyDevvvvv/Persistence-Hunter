// src/components/features/EnrichmentPanel.jsx
// Repurposed: shows signature data for services, decoded PS for registry/task
import { useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchSignatures } from '../../api/client'

const ACCENT = {
    red: '#ff2055',
    green: '#00e676',
    yellow: '#ffd60a',
    cyan: '#00e5ff',
    purple: '#c470ff',
}

function Row({ label, value, mono = false, accent, small = false }) {
    const color = ACCENT[accent] || 'rgba(140,155,175,1)'
    const show = value === null || value === undefined || value === '' ? '—' : value
    const isEmpty = show === '—'
    return (
        <div
            style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 14, padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,.04)', transition: 'background .12s', cursor: 'default' }}
            onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,.02)'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
        >
            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, flexShrink: 0, width: 110, color: 'rgba(53,64,96,.85)', textTransform: 'uppercase', letterSpacing: '.06em' }}>
                {label}
            </span>
            <span style={{ fontFamily: mono ? "'JetBrains Mono',monospace" : "'Space Grotesk',sans-serif", fontSize: small ? 9 : 10, textAlign: 'right', wordBreak: 'break-all', color: isEmpty ? 'rgba(53,64,96,.5)' : color, opacity: isEmpty ? 0.5 : 1 }}>
                {show}
            </span>
        </div>
    )
}

function Section({ title, children, delay = 0, icon }) {
    const ref = useRef(null)
    useEffect(() => {
        const el = ref.current
        if (!el) return
        el.style.opacity = '0'; el.style.transform = 'translateY(8px)'
        const t = setTimeout(() => {
            el.style.transition = 'opacity .38s ease, transform .38s ease'
            el.style.opacity = '1'; el.style.transform = 'translateY(0)'
        }, delay)
        return () => clearTimeout(t)
    }, [delay])
    return (
        <div ref={ref} style={{ marginBottom: 11 }}>
            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 8, fontWeight: 700, letterSpacing: '.16em', textTransform: 'uppercase', color: 'rgba(53,64,96,.85)', marginBottom: 6, paddingLeft: 2, display: 'flex', alignItems: 'center', gap: 6 }}>
                {icon && <span style={{ opacity: .7 }}>{icon}</span>}
                {title}
            </div>
            <div style={{ background: 'rgba(13,17,30,.92)', border: '1px solid rgba(255,255,255,.07)', borderRadius: 8, overflow: 'hidden' }}>
                <div style={{ padding: '0 13px' }}>
                    {children}
                </div>
            </div>
        </div>
    )
}

// ── Service signature panel ───────────────────────────────────────────────────
function ServiceSignaturePanel({ serviceName }) {
    const { data, isLoading } = useQuery({
        queryKey: ['signatures'],
        queryFn: () => fetchSignatures({ exe_only: true }),
        staleTime: 5 * 60 * 1000,
    })

    if (isLoading) return (
        <div style={{ padding: '32px 0', display: 'flex', justifyContent: 'center' }}>
            <svg width="16" height="16" viewBox="0 0 20 20">
                <circle cx="10" cy="10" r="8" fill="none" stroke="rgba(0,229,255,.15)" strokeWidth="2" />
                <circle cx="10" cy="10" r="8" fill="none" stroke="#00e5ff" strokeWidth="2"
                    strokeLinecap="round" strokeDasharray="12 38"
                    style={{ transformOrigin: '50% 50%', animation: 'rh-espin .75s linear infinite' }} />
                <style>{`@keyframes rh-espin{to{transform:rotate(360deg)}}`}</style>
            </svg>
        </div>
    )

    // Find this service in signature results
    const results = data?.results || []
    const sig = results.find(r =>
        r.service_name?.toLowerCase() === serviceName?.toLowerCase()
    )

    if (!sig) return (
        <div style={{ padding: '28px 0', textAlign: 'center' }}>
            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'rgba(90,107,138,1)', marginBottom: 4 }}>
                No signature data
            </div>
            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: 'rgba(53,64,96,1)' }}>
                POST /api/signatures/run to scan binaries
            </div>
        </div>
    )

    const statusColor = sig.sig_status === 'Valid' ? 'green'
        : sig.sig_status === 'NotSigned' ? 'red'
            : sig.sig_status === 'Missing' ? 'yellow'
                : sig.sig_status === 'HashMismatch' ? 'red'
                    : undefined

    const statusLabel = sig.sig_status === 'Valid' ? `✅ Signed — ${sig.signer || 'Unknown'}`
        : sig.sig_status === 'NotSigned' ? '❌ UNSIGNED'
            : sig.sig_status === 'Missing' ? '👻 File missing'
                : sig.sig_status === 'HashMismatch' ? '⚠️ Hash mismatch'
                    : sig.sig_status || '?'

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
            <Section title="Binary Signature" delay={0} icon="🔐">
                <Row label="Status" value={statusLabel} accent={statusColor} />
                <Row label="Issuer" value={sig.issuer} />
                <Row label="Path" value={sig.exe_path} mono small />
                <Row label="Suspicious" value={sig.suspicious_path ? '⚠ Yes' : 'No'} accent={sig.suspicious_path ? 'yellow' : 'green'} />
                <Row label="Exists" value={sig.file_exists ? 'Yes' : '❌ Not found'} accent={sig.file_exists ? 'green' : 'red'} />
            </Section>

            {sig.sha256 && (
                <Section title="File Hash" delay={80} icon="#">
                    <Row label="SHA-256" value={sig.sha256} mono accent="cyan" small />
                </Section>
            )}

            {sig.vt_url && (
                <Section title="Threat Intel" delay={150} icon="🛡">
                    <div style={{ padding: '8px 0' }}>
                        <a
                            href={sig.vt_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: '#00e5ff', wordBreak: 'break-all' }}
                        >
                            VirusTotal →
                        </a>
                    </div>
                </Section>
            )}
        </div>
    )
}

// ── PS decode panel ───────────────────────────────────────────────────────────
function PSDecodePanel({ value }) {
    if (!value) return null
    const hasEnc = /(-enc|-EncodedCommand|-e\s)/i.test(value)
    if (!hasEnc) return null

    // Extract and decode client-side
    let decoded = null
    try {
        const m = value.match(/-(?:EncodedCommand|enc?)\s+([A-Za-z0-9+/=]{8,})/i)
        if (m) {
            const b64 = m[1].trim().padEnd(m[1].length + (4 - m[1].length % 4) % 4, '=')
            const raw = atob(b64)
            // UTF-16 LE decode
            let str = ''
            for (let i = 0; i < raw.length - 1; i += 2) {
                str += String.fromCharCode(raw.charCodeAt(i) | (raw.charCodeAt(i + 1) << 8))
            }
            decoded = str.trim() || null
        }
    } catch { }

    if (!decoded) return null

    return (
        <Section title="Decoded PowerShell" delay={0} icon="🔓">
            <div style={{ padding: '8px 0' }}>
                <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: '#00e5ff', wordBreak: 'break-all', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>
                    {decoded.length > 400 ? decoded.slice(0, 400) + '…' : decoded}
                </div>
            </div>
        </Section>
    )
}

// ── Main export ───────────────────────────────────────────────────────────────
export function EnrichmentPanel({ entryType, serviceName, value, hideRisk = false }) {
    // For services — show signature data
    if (entryType === 'service') {
        return (
            <>
                <style>{`@keyframes rh-pip-pulse{0%,100%{box-shadow:0 0 4px #ff2055}50%{box-shadow:0 0 12px #ff2055,0 0 20px rgba(255,32,85,.3)}}`}</style>
                <ServiceSignaturePanel serviceName={serviceName} />
            </>
        )
    }

    // For registry/task — show PS decode if applicable
    const hasEnc = /(-enc|-EncodedCommand)/i.test(value || '')
    if (hasEnc) {
        return (
            <>
                <style>{`@keyframes rh-pip-pulse{0%,100%{box-shadow:0 0 4px #ff2055}50%{box-shadow:0 0 12px #ff2055,0 0 20px rgba(255,32,85,.3)}}`}</style>
                <PSDecodePanel value={value} />
            </>
        )
    }

    // Fallback empty state
    return (
        <>
            <style>{`@keyframes rh-bolt-float{0%,100%{transform:translateY(0) scale(1);opacity:.15}50%{transform:translateY(-6px) scale(1.05);opacity:.25}}`}</style>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '64px 0', gap: 14, textAlign: 'center' }}>
                <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="rgba(0,229,255,.3)" strokeWidth="1.5" strokeLinecap="round" style={{ animation: 'rh-bolt-float 3s ease-in-out infinite' }}>
                    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
                </svg>
                <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: 'rgba(90,107,138,1)' }}>
                    {entryType === 'registry' ? 'No encoded payload detected' : 'No binary data'}
                </div>
                <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, color: 'rgba(53,64,96,1)' }}>
                    {entryType === 'service' ? 'Run signature check to see binary intel' : 'No PowerShell encoding found in this entry'}
                </div>
            </div>
        </>
    )
}