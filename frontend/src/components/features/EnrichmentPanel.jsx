// src/components/features/EnrichmentPanel.jsx

function Row({ label, value, mono = false, accent }) {
    const color = {
        red:    'var(--red)',
        green:  'var(--green)',
        yellow: 'var(--yellow)',
        cyan:   'var(--cyan)',
    }[accent] || 'var(--text-secondary)'

    return (
        <div className="flex items-start justify-between gap-4 py-2"
            style={{ borderBottom: '1px solid var(--bg-border)' }}>
            <span className="text-[11px] shrink-0 w-32" style={{ color: 'var(--text-muted)' }}>
                {label}
            </span>
            <span className={`text-[11px] text-right break-all ${mono ? 'font-mono' : ''}`}
                style={{ color }}>
                {value ?? '—'}
            </span>
        </div>
    )
}

function Section({ title, children }) {
    return (
        <div>
            <div className="panel-label mb-2">{title}</div>
            <div className="panel" style={{ overflow: 'visible' }}>
                <div className="px-4 py-0.5 [&>*:last-child]:border-b-0">
                    {children}
                </div>
            </div>
        </div>
    )
}

function RiskIndicator({ indicator }) {
    const sevColor = indicator.severity === 'critical' ? 'var(--red)'
        : indicator.severity === 'high' ? 'var(--orange)'
            : 'var(--yellow)'

    return (
        <div className="p-3 rounded-lg"
            style={{
                background: 'var(--bg-raised)',
                borderLeft: `3px solid ${sevColor}`,
                border: '1px solid var(--bg-border)',
            }}>
            <div className="font-mono text-[10px] font-semibold uppercase tracking-widest mb-1"
                style={{ color: sevColor }}>
                {indicator.type.replace(/_/g, ' ')}
            </div>
            <div className="text-[11px] leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                {indicator.description}
            </div>
        </div>
    )
}

export function EnrichmentPanel({ enrichment }) {
    if (!enrichment) {
        return (
            <div className="flex flex-col items-center justify-center py-16 gap-3"
                style={{ color: 'var(--text-muted)' }}>
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                    strokeWidth="1.5" strokeLinecap="round" opacity="0.2">
                    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
                </svg>
                <div className="text-center">
                    <div className="font-mono text-xs mb-1">No enrichment data</div>
                    <div className="font-mono text-[10px]" style={{ opacity: 0.6 }}>
                        Trigger enrichment to analyse this file
                    </div>
                </div>
            </div>
        )
    }

    const { hashes, risk_indicators = [] } = enrichment

    return (
        <div className="space-y-5 animate-slide-up max-w-2xl">

            {/* Risk indicators */}
            {risk_indicators.length > 0 && (
                <div>
                    <div className="panel-label mb-2">
                        Risk Indicators
                        <span className="ml-2 font-mono text-[9px] px-1.5 py-0.5 rounded"
                            style={{ background: 'rgba(255,53,96,0.1)', color: 'var(--red)', border: '1px solid rgba(255,53,96,0.25)' }}>
                            {risk_indicators.length}
                        </span>
                    </div>
                    <div className="space-y-2">
                        {risk_indicators.map((ind, i) => (
                            <RiskIndicator key={i} indicator={ind} />
                        ))}
                    </div>
                </div>
            )}

            {/* Hashes */}
            {hashes?.sha256 && (
                <Section title="File Hashes">
                    <Row label="MD5"    value={enrichment.md5}    mono accent="cyan" />
                    <Row label="SHA1"   value={enrichment.sha1}   mono accent="cyan" />
                    <Row label="SHA256" value={enrichment.sha256} mono accent="cyan" />
                </Section>
            )}

            {/* File info */}
            <Section title="File Info">
                <Row label="Exists"
                    value={enrichment.file_exists ? 'Yes' : 'Not found'}
                    accent={enrichment.file_exists ? 'green' : 'red'} />
                <Row label="Size"
                    value={enrichment.file_size ? `${(enrichment.file_size / 1024).toFixed(1)} KB` : null} />
                <Row label="Signed"
                    value={enrichment.pe_signed ? 'Yes' : 'No'}
                    accent={enrichment.pe_signed ? 'green' : 'red'} />
                <Row label="Publisher" value={enrichment.pe_publisher} />
                <Row label="PE"
                    value={enrichment.pe_is_pe ? 'Yes' : 'No'} />
                <Row label="Compile Time"
                    value={enrichment.pe_compile_time ? enrichment.pe_compile_time.slice(0, 10) : null}
                    accent={enrichment.pe_compile_suspicious ? 'red' : undefined}
                    mono />
                <Row label="Architecture"
                    value={enrichment.pe_is_64bit ? '64-bit' : enrichment.pe_is_pe ? '32-bit' : null} />
            </Section>

            {/* Threat intel */}
            {(enrichment.vt_found !== null || enrichment.mb_found !== null) && (
                <Section title="Threat Intel">
                    {enrichment.vt_total > 0 && (
                        <Row label="VirusTotal"
                            value={`${enrichment.vt_malicious}/${enrichment.vt_total} detections`}
                            accent={enrichment.vt_malicious > 0 ? 'red' : 'green'} />
                    )}
                    {enrichment.mb_found !== null && (
                        <Row label="MalwareBazaar"
                            value={enrichment.mb_found ? `Hit — ${enrichment.mb_signature || 'unknown'}` : 'Not found'}
                            accent={enrichment.mb_found ? 'red' : 'green'} />
                    )}
                    <Row label="Verdict"
                        value={(enrichment.overall_verdict || 'unknown').toUpperCase()}
                        mono
                        accent={
                            enrichment.overall_verdict === 'malicious' ? 'red' :
                                enrichment.overall_verdict === 'suspicious' ? 'yellow' :
                                    enrichment.overall_verdict === 'clean' ? 'green' : undefined
                        } />
                </Section>
            )}
        </div>
    )
}