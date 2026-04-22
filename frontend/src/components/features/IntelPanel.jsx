import { useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useQuery } from '@tanstack/react-query'
import { fetchScore } from '../../api/client'
import { EnrichmentPanel } from './EnrichmentPanel'
import { ThreatScorePanel } from './Threatscore'

function normalizeIndicator(ind, source) {
  const type = String(ind?.type || '').trim()
  const description = String(ind?.description || '').trim()
  const severity = String(ind?.severity || 'medium').trim()
  const key = `${type}::${description}`.toLowerCase()
  return { key, type, description, severity, source, raw: ind }
}

function sevRank(sev) {
  if (sev === 'critical') return 3
  if (sev === 'high') return 2
  if (sev === 'medium') return 1
  return 0
}

function RiskCard({ ind, i }) {
  const c =
    ind.severity === 'critical' ? '#ff2055' :
      ind.severity === 'high' ? '#ff7722' :
        '#ffd60a'

  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1], delay: i * 0.04 }}
      style={{
        padding: '10px 12px',
        borderRadius: 9,
        background: 'rgba(15,19,32,.9)',
        border: '1px solid rgba(255,255,255,.07)',
        borderLeft: `3px solid ${c}`,
      }}
    >
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 10,
        marginBottom: 4,
      }}>
        <div style={{
          display: 'flex', alignItems: 'center', gap: 7, minWidth: 0,
          fontFamily: "'JetBrains Mono',monospace",
          fontSize: 8, fontWeight: 700,
          textTransform: 'uppercase', letterSpacing: '.12em',
          color: c,
        }}>
          <div style={{
            width: 4, height: 4, borderRadius: '50%', background: c,
            boxShadow: `0 0 7px ${c}`,
          }} />
          <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {(ind.type || 'risk').replace(/_/g, ' ')}
          </span>
        </div>
        <span style={{
          flexShrink: 0,
          fontFamily: "'JetBrains Mono',monospace",
          fontSize: 8,
          padding: '1px 6px',
          borderRadius: 3,
          border: '1px solid rgba(255,255,255,.08)',
          color: 'rgba(106,117,144,.9)',
          background: 'rgba(255,255,255,.03)',
        }}>
          {ind.source}
        </span>
      </div>
      <div style={{ fontSize: 11, color: 'rgba(140,155,175,1)', lineHeight: 1.5 }}>
        {ind.description || '—'}
      </div>
    </motion.div>
  )
}

export function IntelPanel({ entryType, entryId, enrichment }) {
  const MotionDiv = motion.div

  const { data: scoreData } = useQuery({
    queryKey: ['score', entryType, entryId, 'lite'],
    queryFn: () => fetchScore(entryType, entryId),
    enabled: !!entryType && !!entryId,
  })

  const mergedIndicators = useMemo(() => {
    const enrich = (enrichment?.risk_indicators || []).map(i => normalizeIndicator(i, 'enrich'))
    const score = (scoreData?.risk_indicators || []).map(i => normalizeIndicator(i, 'score'))
    const map = new Map()
    for (const ind of [...enrich, ...score]) {
      if (!ind.key || ind.key === '::') continue
      if (!map.has(ind.key)) map.set(ind.key, ind)
    }
    const out = [...map.values()]
    out.sort((a, b) => sevRank(b.severity) - sevRank(a.severity))
    return out
  }, [enrichment, scoreData])

  return (
    <>
      <style>{`
        .rh-intel-grid{
          display:grid;
          grid-template-columns: 1.2fr 1fr;
          gap:14px;
          align-items:start;
        }
        @media (max-width: 1100px){
          .rh-intel-grid{ grid-template-columns: 1fr; }
        }
      `}</style>
      <div className="rh-intel-grid">
      {/* Left: enrichment (hashes/file intel/intel verdict) */}
      <MotionDiv
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.32, ease: [0.16, 1, 0.3, 1] }}
        style={{ minWidth: 0 }}
      >
        <EnrichmentPanel enrichment={enrichment} hideRisk />
      </MotionDiv>

      {/* Right: unified risk feed + threat score */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14, minWidth: 0 }}>
        <div>
          <div style={{
            fontFamily: "'JetBrains Mono',monospace",
            fontSize: 8, fontWeight: 700,
            letterSpacing: '.18em', textTransform: 'uppercase',
            color: 'rgba(53,64,96,1)',
            marginBottom: 8,
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
            Risk & Intel Signals
            <span style={{
              fontFamily: "'JetBrains Mono',monospace",
              fontSize: 8,
              padding: '1px 6px',
              borderRadius: 3,
              background: 'rgba(255,32,85,.1)',
              color: '#ff2055',
              border: '1px solid rgba(255,32,85,.25)',
            }}>
              {mergedIndicators.length}
            </span>
          </div>

          <AnimatePresence initial={false}>
            {mergedIndicators.length === 0 ? (
              <MotionDiv
                key="empty"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                style={{
                  padding: '18px 14px',
                  borderRadius: 10,
                  background: 'rgba(15,19,32,.9)',
                  border: '1px solid rgba(255,255,255,.07)',
                  color: 'rgba(90,107,138,1)',
                  fontFamily: "'JetBrains Mono',monospace",
                  fontSize: 10,
                  textAlign: 'center',
                }}
              >
                No signals yet — run enrichment and scoring.
              </MotionDiv>
            ) : (
              <MotionDiv
                key="list"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                style={{ display: 'flex', flexDirection: 'column', gap: 8 }}
              >
                {mergedIndicators.slice(0, 10).map((ind, i) => (
                  <RiskCard key={ind.key} ind={ind} i={i} />
                ))}
                {mergedIndicators.length > 10 && (
                  <div style={{
                    fontFamily: "'JetBrains Mono',monospace",
                    fontSize: 9,
                    color: 'rgba(106,117,144,.8)',
                    paddingLeft: 4,
                  }}>
                    Showing top 10 · {mergedIndicators.length - 10} more signals
                  </div>
                )}
              </MotionDiv>
            )}
          </AnimatePresence>
        </div>

        <MotionDiv
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.32, ease: [0.16, 1, 0.3, 1], delay: 0.06 }}
        >
          <ThreatScorePanel entryType={entryType} entryId={entryId} hideRiskIndicators />
        </MotionDiv>
      </div>
      </div>
    </>
  )
}

