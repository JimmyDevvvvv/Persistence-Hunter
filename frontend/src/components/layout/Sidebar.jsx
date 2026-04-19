// src/components/layout/Sidebar.jsx
import { NavLink } from 'react-router-dom'

const NAV = [
    {
        to: '/', label: 'Dashboard',
        icon: (
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" />
                <rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" />
            </svg>
        ),
    },
    {
        to: '/alerts', label: 'Alerts',
        icon: (
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
        ),
    },
    {
        to: '/entries', label: 'Entries',
        icon: (
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <line x1="8" y1="6" x2="21" y2="6" /><line x1="8" y1="12" x2="21" y2="12" />
                <line x1="8" y1="18" x2="21" y2="18" /><line x1="3" y1="6" x2="3.01" y2="6" />
                <line x1="3" y1="12" x2="3.01" y2="12" /><line x1="3" y1="18" x2="3.01" y2="18" />
            </svg>
        ),
    },
    {
        to: '/search', label: 'Hunt',
        icon: (
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="11" cy="11" r="7" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
        ),
    },
    {
        to: '/baseline', label: 'Baseline',
        icon: (
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="3" />
            </svg>
        ),
    },
]

export function Sidebar() {
    return (
        <aside
            style={{ background: 'var(--bg-surface)', borderRight: '1px solid var(--bg-border)', width: 160 }}
            className="flex flex-col shrink-0"
        >
            {/* ── Logo area - matches reference: just text ── */}
            <div style={{ padding: '14px 16px 12px', borderBottom: '1px solid var(--bg-border)' }}>
                <div style={{ fontFamily: 'IBM Plex Mono', fontWeight: 700, fontSize: 12, color: 'var(--cyan)', letterSpacing: '0.12em', lineHeight: 1.2 }}>
                    PERSISTENCE
                </div>
                <div style={{ fontFamily: 'IBM Plex Mono', fontWeight: 600, fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.2em', marginTop: 1 }}>
                    HUNTER
                </div>
            </div>

            {/* ── MONITORING indicator ── */}
            <div style={{ padding: '8px 16px', borderBottom: '1px solid var(--bg-border)', display: 'flex', alignItems: 'center', gap: 7 }}>
                <div style={{
                    width: 7, height: 7, borderRadius: '50%',
                    background: 'var(--green)', boxShadow: '0 0 6px var(--green)',
                    animation: 'pulse 2s ease-in-out infinite',
                    flexShrink: 0,
                }} />
                <span style={{ fontFamily: 'IBM Plex Mono', fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase' }}>
                    Monitoring
                </span>
                <div style={{
                    marginLeft: 'auto', fontFamily: 'IBM Plex Mono', fontSize: 8,
                    color: 'var(--green)', background: 'rgba(0,229,153,0.08)',
                    border: '1px solid rgba(0,229,153,0.2)', padding: '1px 4px', borderRadius: 3,
                }}>
                    LIVE
                </div>
            </div>

            {/* ── Nav ── */}
            <nav style={{ flex: 1, paddingTop: 8, paddingBottom: 8 }}>
                {NAV.map(({ to, icon, label }) => (
                    <NavLink
                        key={to}
                        to={to}
                        end={to === '/'}
                        className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
                    >
                        <span style={{ opacity: 0.8, display: 'flex', alignItems: 'center' }}>{icon}</span>
                        <span style={{ fontSize: 12, fontWeight: 500 }}>{label}</span>
                    </NavLink>
                ))}
            </nav>

            {/* ── Footer ── */}
            <div style={{ padding: '10px 16px', borderTop: '1px solid var(--bg-border)' }}>
                <div style={{ fontFamily: 'IBM Plex Mono', fontSize: 9, color: 'var(--text-muted)' }}>v1.0.0</div>
            </div>
        </aside>
    )
}