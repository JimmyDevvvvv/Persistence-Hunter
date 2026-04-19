// src/components/layout/Layout.jsx
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'
import { useLocation } from 'react-router-dom'

// Pages that want full-height no-padding layout (their own internal layout)
const FULL_HEIGHT_ROUTES = ['/alerts', '/entries/']

export function Layout({ children, onScan, scanJob }) {
    const { pathname } = useLocation()
    const isFullHeight = FULL_HEIGHT_ROUTES.some(r => pathname.startsWith(r)) || pathname === '/alerts'

    // EntryDetail pages also need full height
    const isEntryDetail = pathname.match(/^\/entries\/[^/]+\/[^/]+/)

    const needsNoPad = isFullHeight || isEntryDetail

    return (
        <div className="flex h-screen overflow-hidden" style={{ background: 'var(--bg-base)' }}>
            <Sidebar />
            <div className="flex flex-col flex-1 overflow-hidden">
                <TopBar onScan={onScan} scanJob={scanJob} />
                <main
                    className="flex-1 overflow-hidden animate-fade-in"
                    style={needsNoPad ? {} : { overflowY: 'auto', padding: '22px 26px' }}
                >
                    {children}
                </main>
            </div>
        </div>
    )
}