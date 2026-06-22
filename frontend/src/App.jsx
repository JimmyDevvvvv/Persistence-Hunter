// src/App.jsx
import { useState } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Layout } from './components/layout/Layout'
import { Dashboard } from './pages/Dashboard'
import { Alerts } from './pages/Alerts'
import { Entries } from './pages/Entries'
import { EntryDetail } from './pages/EntryDetail'
import { Search } from './pages/Search'
import { Baseline } from './pages/Baseline'
import ConsumerDashboard from './pages/ConsumerDashboard'

const qc = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10000,
      retry: 1,
    },
  },
})

export default function App() {
  const [analystMode, setAnalystMode] = useState(false)

  return (
    <QueryClientProvider client={qc}>
      {analystMode ? (
        <BrowserRouter>
          <Layout onSwitchToConsumer={() => setAnalystMode(false)}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/entries" element={<Entries />} />
              <Route path="/entries/:type/:id" element={<EntryDetail />} />
              <Route path="/search" element={<Search />} />
              <Route path="/baseline" element={<Baseline />} />
            </Routes>
          </Layout>
        </BrowserRouter>
      ) : (
        <ConsumerDashboard onSwitchToAnalyst={() => setAnalystMode(true)} />
      )}
    </QueryClientProvider>
  )
}
