/**
 * api/client.js
 * All API calls in one place. Components never call axios directly.
 * Base URL reads from env var VITE_API_URL (defaults to localhost:8000).
 */

import axios from 'axios'

const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const api = axios.create({ baseURL: BASE, timeout: 30000 })

// ── Stats ────────────────────────────────────────────────────────────────────
export const fetchHealth = () => api.get('/api/health').then(r => r.data)
export const fetchStats = () => api.get('/api/stats').then(r => r.data)

// ── Entries ──────────────────────────────────────────────────────────────────
export const fetchEntries = (params = {}) =>
    api.get('/api/entries', { params }).then(r => r.data)

export const fetchEntry = (type, id) =>
    api.get(`/api/entries/${type}/${id}`).then(r => r.data)

// ── Alerts ───────────────────────────────────────────────────────────────────
export const fetchAlerts = (limit = 200) =>
    api.get('/api/alerts', { params: { limit } }).then(r => r.data)

// ── Chains ───────────────────────────────────────────────────────────────────
export const fetchChain = (type, id, rebuild = false) =>
    api.get(`/api/chains/${type}/${id}`, { params: { rebuild } }).then(r => r.data)

// ── Search ───────────────────────────────────────────────────────────────────
export const search = (q, entry_type = 'all', limit = 100) =>
    api.get('/api/search', { params: { q, entry_type, limit } }).then(r => r.data)

// ── Scan ─────────────────────────────────────────────────────────────────────
export const triggerScan = (payload) =>
    api.post('/api/scan', payload).then(r => r.data)

export const fetchScanStatus = (jobId) =>
    api.get('/api/scan/status', { params: jobId ? { job_id: jobId } : {} })
        .then(r => r.data)

// ── Baseline ─────────────────────────────────────────────────────────────────
export const fetchBaselines = () => api.get('/api/baseline').then(r => r.data)
export const createBaseline = (payload) => api.post('/api/baseline', payload).then(r => r.data)
export const fetchDiff = (params) => api.get('/api/baseline/diff', { params }).then(r => r.data)
export const deleteBaseline = (id) => api.delete(`/api/baseline/${id}`).then(r => r.data)

// ── Enrichment ───────────────────────────────────────────────────────────────
export const fetchEnrichment = (type, id) =>
    api.get(`/api/enrich/${type}/${id}`).then(r => r.data)

export const triggerEnrichment = (type, id) =>
    api.post(`/api/enrich/${type}/${id}`).then(r => r.data)

// ── Export ───────────────────────────────────────────────────────────────────
export const exportMitre = () =>
    api.get('/api/export/mitre').then(r => r.data)

// ── Scores ───────────────────────────────────────────────────────────────────
export const fetchScore = (type, id) =>
    api.get(`/api/scores/${type}/${id}`).then(r => r.data)

export const triggerScores = () =>
    api.post('/api/scores/run').then(r => r.data)