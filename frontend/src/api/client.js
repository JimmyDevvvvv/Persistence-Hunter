/**
 * src/api/client.js
 * All API calls in one place. Components never call axios directly.
 * Base URL reads from env var VITE_API_URL (defaults to localhost:8000).
 */

import axios from 'axios'

const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const api = axios.create({ baseURL: BASE, timeout: 30000 })

// ── Health & Stats ────────────────────────────────────────────────────────────
export const fetchHealth = () =>
    api.get('/api/health').then(r => r.data)

export const fetchStats = () =>
    api.get('/api/stats').then(r => r.data)

// ── Summary (cross-collector diff report) ─────────────────────────────────────
export const fetchSummary = (params = {}) =>
    api.get('/api/summary', { params }).then(r => r.data)
// params: { include_all: bool, include_chains: bool }

export const fetchSummaryStats = () =>
    api.get('/api/summary/stats').then(r => r.data)

// ── Entries ───────────────────────────────────────────────────────────────────
export const fetchEntries = (params = {}) =>
    api.get('/api/entries', { params }).then(r => r.data)

export const fetchEntry = (type, id) =>
    api.get(`/api/entries/${type}/${id}`).then(r => r.data)

// ── Alerts ────────────────────────────────────────────────────────────────────
export const fetchAlerts = (limit = 200) =>
    api.get('/api/alerts', { params: { limit } }).then(r => r.data)

// ── Chains ────────────────────────────────────────────────────────────────────
export const fetchChain = (type, id, rebuild = false) =>
    api.get(`/api/chains/${type}/${id}`, { params: { rebuild } }).then(r => r.data)

// ── Search ────────────────────────────────────────────────────────────────────
export const search = (q, entry_type = 'all', limit = 100) =>
    api.get('/api/search', { params: { q, entry_type, limit } }).then(r => r.data)

// ── Scan ──────────────────────────────────────────────────────────────────────
export const triggerScan = (payload = {}) =>
    api.post('/api/scan', {
        entry_types: ['registry', 'task', 'service'],
        hours: 24,
        ...payload,
    }).then(r => r.data)

export const fetchScanStatus = (jobId) =>
    api.get('/api/scan/status', { params: jobId ? { job_id: jobId } : {} })
        .then(r => r.data)

export const fetchScanHistory = () =>
    api.get('/api/scan/history').then(r => r.data)

// ── Baseline ──────────────────────────────────────────────────────────────────
export const fetchBaselines = () =>
    api.get('/api/baseline').then(r => r.data)

export const createBaseline = (params = {}) =>
    api.post('/api/baseline', null, { params: { name: 'default', ...params } })
        .then(r => r.data)

export const fetchDiff = (params = {}) =>
    api.get('/api/baseline/diff', { params }).then(r => r.data)

export const deleteBaseline = (id) =>
    api.delete(`/api/baseline/${id}`).then(r => r.data)

// ── Signatures ────────────────────────────────────────────────────────────────
export const fetchSignatures = (params = {}) =>
    api.get('/api/signatures', { params }).then(r => r.data)
// params: { unsigned_only: bool, exe_only: bool, severity: 'all'|'critical'|'high' }

export const runSignatures = () =>
    api.post('/api/signatures/run').then(r => r.data)

export const fetchSignatureIOCs = () =>
    api.get('/api/signatures/iocs').then(r => r.data)

// ── Scores ────────────────────────────────────────────────────────────────────

// Single entry — used in detail panels for breakdown + APT data
export const fetchScore = (type, id) =>
    api.get(`/api/scores/${type}/${id}`).then(r => r.data)

// All scores in one request — returns a Map keyed "type/id" for O(1) lookups
// e.g. scoresMap.get("registry/3") -> { score: 40, ... }
export const fetchAllScores = () =>
    api.get('/api/scores').then(r => {
        const map = new Map()
        for (const s of (r.data?.scores || [])) {
            map.set(`${s.entry_type}/${s.entry_id}`, s)
        }
        return map
    })

export const runScorer = () =>
    api.post('/api/scores/run').then(r => r.data)

// ── Export ────────────────────────────────────────────────────────────────────
export const exportMitre = () =>
    api.get('/api/export/mitre').then(r => r.data)

// ── Score helpers (single source of truth for UI classification) ──────────────

/**
 * Convert a numeric threat score to a severity tier.
 * This replaces the collector's static severity field everywhere in the UI.
 */
export function scoreToSeverity(score) {
    if (score == null) return null
    if (score >= 80) return 'critical'
    if (score >= 60) return 'high'
    if (score >= 35) return 'medium'
    return 'low'
}

export const SCORE_LABEL = {
    critical: 'CRITICAL',
    high: 'HIGH',
    medium: 'SUSPICIOUS',
    low: 'LOW RISK',
}

export const SCORE_COLOR = {
    critical: '#ff2055',
    high: '#ff7722',
    medium: '#ffd60a',
    low: '#00e676',
}