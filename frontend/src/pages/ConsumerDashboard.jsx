import { useState, useEffect, useCallback } from "react";
import axios from "axios";

const API = "http://127.0.0.1:8000";

// ---------------------------------------------------------------------------
// Theme tokens — dark navy + cyan
// ---------------------------------------------------------------------------
const T = {
  bg:          "#0f1117",
  surface:     "#1a1f2e",
  surfaceHigh: "#232a3d",
  border:      "#2a3352",
  cyan:        "#06b6d4",
  cyanDim:     "#0e7490",
  green:       "#22c55e",
  amber:       "#f59e0b",
  red:         "#ef4444",
  textPrimary: "#f1f5f9",
  textSub:     "#94a3b8",
  textDim:     "#475569",
};

// ---------------------------------------------------------------------------
// Shield SVG — color changes with status
// ---------------------------------------------------------------------------
function Shield({ color, size = 72, pulse = false }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      style={{
        filter: pulse
          ? `drop-shadow(0 0 12px ${color}88)`
          : `drop-shadow(0 0 6px ${color}44)`,
        animation: pulse ? "pulse 1.5s ease-in-out infinite" : "none",
      }}
    >
      <polygon
        points="50,5 95,20 95,58 50,97 5,58 5,20"
        fill={color}
        fillOpacity="0.15"
        stroke={color}
        strokeWidth="3"
        strokeLinejoin="round"
      />
      <polygon
        points="50,18 82,29 82,55 50,82 18,55 18,29"
        fill={color}
        fillOpacity="0.25"
      />
      {/* checkmark or X based on color */}
      {color === T.green && (
        <polyline
          points="34,50 45,62 66,38"
          fill="none"
          stroke={color}
          strokeWidth="5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      )}
      {color === T.red && (
        <>
          <line x1="38" y1="38" x2="62" y2="62" stroke={color} strokeWidth="5" strokeLinecap="round" />
          <line x1="62" y1="38" x2="38" y2="62" stroke={color} strokeWidth="5" strokeLinecap="round" />
        </>
      )}
      {color === T.amber && (
        <>
          <line x1="50" y1="36" x2="50" y2="56" stroke={color} strokeWidth="5" strokeLinecap="round" />
          <circle cx="50" cy="64" r="3" fill={color} />
        </>
      )}
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Stat card
// ---------------------------------------------------------------------------
function StatCard({ label, value, sub, accent }) {
  return (
    <div style={{
      background:   T.surface,
      border:       `1px solid ${T.border}`,
      borderRadius: 12,
      padding:      "20px 24px",
      minWidth:     140,
      flex:         1,
    }}>
      <div style={{ fontSize: 28, fontWeight: 700, color: accent || T.textPrimary }}>
        {value}
      </div>
      <div style={{ fontSize: 13, color: T.textPrimary, marginTop: 2 }}>{label}</div>
      {sub && <div style={{ fontSize: 12, color: T.textDim, marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Alert card (consumer-facing, plain English)
// ---------------------------------------------------------------------------
function AlertCard({ alert, onBlock, onTrust }) {
  const [expanded, setExpanded] = useState(false);

  const borderColor = {
    critical: T.red,
    high:     T.amber,
    medium:   T.cyan,
    low:      T.border,
  }[alert.severity] || T.border;

  const badgeStyle = {
    background: {
      critical: `${T.red}22`,
      high:     `${T.amber}22`,
      medium:   `${T.cyan}22`,
      low:      `${T.border}44`,
    }[alert.severity],
    color: {
      critical: T.red,
      high:     T.amber,
      medium:   T.cyan,
      low:      T.textDim,
    }[alert.severity],
    padding:      "3px 10px",
    borderRadius: 20,
    fontSize:     11,
    fontWeight:   600,
    letterSpacing: "0.05em",
    textTransform: "uppercase",
  };

  return (
    <div style={{
      background:   T.surface,
      border:       `1px solid ${borderColor}`,
      borderLeft:   `3px solid ${borderColor}`,
      borderRadius: 10,
      padding:      "16px 20px",
      marginBottom: 10,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
            <span style={badgeStyle}>{alert.severity_label || alert.severity}</span>
            <span style={{ fontSize: 13, color: T.textDim }}>{alert.entry_type}</span>
          </div>
          <div style={{ fontSize: 15, fontWeight: 600, color: T.textPrimary, marginBottom: 4 }}>
            {alert.title}
          </div>
          <div style={{ fontSize: 13, color: T.textSub }}>
            {alert.what_it_is}
          </div>

          {expanded && alert.plain_reasons?.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <div style={{ fontSize: 12, color: T.textDim, marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em" }}>
                Why this is suspicious
              </div>
              {alert.plain_reasons.map((r, i) => (
                <div key={i} style={{
                  display:      "flex",
                  alignItems:   "flex-start",
                  gap:          8,
                  marginBottom: 5,
                  fontSize:     13,
                  color:        T.textSub,
                }}>
                  <span style={{ color: T.amber, marginTop: 1 }}>›</span>
                  {r}
                </div>
              ))}
              <div style={{
                marginTop:    12,
                padding:      "10px 14px",
                background:   T.surfaceHigh,
                borderRadius: 8,
                fontSize:     13,
                color:        T.textPrimary,
              }}>
                {alert.recommendation}
              </div>
            </div>
          )}
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 8, minWidth: 110 }}>
          <button
            onClick={() => onBlock(alert)}
            style={{
              background:   alert.severity === "critical" ? T.red : T.cyan,
              color:        "#fff",
              border:       "none",
              borderRadius: 8,
              padding:      "9px 18px",
              fontSize:     13,
              fontWeight:   600,
              cursor:       "pointer",
              width:        "100%",
            }}
          >
            {alert.action_primary || "Block"}
          </button>
          <button
            onClick={() => setExpanded(e => !e)}
            style={{
              background:   "transparent",
              color:        T.textSub,
              border:       `1px solid ${T.border}`,
              borderRadius: 8,
              padding:      "8px 18px",
              fontSize:     13,
              cursor:       "pointer",
              width:        "100%",
            }}
          >
            {expanded ? "Less" : "Details"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Hero zone — the big status area at the top
// ---------------------------------------------------------------------------
function HeroZone({ status, summary, scanning, onScan }) {
  const config = {
    clean: {
      color:   T.green,
      label:   "You're Protected",
      sublabel: summary || "No threats detected",
      pulse:   false,
    },
    notice: {
      color:   T.cyan,
      label:   "Items to Review",
      sublabel: summary || "Some items worth reviewing",
      pulse:   false,
    },
    warning: {
      color:   T.amber,
      label:   "Attention Required",
      sublabel: summary || "Suspicious items found",
      pulse:   true,
    },
    danger: {
      color:   T.red,
      label:   "Threat Detected",
      sublabel: summary || "Immediate action required",
      pulse:   true,
    },
    error: {
      color:   T.textDim,
      label:   "Service Unavailable",
      sublabel: "Persistence Hunter service is not running",
      pulse:   false,
    },
  }[status] || {
    color:   T.textDim,
    label:   "Connecting...",
    sublabel: "",
    pulse:   false,
  };

  return (
    <div style={{
      background:    `linear-gradient(135deg, ${T.surface} 0%, ${T.surfaceHigh} 100%)`,
      border:        `1px solid ${T.border}`,
      borderRadius:  16,
      padding:       "40px 32px",
      display:       "flex",
      alignItems:    "center",
      gap:           32,
      marginBottom:  24,
      position:      "relative",
      overflow:      "hidden",
    }}>
      {/* Background glow */}
      <div style={{
        position:   "absolute",
        top:        -60,
        right:      -60,
        width:      200,
        height:     200,
        background: `radial-gradient(circle, ${config.color}18 0%, transparent 70%)`,
        pointerEvents: "none",
      }} />

      <Shield color={config.color} size={80} pulse={config.pulse || scanning} />

      <div style={{ flex: 1 }}>
        <div style={{
          fontSize:   26,
          fontWeight: 700,
          color:      config.color,
          marginBottom: 6,
          letterSpacing: "-0.02em",
        }}>
          {scanning ? "Scanning..." : config.label}
        </div>
        <div style={{ fontSize: 14, color: T.textSub }}>
          {scanning ? "Checking all startup entries, scheduled tasks, and services" : config.sublabel}
        </div>
      </div>

      <button
        onClick={onScan}
        disabled={scanning}
        style={{
          background:   scanning ? T.surfaceHigh : T.cyan,
          color:        scanning ? T.textDim : "#fff",
          border:       "none",
          borderRadius: 10,
          padding:      "12px 28px",
          fontSize:     14,
          fontWeight:   600,
          cursor:       scanning ? "not-allowed" : "pointer",
          whiteSpace:   "nowrap",
          transition:   "background 0.2s",
        }}
      >
        {scanning ? "Scanning..." : "Scan Now"}
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main consumer dashboard
// ---------------------------------------------------------------------------
export default function ConsumerDashboard({ onSwitchToAnalyst }) {
  const [status,   setStatus]   = useState({ status: "clean", status_message: "", counts: {}, scanning: false });
  const [alerts,   setAlerts]   = useState([]);
  const [lastScan, setLastScan] = useState(null);
  const [loading,  setLoading]  = useState(true);
  const [rulesVer, setRulesVer] = useState("—");

  const fetchStatus = useCallback(async () => {
    try {
      const [s, a, info] = await Promise.all([
        axios.get(`${API}/api/status`),
        axios.get(`${API}/api/alerts`),
        axios.get(`${API}/api/stats`).catch(() => ({ data: {} })),
      ]);
      setStatus(s.data);
      setAlerts(a.data || []);
      if (info.data?.last_scan)   setLastScan(info.data.last_scan);
      if (info.data?.rules_version) setRulesVer(info.data.rules_version);
    } catch {
      setStatus(prev => ({ ...prev, status: "error" }));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const id = setInterval(fetchStatus, 10000);
    return () => clearInterval(id);
  }, [fetchStatus]);

  const handleScan = async () => {
    try {
      await axios.post(`${API}/api/scan`);
      setTimeout(fetchStatus, 1000);
    } catch {}
  };

  const handleBlock = async (alert) => {
    try {
      await axios.post(`${API}/api/entries/${alert.entry_type}/${alert.entry_name}/block`);
      fetchStatus();
    } catch {}
  };

  const counts = status.counts || {};
  const totalThreats = (counts.critical || 0) + (counts.high || 0) + (counts.medium || 0);

  const lastScanLabel = lastScan
    ? new Date(lastScan).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
    : "Never";

  if (loading) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", flex: 1, color: T.textDim, fontSize: 14 }}>
        Connecting to service...
      </div>
    );
  }

  return (
    <div style={{ flex: 1, overflowY: "auto", padding: "28px 32px" }}>
      {/* Hero */}
      <HeroZone
        status   = {status.status}
        summary  = {status.status_message}
        scanning = {status.scanning}
        onScan   = {handleScan}
      />

      {/* Stat cards */}
      <div style={{ display: "flex", gap: 14, marginBottom: 28 }}>
        <StatCard
          label  = "Threats Found"
          value  = {totalThreats}
          accent = {totalThreats > 0 ? T.red : T.green}
        />
        <StatCard
          label  = "Last Scan"
          value  = {lastScanLabel}
          sub    = "on-demand or scheduled"
          accent = {T.cyan}
        />
        <StatCard
          label  = "Real-time"
          value  = {status.status === "error" ? "Off" : "Active"}
          accent = {status.status === "error" ? T.textDim : T.green}
        />
        <StatCard
          label  = "Rules"
          value  = {rulesVer}
          sub    = "community + built-in"
          accent = {T.cyan}
        />
      </div>

      {/* Alerts */}
      {alerts.length > 0 && (
        <div>
          <div style={{
            fontSize:     12,
            fontWeight:   600,
            color:        T.textDim,
            textTransform:"uppercase",
            letterSpacing:"0.08em",
            marginBottom: 14,
          }}>
            Detections — {alerts.length} item{alerts.length !== 1 ? "s" : ""}
          </div>
          {alerts.map((alert, i) => (
            <AlertCard
              key     = {i}
              alert   = {alert}
              onBlock = {handleBlock}
              onTrust = {() => {}}
            />
          ))}
        </div>
      )}

      {alerts.length === 0 && !loading && (
        <div style={{
          textAlign: "center",
          color:     T.textDim,
          fontSize:  14,
          marginTop: 40,
        }}>
          No detections. Run a scan to check your system.
        </div>
      )}

      {/* Analyst mode hint — subtle, bottom right */}
      <div style={{ marginTop: 40, display: "flex", justifyContent: "flex-end" }}>
        <button
          onClick    = {onSwitchToAnalyst}
          title      = "Switch to Analyst Mode"
          style={{
            background:   "transparent",
            border:       "none",
            color:        T.textDim,
            fontSize:     12,
            cursor:       "pointer",
            padding:      "6px 10px",
            borderRadius: 6,
            fontFamily:   "monospace",
            letterSpacing:"0.05em",
          }}
        >
          {"</>"}
        </button>
      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.6; }
        }
      `}</style>
    </div>
  );
}
