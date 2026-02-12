import { useState, useEffect, useRef } from "react"
import { API_BASE } from "../api/client"

interface ScanTarget {
  url: string
  method: string
  parameters: string[]
  context: string
}

interface Finding {
  type: string
  name?: string
  url: string
  method?: string
  param: string
  payload: string
  severity: string
  confidence?: number
  evidence?: string
}

interface ProgressData {
  phase?: string
  current_url?: string
  visited_count?: number
  found_count?: number
  testing_target?: number
  total_targets?: number
  status?: string
  findings_count?: number
}

export default function NewScan() {
  const [url, setUrl] = useState("")
  const [maxPages, setMaxPages] = useState(10)
  const [targetLoginUrl, setTargetLoginUrl] = useState("")
  const [targetUsername, setTargetUsername] = useState("")
  const [targetPassword, setTargetPassword] = useState("")
  const [proxy, setProxy] = useState("")  // e.g., "http://127.0.0.1:8080" for Burp

  const [jobId, setJobId] = useState<string | null>(null)
  const [progress, setProgress] = useState<ProgressData | null>(null)
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  
  const [showLogs, setShowLogs] = useState(false)
  const [logs, setLogs] = useState<any[]>([])
  
  const intervalRef = useRef<NodeJS.Timeout | null>(null)

  async function startScan() {
    if (!url) {
      setError("Please enter a URL to scan")
      return
    }
    
    setError("")
    setLoading(true)
    setResult(null)
    setProgress(null)
    setLogs([])

    try {
      const token = localStorage.getItem("token")
      const params = new URLSearchParams({
        url,
        max_pages: String(maxPages),
        target_login_url: targetLoginUrl,
        target_username: targetUsername,
        target_password: targetPassword,
        ...(proxy && { proxy })  // Only include if set
      })

      const res = await fetch(`${API_BASE}/scan/?${params}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` }
      })

      const data = await res.json()

      if (data.job_id) {
        setJobId(data.job_id)
        pollForResult(data.job_id)
      } else {
        setError(data.detail || "Failed to start scan")
        setLoading(false)
      }
    } catch (err) {
      setError("Network error")
      setLoading(false)
    }
  }

  function pollForResult(id: string) {
    const token = localStorage.getItem("token")
    
    intervalRef.current = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/scan/${id}/progress`, {
          headers: { Authorization: `Bearer ${token}` }
        })
        const p = await res.json()
        setProgress(p)

        if (p && p.status === "completed") {
          clearInterval(intervalRef.current!)
          intervalRef.current = null
          setResult(p.result || p)
          setLoading(false)
        }

        if (p && p.status === "failed") {
          clearInterval(intervalRef.current!)
          intervalRef.current = null
          setResult({ error: p.last_error || "Scan failed" })
          setLoading(false)
        }
      } catch (err) {
        console.error("Polling error:", err)
      }
    }, 2000)
  }

  async function fetchLogs(id: string) {
    const token = localStorage.getItem("token")
    try {
      const res = await fetch(`${API_BASE}/scan/${id}/logs`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      const data = await res.json()
      setLogs(data || [])
    } catch (err) {
      console.error("Failed to fetch logs:", err)
    }
  }

  function cancelScan() {
    if (intervalRef.current) {
      clearInterval(intervalRef.current)
      intervalRef.current = null
    }
    setLoading(false)
    setProgress(null)
    setJobId(null)
  }

  useEffect(() => {
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
      }
    }
  }, [])

  const getProgressPercent = () => {
    if (!progress) return 0
    if (progress.phase === "crawling") {
      return Math.min((progress.visited_count || 0) / maxPages * 50, 50)
    }
    if (progress.phase === "testing" && progress.total_targets) {
      return 50 + ((progress.testing_target || 0) / progress.total_targets * 50)
    }
    if (progress.status === "completed") return 100
    return 0
  }

  return (
    <div className="scan-container">
      <h1 className="page-title">🔍 New Security Scan</h1>

      {/* Main Scan Config */}
      <div className="scan-section">
        <h3>🎯 Target Configuration</h3>
        
        <div className="form-group">
          <label>Target URL</label>
          <input
            type="url"
            className="form-input"
            placeholder="https://example.com"
            value={url}
            onChange={e => setUrl(e.target.value)}
          />
        </div>

        <div className="form-group">
          <label>Max Pages to Crawl</label>
          <input
            type="number"
            className="form-input"
            min={1}
            max={500}
            value={maxPages}
            onChange={e => setMaxPages(Number(e.target.value))}
          />
        </div>

        <button 
          className="btn btn-primary" 
          onClick={startScan}
          disabled={loading || !url}
          style={{ width: "100%" }}
        >
          {loading ? "⏳ Scanning..." : "🚀 Start Scan"}
        </button>
      </div>

      {/* Optional: Target Login */}
      <div className="scan-section">
        <h3>🔐 Target Authentication <span className="optional">(Optional)</span></h3>
        <p className="text-muted mb-2" style={{ fontSize: "0.9rem" }}>
          If the target requires login, provide credentials to scan authenticated areas.
        </p>

        <div className="form-group">
          <label>Login Page URL</label>
          <input
            className="form-input"
            placeholder="https://example.com/login"
            value={targetLoginUrl}
            onChange={e => setTargetLoginUrl(e.target.value)}
          />
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
          <div className="form-group">
            <label>Username</label>
            <input
              className="form-input"
              placeholder="username"
              value={targetUsername}
              onChange={e => setTargetUsername(e.target.value)}
            />
          </div>

          <div className="form-group">
            <label>Password</label>
            <input
              type="password"
              className="form-input"
              placeholder="••••••••"
              value={targetPassword}
              onChange={e => setTargetPassword(e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* Proxy Configuration */}
      <div className="scan-section">
        <h3>🔧 Proxy Integration <span className="optional">(Optional)</span></h3>
        <p className="text-muted mb-2" style={{ fontSize: "0.9rem" }}>
          Route all scanner traffic through a proxy like Burp Suite or OWASP ZAP to inspect requests.
        </p>

        <div className="form-group">
          <label>Proxy URL</label>
          <input
            className="form-input"
            placeholder="http://127.0.0.1:8080"
            value={proxy}
            onChange={e => setProxy(e.target.value)}
          />
          <div style={{ marginTop: "8px", fontSize: "0.85rem", color: "var(--text-muted)" }}>
            <strong>Common proxies:</strong>
            <div style={{ display: "flex", gap: "12px", marginTop: "4px" }}>
              <button
                type="button"
                onClick={() => setProxy("http://127.0.0.1:8080")}
                style={{
                  background: "var(--bg-tertiary)",
                  border: "1px solid var(--border-color)",
                  borderRadius: "4px",
                  padding: "4px 8px",
                  cursor: "pointer",
                  fontSize: "0.8rem"
                }}
              >
                Burp Suite (8080)
              </button>
              <button
                type="button"
                onClick={() => setProxy("http://127.0.0.1:8081")}
                style={{
                  background: "var(--bg-tertiary)",
                  border: "1px solid var(--border-color)",
                  borderRadius: "4px",
                  padding: "4px 8px",
                  cursor: "pointer",
                  fontSize: "0.8rem"
                }}
              >
                OWASP ZAP (8081)
              </button>
              {proxy && (
                <button
                  type="button"
                  onClick={() => setProxy("")}
                  style={{
                    background: "var(--accent-danger)",
                    color: "white",
                    border: "none",
                    borderRadius: "4px",
                    padding: "4px 8px",
                    cursor: "pointer",
                    fontSize: "0.8rem"
                  }}
                >
                  Clear
                </button>
              )}
            </div>
          </div>
        </div>

        {proxy && (
          <div style={{
            background: "rgba(34, 197, 94, 0.1)",
            border: "1px solid rgba(34, 197, 94, 0.3)",
            borderRadius: "8px",
            padding: "12px",
            marginTop: "12px",
            fontSize: "0.85rem"
          }}>
            <strong style={{ color: "#22c55e" }}>✓ Proxy enabled:</strong> {proxy}
            <div style={{ marginTop: "4px", color: "var(--text-muted)" }}>
              All scanner traffic will be routed through this proxy. Make sure your proxy is running!
            </div>
          </div>
        )}
      </div>

      {/* Error Display */}
      {error && (
        <div className="error" style={{ marginBottom: "20px" }}>
          ❌ {error}
        </div>
      )}

      {/* Progress Section */}
      {jobId && loading && (
        <div className="progress-section">
          <div className="progress-header">
            <div className="progress-status">
              <span className={`status-badge ${progress?.status || 'running'}`}>
                {progress?.phase === "crawling" ? "🕷️ Crawling" : 
                 progress?.phase === "testing" ? "🔬 Testing" : 
                 "⏳ Processing"}
              </span>
              {progress?.current_url && (
                <span className="text-muted" style={{ fontSize: "0.85rem", maxWidth: "400px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {progress.current_url}
                </span>
              )}
            </div>
            <button className="btn btn-secondary" onClick={cancelScan} style={{ padding: "8px 16px" }}>
              Cancel
            </button>
          </div>

          <div className="progress-bar-container">
            <div className="progress-bar" style={{ width: `${getProgressPercent()}%` }} />
          </div>

          <div className="progress-details">
            <div className="progress-stat">
              <div className="label">Pages Visited</div>
              <div className="value">{progress?.visited_count || 0}</div>
            </div>
            <div className="progress-stat">
              <div className="label">Targets Found</div>
              <div className="value">{progress?.found_count || 0}</div>
            </div>
            {progress?.phase === "testing" && (
              <div className="progress-stat">
                <div className="label">Testing Progress</div>
                <div className="value">{progress?.testing_target || 0}/{progress?.total_targets || 0}</div>
              </div>
            )}
            {proxy && (
              <div className="progress-stat">
                <div className="label">Proxy</div>
                <div className="value" style={{ color: "#22c55e", fontSize: "0.8rem" }}>✓ Active</div>
              </div>
            )}
          </div>

          {/* Logs Toggle */}
          <div style={{ marginTop: "20px" }}>
            <button 
              className="btn btn-secondary"
              onClick={() => {
                setShowLogs(!showLogs)
                if (!showLogs && jobId) fetchLogs(jobId)
              }}
              style={{ padding: "8px 16px", fontSize: "0.875rem" }}
            >
              {showLogs ? "Hide Logs" : "Show Logs"}
            </button>

            {showLogs && (
              <div className="logs-container mt-2">
                {logs.length === 0 ? (
                  <div className="log-entry info">No logs yet...</div>
                ) : (
                  logs.map((log, i) => (
                    <div key={i} className={`log-entry ${log.level}`}>
                      <span className="log-time">{new Date(log.created_at).toLocaleTimeString()}</span>
                      <span>{log.message}</span>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Results Section */}
      {result && (
        <div className="results-section">
          <div className="results-header">
            <h3>
              {result.error ? "❌ Scan Failed" : "✅ Scan Complete"}
            </h3>
            {result.stats && (
              <div style={{ display: "flex", gap: "20px", fontSize: "0.9rem" }}>
                <span>📄 {result.stats.pages_visited} pages</span>
                <span>🎯 {result.stats.targets_found} targets</span>
                <span className={result.stats.vulnerabilities_found > 0 ? "text-danger" : "text-success"}>
                  🐛 {result.stats.vulnerabilities_found} vulnerabilities
                </span>
              </div>
            )}
          </div>

          {result.error ? (
            <div style={{ padding: "24px", color: "var(--accent-danger)" }}>
              {result.error}
            </div>
          ) : (
            <>
              {/* Vulnerabilities */}
              {result.findings && result.findings.length > 0 && (
                <div style={{ borderBottom: "1px solid var(--border-color)" }}>
                  <div style={{ padding: "16px 24px", background: "rgba(239, 68, 68, 0.1)", borderBottom: "1px solid var(--border-color)" }}>
                    <strong style={{ color: "var(--accent-danger)" }}>
                      ⚠️ {result.findings.length} Vulnerabilities Found
                    </strong>
                  </div>
                  {result.findings.map((finding: Finding, i: number) => (
                    <div key={i} className="finding-item">
                      <div className="finding-header">
                        <span className="finding-type">{finding.type} - {finding.name || finding.param}</span>
                        <span className={`severity-badge ${finding.severity.toLowerCase()}`}>
                          {finding.severity}
                        </span>
                      </div>
                      <div className="finding-details">
                        <div><strong>URL:</strong> <code>{finding.url}</code></div>
                        <div><strong>Parameter:</strong> <code>{finding.param}</code></div>
                        <div><strong>Payload:</strong> <code>{finding.payload}</code></div>
                        {finding.evidence && (
                          <div><strong>Evidence:</strong> {finding.evidence}</div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Targets */}
              {result.targets && result.targets.length > 0 && (
                <div>
                  <div style={{ padding: "16px 24px", borderBottom: "1px solid var(--border-color)" }}>
                    <strong>📋 Discovered Targets ({result.targets.length})</strong>
                  </div>
                  {result.targets.map((target: ScanTarget, i: number) => (
                    <div key={i} className="target-item">
                      <div className="target-header">
                        <span className={`method-badge ${target.method.toLowerCase()}`}>
                          {target.method}
                        </span>
                        <span className={`context-badge ${target.context}`}>
                          {target.context === "form" ? "📝 Form" : "🔗 URL"}
                        </span>
                        <span className="text-muted" style={{ marginLeft: "auto", fontSize: "0.85rem" }}>
                          #{i + 1}
                        </span>
                      </div>
                      <div className="target-url">{target.url}</div>
                      <div className="target-params">
                        {target.parameters.map((param, j) => (
                          <span key={j} className="param-tag">{param}</span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {(!result.targets || result.targets.length === 0) && (!result.findings || result.findings.length === 0) && (
                <div style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)" }}>
                  No targets or vulnerabilities found. The site may be well-protected or the crawl was limited.
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}