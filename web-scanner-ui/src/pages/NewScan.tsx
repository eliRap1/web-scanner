import { useState } from "react"

// Mock API for demonstration
const API_BASE = "http://localhost:8000"

export default function NewScan() {
  const [url, setUrl] = useState("")
  const [maxPages, setMaxPages] = useState(10)
  const [targetLoginUrl, setTargetLoginUrl] = useState("")
  const [targetUsername, setTargetUsername] = useState("")
  const [targetPassword, setTargetPassword] = useState("")
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState("")
  const [jobId, setJobId] = useState("")
  const [statusMessage, setStatusMessage] = useState("")
  const [progress, setProgress] = useState<any>(null)
  const [logs, setLogs] = useState<any[]>([])
  const [showLogs, setShowLogs] = useState(false)

  async function startScan() {
    if (!url) {
      setError("Please enter a URL")
      return
    }

    setLoading(true)
    setError("")
    setResult(null)
    setStatusMessage("Initializing scan...")
    setLogs([])
    setShowLogs(false)

    try {
      const token = localStorage.getItem("token")
      const params = new URLSearchParams({
        url: url,
        max_pages: maxPages.toString(),
        target_login_url: targetLoginUrl,
        target_username: targetUsername,
        target_password: targetPassword
      })

      const res = await fetch(`${API_BASE}/scan?${params}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` }
      })

      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.detail || "Scan failed")
      }

      const data = await res.json()
      setJobId(data.job_id)
      setStatusMessage(data.message || "Scan started")

      pollForResult(data.job_id)
    } catch (e: any) {
      setError(e.message)
      setLoading(false)
    }
  }

  function pollForResult(id: string) {
    const token = localStorage.getItem("token")

    const interval = setInterval(async () => {
      try {
        // ✅ FIX: Declare 'p' in outer scope
        let p: any = null

        // 1. Check Progress
        const progressRes = await fetch(`${API_BASE}/scan/${id}/progress`, {
          headers: { Authorization: `Bearer ${token}` }
        })

        if (progressRes.ok) {
          p = await progressRes.json()
          setProgress(p)
          setStatusMessage(`Scanning ${p.visited_count}/${maxPages}`)
        }

        // 2. ✅ NOW CHECK IF COMPLETED (p is defined!)
        if (p && p.status === "completed") {
          clearInterval(interval)
          await fetchFinalResults(id)
          return // Exit early
        }

        // 3. Fetch logs only if user toggled view
        if (showLogs) {
          const logsRes = await fetch(`${API_BASE}/scan/${id}/logs`, {
            headers: { Authorization: `Bearer ${token}` }
          })
          if (logsRes.ok) {
            const logData = await logsRes.json()
            setLogs(logData)
          }
        }

      } catch (e) {
        console.error("Polling error:", e)
      }
    }, 3000)
  }

  async function fetchFinalResults(id: string) {
    const token = localStorage.getItem("token")
    const res = await fetch(`${API_BASE}/scan/${id}`, {
      headers: { Authorization: `Bearer ${token}` }
    })
    const data = await res.json()
    setResult(data)
    setLoading(false)
    setStatusMessage("Completed")
    setJobId("")
    setProgress(null)
    setShowLogs(false)
  }

  async function fetchLogs(jobId: string) {
    const token = localStorage.getItem("token")
    try {
      const res = await fetch(`${API_BASE}/scan/${jobId}/logs`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (res.ok) {
        const data = await res.json()
        setLogs(data)
      } else {
        alert("Failed to load logs")
      }
    } catch (e) {
      console.error("Error loading logs:", e)
    }
  }

  return (
    <div style={{ padding: "20px", fontFamily: "system-ui, sans-serif" }}>
      <h1>New Scan</h1>

      <div style={{ maxWidth: 520, padding: "20px", border: "1px solid #ddd", borderRadius: "8px", marginBottom: "20px" }}>
        <div style={{ marginBottom: "15px" }}>
          <label style={{ display: "block", marginBottom: "5px", fontWeight: "bold" }}>Target URL</label>
          <input
            placeholder="https://example.com"
            value={url}
            onChange={e => setUrl(e.target.value)}
            style={{ width: "100%", padding: "8px", borderRadius: "4px", border: "1px solid #ccc" }}
          />
        </div>

        <div style={{ marginBottom: "15px" }}>
          <label style={{ display: "block", marginBottom: "5px", fontWeight: "bold" }}>Max Pages</label>
          <input
            type="number"
            min={1}
            max={100}
            value={maxPages}
            onChange={e => setMaxPages(Number(e.target.value))}
            style={{ width: "100%", padding: "8px", borderRadius: "4px", border: "1px solid #ccc" }}
          />
        </div>

        <button 
          onClick={startScan} 
          disabled={loading} 
          style={{ 
            width: "100%", 
            padding: "10px", 
            background: loading ? "#ccc" : "#007bff", 
            color: "white", 
            border: "none", 
            borderRadius: "4px",
            cursor: loading ? "not-allowed" : "pointer",
            fontWeight: "bold"
          }}
        >
          {loading ? "Scanning..." : "Start Scan"}
        </button>
      </div>

      <div style={{ maxWidth: 520, padding: "20px", border: "1px solid #ddd", borderRadius: "8px", marginBottom: "20px" }}>
        <h3 style={{ marginTop: 0 }}>Target Login (Optional)</h3>

        <input
          placeholder="Login URL"
          value={targetLoginUrl}
          onChange={e => setTargetLoginUrl(e.target.value)}
          style={{ width: "100%", padding: "8px", marginBottom: "10px", borderRadius: "4px", border: "1px solid #ccc" }}
        />

        <input
          placeholder="Username"
          value={targetUsername}
          onChange={e => setTargetUsername(e.target.value)}
          style={{ width: "100%", padding: "8px", marginBottom: "10px", borderRadius: "4px", border: "1px solid #ccc" }}
        />

        <input
          type="password"
          placeholder="Password"
          value={targetPassword}
          onChange={e => setTargetPassword(e.target.value)}
          style={{ width: "100%", padding: "8px", borderRadius: "4px", border: "1px solid #ccc" }}
        />
      </div>

      {error && <p style={{ color: "red", fontWeight: "bold" }}>{error}</p>}

      {jobId && (
        <div style={{ marginTop: "20px", padding: "15px", background: "#f8f9fa", borderRadius: "8px", border: "1px solid #dee2e6" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <strong>Status:</strong> {statusMessage}

            {progress && !result && (
              <button 
                onClick={() => {
                  setShowLogs(!showLogs)
                  if (!showLogs && jobId) {
                    fetchLogs(jobId)
                  }
                }}
                style={{ padding: "5px 10px", background: "#6c757d", color: "white", border: "none", borderRadius: "3px", cursor: "pointer", fontSize: "12px" }}
              >
                {showLogs ? "Hide Logs" : "View Logs"}
              </button>
            )}
          </div>

          {progress && (
            <div style={{ marginTop: "15px", borderTop: "1px solid #ddd", paddingTop: "15px" }}>
              <p style={{ margin: "5px 0", fontSize: "12px", color: "#666" }}>Job ID: {jobId}</p>
              <p><strong>Current URL:</strong> <span style={{ fontFamily: "monospace", background: "#fff", padding: "2px 6px", borderRadius: "3px" }}>{progress.current_url}</span></p>
              <p><strong>Visited:</strong> {progress.visited_count}</p>
              <p><strong>Targets Found:</strong> {progress.found_count}</p>

              <div style={{ background: "#ddd", height: "10px", borderRadius: "5px", overflow: "hidden" }}>
                <div
                  style={{
                    width: `${Math.min((progress.visited_count / maxPages) * 100, 100)}%`,
                    background: "#007bff",
                    height: "100%",
                    transition: "width 0.3s ease"
                  }}
                />
              </div>
            </div>
          )}
        </div>
      )}

      {result && (
        <div style={{ marginTop: "30px" }}>
          <h2 style={{ borderBottom: "2px solid #007bff", paddingBottom: "10px", color: "#007bff", marginBottom: "20px" }}>
            🎯 Scan Results
          </h2>
          
          {/* Check if it's an error response */}
          {result.error ? (
            <div style={{ 
              background: "#fff3cd", 
              border: "2px solid #ffc107", 
              borderRadius: "8px", 
              padding: "20px",
              color: "#856404"
            }}>
              <h3 style={{ marginTop: 0, display: "flex", alignItems: "center", gap: "10px" }}>
                <span style={{ fontSize: "24px" }}>⚠️</span>
                Scan Failed
              </h3>
              <p style={{ margin: "10px 0", fontSize: "14px", lineHeight: "1.6" }}>
                <strong>Error:</strong> {result.error}
              </p>
            </div>
          ) : (
            <>
              {/* Summary Card */}
              <div style={{ 
                background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
                borderRadius: "12px",
                padding: "25px",
                color: "white",
                marginBottom: "25px",
                boxShadow: "0 4px 15px rgba(0,0,0,0.1)"
              }}>
                <h3 style={{ margin: "0 0 15px 0", fontSize: "18px", display: "flex", alignItems: "center", gap: "10px" }}>
                  <span>📊</span> Summary
                </h3>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "15px" }}>
                  <div>
                    <div style={{ fontSize: "32px", fontWeight: "bold" }}>{result.length || 0}</div>
                    <div style={{ fontSize: "14px", opacity: 0.9 }}>Total Targets Found</div>
                  </div>
                  <div>
                    <div style={{ fontSize: "32px", fontWeight: "bold" }}>
                      {result.filter((t: any) => t.context === "form").length}
                    </div>
                    <div style={{ fontSize: "14px", opacity: 0.9 }}>Forms Discovered</div>
                  </div>
                  <div>
                    <div style={{ fontSize: "32px", fontWeight: "bold" }}>
                      {result.filter((t: any) => t.context === "url").length}
                    </div>
                    <div style={{ fontSize: "14px", opacity: 0.9 }}>URL Parameters</div>
                  </div>
                </div>
              </div>

              {/* Targets List */}
              <div style={{ 
                background: "white",
                borderRadius: "12px",
                border: "1px solid #e1e8ed",
                overflow: "hidden",
                boxShadow: "0 2px 8px rgba(0,0,0,0.05)"
              }}>
                <div style={{ 
                  padding: "20px", 
                  background: "#f8f9fa", 
                  borderBottom: "1px solid #e1e8ed",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center"
                }}>
                  <h3 style={{ margin: 0, fontSize: "16px", color: "#333" }}>
                    🎯 Attack Surface Details
                  </h3>
                  <span style={{ 
                    fontSize: "12px", 
                    color: "#666",
                    background: "white",
                    padding: "4px 12px",
                    borderRadius: "20px",
                    border: "1px solid #ddd"
                  }}>
                    {result.length} items
                  </span>
                </div>

                <div style={{ maxHeight: "600px", overflowY: "auto" }}>
                  {result.map((target: any, index: number) => (
                    <div 
                      key={index}
                      style={{ 
                        padding: "20px",
                        borderBottom: index < result.length - 1 ? "1px solid #f0f0f0" : "none",
                        transition: "background 0.2s",
                        cursor: "pointer",
                        background: index % 2 === 0 ? "#fafbfc" : "white"
                      }}
                      onMouseEnter={(e) => e.currentTarget.style.background = "#f0f7ff"}
                      onMouseLeave={(e) => e.currentTarget.style.background = index % 2 === 0 ? "#fafbfc" : "white"}
                    >
                      {/* Header Row */}
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                        <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                          <span style={{ 
                            background: target.method === "GET" ? "#28a745" : target.method === "POST" ? "#007bff" : "#6c757d",
                            color: "white",
                            padding: "4px 10px",
                            borderRadius: "4px",
                            fontSize: "11px",
                            fontWeight: "bold",
                            fontFamily: "monospace"
                          }}>
                            {target.method}
                          </span>
                          <span style={{ 
                            background: target.context === "form" ? "#ffc107" : "#17a2b8",
                            color: target.context === "form" ? "#333" : "white",
                            padding: "4px 10px",
                            borderRadius: "4px",
                            fontSize: "11px",
                            fontWeight: "bold"
                          }}>
                            {target.context === "form" ? "📝 FORM" : "🔗 URL"}
                          </span>
                        </div>
                        <span style={{ fontSize: "12px", color: "#999" }}>#{index + 1}</span>
                      </div>

                      {/* URL */}
                      <div style={{ marginBottom: "12px" }}>
                        <div style={{ fontSize: "11px", color: "#666", marginBottom: "4px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                          Target URL
                        </div>
                        <a 
                          href={target.url} 
                          target="_blank" 
                          rel="noreferrer"
                          style={{ 
                            color: "#007bff",
                            textDecoration: "none",
                            fontSize: "13px",
                            fontFamily: "monospace",
                            wordBreak: "break-all",
                            display: "block",
                            padding: "8px 12px",
                            background: "#f8f9fa",
                            borderRadius: "4px",
                            border: "1px solid #e1e8ed"
                          }}
                          onMouseEnter={(e) => e.currentTarget.style.background = "#e7f3ff"}
                          onMouseLeave={(e) => e.currentTarget.style.background = "#f8f9fa"}
                        >
                          {target.url}
                        </a>
                      </div>

                      {/* Parameters */}
                      <div>
                        <div style={{ fontSize: "11px", color: "#666", marginBottom: "6px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                          Parameters ({target.parameters.length})
                        </div>
                        {target.parameters.length > 0 ? (
                          <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                            {target.parameters.map((param: string, i: number) => (
                              <span 
                                key={i}
                                style={{ 
                                  background: "#e7f3ff",
                                  color: "#0066cc",
                                  padding: "4px 10px",
                                  borderRadius: "4px",
                                  fontSize: "12px",
                                  fontFamily: "monospace",
                                  border: "1px solid #cce5ff"
                                }}
                              >
                                {param}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span style={{ fontSize: "13px", color: "#999", fontStyle: "italic" }}>
                            No parameters
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Raw JSON Toggle */}
              <details style={{ marginTop: "20px" }}>
                <summary style={{ 
                  cursor: "pointer", 
                  padding: "12px 16px",
                  background: "#f8f9fa",
                  borderRadius: "6px",
                  border: "1px solid #dee2e6",
                  fontSize: "14px",
                  fontWeight: "600",
                  color: "#495057",
                  userSelect: "none"
                }}>
                  🔍 View Raw JSON Data
                </summary>
                <pre style={{ 
                  marginTop: "10px",
                  overflowX: "auto", 
                  background: "#2d2d2d", 
                  color: "#f8f8f2",
                  padding: "20px", 
                  borderRadius: "8px", 
                  fontSize: "13px", 
                  fontFamily: "monospace",
                  lineHeight: "1.6",
                  border: "1px solid #444"
                }}>
                  {JSON.stringify(result, null, 2)}
                </pre>
              </details>
            </>
          )}
        </div>
      )}
    </div>
  )
}