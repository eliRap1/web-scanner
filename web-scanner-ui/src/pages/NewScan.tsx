import { useState } from "react"
import { API_BASE } from "../api/client"

export default function NewScan() {
  const [url, setUrl] = useState("")
  const [maxPages, setMaxPages] = useState(10)
  
  // New State for Target Authentication
  const [targetLoginUrl, setTargetLoginUrl] = useState("")
  const [targetUsername, setTargetUsername] = useState("")
  const [targetPassword, setTargetPassword] = useState("")

  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState("")

  async function startScan() {
    if (!url) {
      setError("Please enter a URL")
      return
    }

    setLoading(true)
    setError("")
    setResult(null)

    try {
      const token = localStorage.getItem("token")

      // Construct query parameters (handles encoding automatically)
      const params = new URLSearchParams({
        url: url,
        max_pages: maxPages.toString(),
        target_login_url: targetLoginUrl,
        target_username: targetUsername,
        target_password: targetPassword
      })

      const res = await fetch(
        `${API_BASE}/scan?${params.toString()}`,
        {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${token}`
          }
        }
      )

      if (!res.ok) {
        const errorData = await res.json()
        throw new Error(errorData.detail || "Scan failed")
      }

      const data = await res.json()
      setResult(data)
    } catch (e: any) {
      setError(e.message || "Error starting scan")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <h1>New Scan</h1>

      {/* Scan Configuration */}
      <div className="card" style={{ maxWidth: 500 }}>
        <div style={{ marginBottom: "15px" }}>
          <label style={{ display: "block", marginBottom: "5px", fontWeight: "bold" }}>Target URL</label>
          <input
            placeholder="https://example.com"
            value={url}
            onChange={e => setUrl(e.target.value)}
            style={{ width: "100%", padding: "8px" }}
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
            style={{ width: "100%", padding: "8px" }}
          />
        </div>

        <button onClick={startScan} disabled={loading} style={{ width: "100%", padding: "10px", background: "#007bff", color: "white", border: "none", cursor: "pointer" }}>
          {loading ? "Scanning..." : "Start Scan"}
        </button>
      </div>

      {/* Authentication Section */}
      <div className="card" style={{ maxWidth: 500, marginTop: "20px" }}>
        <h3 style={{ marginTop: 0 }}>Target Site Credentials (Optional)</h3>
        <p style={{ fontSize: "12px", color: "#666" }}>
          Fill this to scan protected areas (Admin panels, user profiles).
        </p>

        <div style={{ marginBottom: "10px" }}>
          <label style={{ display: "block", marginBottom: "5px" }}>Login Page URL</label>
          <input
            placeholder="https://example.com/login"
            value={targetLoginUrl}
            onChange={e => setTargetLoginUrl(e.target.value)}
            style={{ width: "100%", padding: "8px" }}
          />
        </div>

        <div style={{ marginBottom: "10px" }}>
          <label style={{ display: "block", marginBottom: "5px" }}>Username</label>
          <input
            placeholder="admin"
            value={targetUsername}
            onChange={e => setTargetUsername(e.target.value)}
            style={{ width: "100%", padding: "8px" }}
          />
        </div>

        <div style={{ marginBottom: "10px" }}>
          <label style={{ display: "block", marginBottom: "5px" }}>Password</label>
          <input
            type="password"
            placeholder="********"
            value={targetPassword}
            onChange={e => setTargetPassword(e.target.value)}
            style={{ width: "100%", padding: "8px" }}
          />
        </div>
      </div>

      {error && <p className="error" style={{ color: "red", marginTop: "10px" }}>{error}</p>}

            {result && (
        <div style={{ marginTop: 30 }}>
          <h2>Scan Results</h2>

          {/* UPDATE: Added 'color: "black"' to make text visible */}
          <pre 
            className="card" 
            style={{ 
                overflowX: "auto", 
                background: "#f4f4f4", // Light grey background
                padding: "10px",
                color: "black"         // THIS MAKES TEXT VISIBLE
            }}
          >
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}