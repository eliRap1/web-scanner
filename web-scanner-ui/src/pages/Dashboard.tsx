import { useState, useEffect } from "react"
import { API_BASE } from "../api/client"

interface ScanSummary {
  total: number
  active: number
  completed: number
  failed: number
}

interface RecentScan {
  scan_id: number
  target_url: string
  status: string
  start_time: string
  findings_count: number
}

export default function Dashboard() {
  const [stats, setStats] = useState<ScanSummary>({ total: 0, active: 0, completed: 0, failed: 0 })
  const [recentScans, setRecentScans] = useState<RecentScan[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchDashboardData()
  }, [])

  async function fetchDashboardData() {
    const token = localStorage.getItem("token")
    try {
      // Fetch scan stats - you may need to create this endpoint
      // For now using placeholder data
      setStats({
        total: 12,
        active: 1,
        completed: 10,
        failed: 1
      })

      // Fetch recent scans
      const res = await fetch(`${API_BASE}/scans`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      
      if (res.ok) {
        const data = await res.json()
        setRecentScans(data.slice(0, 5))
      }
    } catch (err) {
      console.error("Failed to fetch dashboard data:", err)
    } finally {
      setLoading(false)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed": return "var(--accent-success)"
      case "running": return "var(--accent-primary)"
      case "failed": return "var(--accent-danger)"
      default: return "var(--text-muted)"
    }
  }

  return (
    <div>
      <h1 className="page-title">📊 Dashboard</h1>

      {/* Stats Grid */}
      <div className="grid" style={{ marginBottom: "40px" }}>
        <div className="stat-card">
          <h3>Total Scans</h3>
          <div className="value">{stats.total}</div>
        </div>
        
        <div className="stat-card info">
          <h3>Active Scans</h3>
          <div className="value">{stats.active}</div>
        </div>
        
        <div className="stat-card success">
          <h3>Completed</h3>
          <div className="value">{stats.completed}</div>
        </div>
        
        <div className="stat-card danger">
          <h3>Failed</h3>
          <div className="value">{stats.failed}</div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="scan-section" style={{ marginBottom: "40px" }}>
        <h3>⚡ Quick Actions</h3>
        <div style={{ display: "flex", gap: "16px", flexWrap: "wrap" }}>
          <a href="/scan" className="btn btn-primary" style={{ textDecoration: "none" }}>
            🔍 New Scan
          </a>
          <button className="btn btn-secondary">
            📄 View Reports
          </button>
          <button className="btn btn-secondary">
            ⚙️ Settings
          </button>
        </div>
      </div>

      {/* Recent Scans */}
      <div className="results-section">
        <div className="results-header">
          <h3>🕐 Recent Scans</h3>
          <a href="/scans" className="link" style={{ fontSize: "0.9rem" }}>View All →</a>
        </div>
        
        {loading ? (
          <div style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)" }}>
            Loading...
          </div>
        ) : recentScans.length === 0 ? (
          <div style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)" }}>
            <p>No scans yet.</p>
            <a href="/scan" className="btn btn-primary" style={{ display: "inline-block", marginTop: "16px", textDecoration: "none" }}>
              Start Your First Scan
            </a>
          </div>
        ) : (
          <div>
            {recentScans.map((scan, i) => (
              <div key={i} className="target-item">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <div style={{ fontWeight: 600, marginBottom: "4px" }}>{scan.target_url}</div>
                    <div className="text-muted" style={{ fontSize: "0.85rem" }}>
                      {scan.start_time ? new Date(scan.start_time).toLocaleString() : "Pending"}
                    </div>
                  </div>
                  <div style={{ textAlign: "right" }}>
                    <span 
                      className="status-badge"
                      style={{ 
                        background: `${getStatusColor(scan.status)}20`,
                        color: getStatusColor(scan.status)
                      }}
                    >
                      {scan.status}
                    </span>
                    {scan.findings_count > 0 && (
                      <div className="text-danger" style={{ marginTop: "4px", fontSize: "0.85rem" }}>
                        {scan.findings_count} findings
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}