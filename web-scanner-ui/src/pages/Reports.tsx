import { useState, useEffect } from "react"
import { API_BASE, getGraphData } from "../api/client"
import { Link } from "react-router-dom"
import VulnerabilityGraph from "../components/VulnerabilityGraph"

interface Report {
  report_id: number
  scan_id: number
  summary: string
  total_vulns: number
  created_at: string
  report_path: string | null
}

interface Scan {
  scan_id: number
  target_url: string
  status: string
  start_time: string
  findings_count: number
}

export default function Reports() {
  const [reports, setReports] = useState<Report[]>([])
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState<number | null>(null)
  const [error, setError] = useState("")
  const [success, setSuccess] = useState("")
  const [graphData, setGraphData] = useState<any>(null)
  const [graphScanId, setGraphScanId] = useState<number | null>(null)
  const [loadingGraph, setLoadingGraph] = useState(false)

  useEffect(() => {
    fetchData()
  }, [])

  async function fetchData() {
    const token = localStorage.getItem("token")
    if (!token) {
      setError("Not authenticated")
      setLoading(false)
      return
    }

    try {
      // Fetch reports and scans in parallel
      const [reportsRes, scansRes] = await Promise.all([
        fetch(`${API_BASE}/reports/`, {
          headers: { Authorization: `Bearer ${token}` }
        }),
        fetch(`${API_BASE}/scans`, {
          headers: { Authorization: `Bearer ${token}` }
        })
      ])

      if (reportsRes.ok) {
        const data = await reportsRes.json()
        setReports(data.reports || [])
      }

      if (scansRes.ok) {
        const data = await scansRes.json()
        // Only show completed scans
        setScans(data.filter((s: Scan) => s.status === "completed"))
      }
    } catch (err) {
      setError("Network error - is the server running?")
    } finally {
      setLoading(false)
    }
  }

  async function generateReport(scanId: number, format: string = "html") {
    const token = localStorage.getItem("token")
    setGenerating(scanId)
    setError("")
    setSuccess("")

    try {
      const res = await fetch(`${API_BASE}/reports/generate/${scanId}?format=${format}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` }
      })

      const data = await res.json()

      if (res.ok) {
        setSuccess(`${format.toUpperCase()} report generated successfully!`)
        await fetchData()

        // Auto-open the report in a new tab
        if (data.report_id) {
          // Use /view for HTML, /download for PDF/JSON
          const endpoint = format === "html" ? "view" : "download"
          const url = `${API_BASE}/reports/${endpoint}/${data.report_id}?token=${token}`
          window.open(url, "_blank")
        }
      } else {
        setError(data.detail || "Failed to generate report")
      }
    } catch (err) {
      setError("Network error while generating report")
    } finally {
      setGenerating(null)
    }
  }

  function downloadReport(reportId: number) {
    const token = localStorage.getItem("token")
    // Create a hidden link and click it to trigger download
    const url = `${API_BASE}/reports/download/${reportId}?token=${token}`
    window.open(url, "_blank")
  }

  function viewReport(reportId: number) {
    const token = localStorage.getItem("token")
    const url = `${API_BASE}/reports/view/${reportId}?token=${token}`
    window.open(url, "_blank")
  }

  async function loadGraphData(scanId: number) {
    if (graphScanId === scanId && graphData) {
      setGraphData(null)
      setGraphScanId(null)
      return
    }
    setLoadingGraph(true)
    try {
      const data = await getGraphData(String(scanId))
      if (data) {
        setGraphData(data)
        setGraphScanId(scanId)
      } else {
        setError("No graph analysis data available for this scan")
        setGraphData(null)
        setGraphScanId(null)
      }
    } catch {
      setError("Failed to load graph data")
    } finally {
      setLoadingGraph(false)
    }
  }

  function getSeverityColor(vulns: number): string {
    if (vulns === 0) return "#22c55e"
    if (vulns <= 3) return "#eab308"
    if (vulns <= 10) return "#f97316"
    return "#ef4444"
  }

  // Find scans that don't have reports yet
  function getScansWithoutReports(): Scan[] {
    const reportedScanIds = new Set(reports.map(r => r.scan_id))
    return scans.filter(s => !reportedScanIds.has(s.scan_id))
  }

  const scansWithoutReports = getScansWithoutReports()

  return (
    <div style={{ padding: "20px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "24px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: "bold" }}>Scan Reports</h1>
        <Link to="/" style={{ color: "#60a5fa", textDecoration: "none" }}>
          Back to Dashboard
        </Link>
      </div>

      {error && (
        <div style={{
          padding: "12px 16px",
          background: "#fef2f2",
          border: "1px solid #fecaca",
          borderRadius: "8px",
          color: "#dc2626",
          marginBottom: "20px"
        }}>
          {error}
        </div>
      )}

      {success && (
        <div style={{
          padding: "12px 16px",
          background: "#f0fdf4",
          border: "1px solid #86efac",
          borderRadius: "8px",
          color: "#166534",
          marginBottom: "20px"
        }}>
          {success}
        </div>
      )}

      {loading ? (
        <div style={{ textAlign: "center", padding: "40px", color: "#9ca3af" }}>
          Loading reports...
        </div>
      ) : (
        <>
          {/* Scans without reports */}
          {scansWithoutReports.length > 0 && (
            <div style={{ marginBottom: "30px" }}>
              <h2 style={{ fontSize: "18px", marginBottom: "16px", color: "#9ca3af" }}>
                Completed Scans - Generate Reports
              </h2>
              <div style={{ display: "grid", gap: "12px" }}>
                {scansWithoutReports.map((scan) => (
                  <div
                    key={scan.scan_id}
                    style={{
                      background: "#1e1e2e",
                      borderRadius: "12px",
                      padding: "16px 20px",
                      border: "1px solid #2d2d3d",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center"
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: "600", marginBottom: "4px" }}>
                        {scan.target_url}
                      </div>
                      <div style={{ fontSize: "13px", color: "#6b7280" }}>
                        {scan.findings_count} findings | {new Date(scan.start_time).toLocaleString()}
                      </div>
                    </div>
                    <div style={{ display: "flex", gap: "8px" }}>
                      <button
                        onClick={() => generateReport(scan.scan_id, "html")}
                        disabled={generating === scan.scan_id}
                        style={{
                          padding: "8px 16px",
                          background: generating === scan.scan_id ? "#4b5563" : "#22c55e",
                          color: "white",
                          border: "none",
                          borderRadius: "6px",
                          cursor: generating === scan.scan_id ? "not-allowed" : "pointer",
                          fontSize: "13px"
                        }}
                      >
                        {generating === scan.scan_id ? "..." : "HTML"}
                      </button>
                      <button
                        onClick={() => generateReport(scan.scan_id, "pdf")}
                        disabled={generating === scan.scan_id}
                        style={{
                          padding: "8px 16px",
                          background: generating === scan.scan_id ? "#4b5563" : "#8b5cf6",
                          color: "white",
                          border: "none",
                          borderRadius: "6px",
                          cursor: generating === scan.scan_id ? "not-allowed" : "pointer",
                          fontSize: "13px"
                        }}
                      >
                        {generating === scan.scan_id ? "..." : "PDF"}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Existing Reports */}
          {reports.length === 0 && scansWithoutReports.length === 0 ? (
            <div style={{
              textAlign: "center",
              padding: "60px 20px",
              background: "#1e1e2e",
              borderRadius: "12px",
              color: "#9ca3af"
            }}>
              <p style={{ fontSize: "18px", marginBottom: "12px" }}>No reports available</p>
              <p>Complete a scan to generate reports.</p>
              <Link
                to="/scan"
                style={{
                  display: "inline-block",
                  marginTop: "20px",
                  padding: "10px 20px",
                  background: "#3b82f6",
                  color: "white",
                  borderRadius: "8px",
                  textDecoration: "none"
                }}
              >
                Start New Scan
              </Link>
            </div>
          ) : reports.length > 0 && (
            <>
              <h2 style={{ fontSize: "18px", marginBottom: "16px", color: "#9ca3af" }}>
                Generated Reports
              </h2>
              <div style={{ display: "grid", gap: "16px" }}>
                {reports.map((report) => (
                  <div
                    key={report.report_id}
                    style={{
                      background: "#1e1e2e",
                      borderRadius: "12px",
                      padding: "20px",
                      border: "1px solid #2d2d3d"
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                      <div>
                        <h3 style={{ fontSize: "18px", fontWeight: "600", marginBottom: "8px" }}>
                          Scan #{report.scan_id}
                        </h3>
                        <p style={{ color: "#9ca3af", marginBottom: "4px" }}>{report.summary}</p>
                        <p style={{ color: "#6b7280", fontSize: "14px" }}>
                          Created: {new Date(report.created_at).toLocaleString()}
                        </p>
                        {report.report_path && (
                          <p style={{ color: "#6b7280", fontSize: "12px", marginTop: "4px" }}>
                            Format: {report.report_path.endsWith('.pdf') ? 'PDF' : 'HTML'}
                          </p>
                        )}
                      </div>
                      <div style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                        padding: "8px 16px",
                        background: "#2d2d3d",
                        borderRadius: "20px"
                      }}>
                        <span style={{
                          width: "10px",
                          height: "10px",
                          borderRadius: "50%",
                          background: getSeverityColor(report.total_vulns)
                        }}></span>
                        <span style={{ fontWeight: "600" }}>{report.total_vulns}</span>
                        <span style={{ color: "#9ca3af" }}>vulnerabilities</span>
                      </div>
                    </div>

                    <div style={{
                      display: "flex",
                      gap: "10px",
                      marginTop: "16px",
                      paddingTop: "16px",
                      borderTop: "1px solid #2d2d3d",
                      flexWrap: "wrap"
                    }}>
                      {report.report_path ? (
                        <>
                          {report.report_path?.endsWith('.html') ? (
                            <button
                              onClick={() => viewReport(report.report_id)}
                              style={{
                                padding: "8px 16px",
                                background: "#3b82f6",
                                color: "white",
                                border: "none",
                                borderRadius: "6px",
                                cursor: "pointer",
                                fontSize: "14px"
                              }}
                            >
                              View Report
                            </button>
                          ) : null}
                          <button
                            onClick={() => loadGraphData(report.scan_id)}
                            disabled={loadingGraph}
                            style={{
                              padding: "8px 16px",
                              background: graphScanId === report.scan_id ? "#6366f1" : "#2d2d3d",
                              color: "white",
                              border: "1px solid #3d3d4d",
                              borderRadius: "6px",
                              cursor: loadingGraph ? "not-allowed" : "pointer",
                              fontSize: "14px"
                            }}
                          >
                            {loadingGraph && graphScanId === report.scan_id ? "Loading..." : graphScanId === report.scan_id ? "Hide Graph" : "View Graph"}
                          </button>
                          <button
                            onClick={() => downloadReport(report.report_id)}
                            style={{
                              padding: "8px 16px",
                              background: report.report_path?.endsWith('.html') ? "#2d2d3d" : "#3b82f6",
                              color: "white",
                              border: report.report_path?.endsWith('.html') ? "1px solid #3d3d4d" : "none",
                              borderRadius: "6px",
                              cursor: "pointer",
                              fontSize: "14px"
                            }}
                          >
                            {report.report_path?.endsWith('.pdf') ? "Open PDF" : "Download"}
                          </button>
                          <span style={{ color: "#6b7280", padding: "8px", fontSize: "13px" }}>|</span>
                          <button
                            onClick={() => generateReport(report.scan_id, "html")}
                            disabled={generating === report.scan_id}
                            style={{
                              padding: "8px 16px",
                              background: generating === report.scan_id ? "#4b5563" : "#22c55e",
                              color: "white",
                              border: "none",
                              borderRadius: "6px",
                              cursor: generating === report.scan_id ? "not-allowed" : "pointer",
                              fontSize: "14px"
                            }}
                          >
                            Regenerate HTML
                          </button>
                          <button
                            onClick={() => generateReport(report.scan_id, "pdf")}
                            disabled={generating === report.scan_id}
                            style={{
                              padding: "8px 16px",
                              background: generating === report.scan_id ? "#4b5563" : "#8b5cf6",
                              color: "white",
                              border: "none",
                              borderRadius: "6px",
                              cursor: generating === report.scan_id ? "not-allowed" : "pointer",
                              fontSize: "14px"
                            }}
                          >
                            Regenerate PDF
                          </button>
                        </>
                      ) : (
                        <>
                          <button
                            onClick={() => generateReport(report.scan_id, "html")}
                            disabled={generating === report.scan_id}
                            style={{
                              padding: "8px 16px",
                              background: generating === report.scan_id ? "#4b5563" : "#22c55e",
                              color: "white",
                              border: "none",
                              borderRadius: "6px",
                              cursor: generating === report.scan_id ? "not-allowed" : "pointer",
                              fontSize: "14px"
                            }}
                          >
                            {generating === report.scan_id ? "Generating..." : "Generate HTML"}
                          </button>
                          <button
                            onClick={() => generateReport(report.scan_id, "pdf")}
                            disabled={generating === report.scan_id}
                            style={{
                              padding: "8px 16px",
                              background: generating === report.scan_id ? "#4b5563" : "#8b5cf6",
                              color: "white",
                              border: "none",
                              borderRadius: "6px",
                              cursor: generating === report.scan_id ? "not-allowed" : "pointer",
                              fontSize: "14px"
                            }}
                          >
                            {generating === report.scan_id ? "Generating..." : "Generate PDF"}
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </>
      )}

      {/* Graph Visualization */}
      {graphData && graphScanId && (
        <div style={{ marginTop: "30px" }}>
          <h2 style={{ fontSize: "18px", marginBottom: "16px", color: "#9ca3af" }}>
            Vulnerability Graph - Scan #{graphScanId}
          </h2>

          {/* Summary Cards */}
          {graphData.summary && (
            <div className="graph-summary-grid" style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
              gap: "12px",
              marginBottom: "20px"
            }}>
              <div style={{ background: "#1e1e2e", borderRadius: "12px", padding: "16px", border: "1px solid #2d2d3d" }}>
                <div style={{ fontSize: "0.75rem", color: "#6b7280", textTransform: "uppercase" }}>Pages</div>
                <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "#60a5fa" }}>{graphData.summary.total_nodes}</div>
              </div>
              <div style={{ background: "#1e1e2e", borderRadius: "12px", padding: "16px", border: "1px solid #2d2d3d" }}>
                <div style={{ fontSize: "0.75rem", color: "#6b7280", textTransform: "uppercase" }}>Links</div>
                <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "#22c55e" }}>{graphData.summary.total_edges}</div>
              </div>
              <div style={{ background: "#1e1e2e", borderRadius: "12px", padding: "16px", border: "1px solid #2d2d3d" }}>
                <div style={{ fontSize: "0.75rem", color: "#6b7280", textTransform: "uppercase" }}>Cycles</div>
                <div style={{ fontSize: "1.75rem", fontWeight: 700, color: graphData.summary.total_cycles > 0 ? "#ef4444" : "#22c55e" }}>
                  {graphData.summary.total_cycles}
                </div>
              </div>
              <div style={{ background: "#1e1e2e", borderRadius: "12px", padding: "16px", border: "1px solid #2d2d3d" }}>
                <div style={{ fontSize: "0.75rem", color: "#6b7280", textTransform: "uppercase" }}>Clusters</div>
                <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "#eab308" }}>{graphData.summary.total_clusters}</div>
              </div>
              <div style={{ background: "#1e1e2e", borderRadius: "12px", padding: "16px", border: "1px solid #2d2d3d" }}>
                <div style={{ fontSize: "0.75rem", color: "#6b7280", textTransform: "uppercase" }}>Vulns</div>
                <div style={{ fontSize: "1.75rem", fontWeight: 700, color: graphData.summary.total_vulnerabilities > 0 ? "#ef4444" : "#22c55e" }}>
                  {graphData.summary.total_vulnerabilities}
                </div>
              </div>
            </div>
          )}

          <VulnerabilityGraph data={graphData} width={1000} height={650} />

          {/* Clusters */}
          {graphData.clusters && graphData.clusters.length > 0 && (
            <div style={{ marginTop: "20px" }}>
              <h3 style={{ fontSize: "16px", marginBottom: "12px", color: "#9ca3af" }}>
                Vulnerability Clusters
              </h3>
              <div style={{ display: "grid", gap: "12px" }}>
                {graphData.clusters.map((cluster: any, i: number) => (
                  <div key={i} style={{
                    background: "#1e1e2e",
                    borderRadius: "12px",
                    padding: "16px 20px",
                    border: "1px solid #2d2d3d"
                  }}>
                    <div style={{ fontWeight: 600, marginBottom: "8px" }}>
                      {cluster.vuln_type}
                      <span style={{ color: "#6b7280", fontWeight: 400, marginLeft: "8px" }}>
                        ({cluster.total_findings} findings across {cluster.urls.length} pages)
                      </span>
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                      {cluster.urls.map((url: string, j: number) => (
                        <span key={j} style={{
                          padding: "4px 8px",
                          background: "#2d2d3d",
                          borderRadius: "4px",
                          fontSize: "0.8rem",
                          fontFamily: "monospace",
                          color: "#60a5fa"
                        }}>
                          {url}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
