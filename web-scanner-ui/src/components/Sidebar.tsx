import { API_BASE } from "../api/client"
import { useLocation } from "react-router-dom"

export default function Sidebar() {
  const location = useLocation()

  async function logout() {
    const token = localStorage.getItem("token")

    if (token) {
      await fetch(`${API_BASE}/logout`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json"
        }
      })
    }

    localStorage.removeItem("token")
    window.location.href = "/login"
  }

  const isActive = (path: string) => location.pathname === path

  return (
    <div className="sidebar">
      <h2>Web Scanner</h2>
      
      <nav>
        <a href="/" className={isActive("/") ? "active" : ""}>
          📊 Dashboard
        </a>
        <a href="/scan" className={isActive("/scan") ? "active" : ""}>
          🔍 New Scan
        </a>
        <a href="/reports" className={isActive("/reports") ? "active" : ""}>
          📄 Reports
        </a>
        <a href="/settings" className={isActive("/settings") ? "active" : ""}>
          ⚙️ Settings
        </a>
      </nav>
      
      <button className="logout" onClick={logout}>
        🚪 Logout
      </button>
    </div>
  )
}