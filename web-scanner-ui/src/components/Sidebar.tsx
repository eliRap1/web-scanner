import { NavLink, useNavigate } from "react-router-dom"
import { API_BASE, clearToken, getToken } from "../api/client"

const NAV_ITEMS = [
  { to: "/", label: "Dashboard", icon: "📊", end: true },
  { to: "/scan", label: "New Scan", icon: "🔍" },
  { to: "/reports", label: "Reports", icon: "📄" },
  { to: "/settings", label: "Settings", icon: "⚙️" },
]

export default function Sidebar() {
  const navigate = useNavigate()

  async function logout() {
    const token = getToken()

    if (token) {
      try {
        await fetch(`${API_BASE}/logout`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        })
      } catch {
        // Best-effort: even if the server rejects, drop the token locally.
      }
    }

    clearToken()
    navigate("/login", { replace: true })
  }

  return (
    <div className="sidebar">
      <h2>Web Scanner</h2>

      <nav>
        {NAV_ITEMS.map(({ to, label, icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) => (isActive ? "active" : "")}
          >
            {icon} {label}
          </NavLink>
        ))}
      </nav>

      <button className="logout" onClick={logout}>
        🚪 Logout
      </button>
    </div>
  )
}
