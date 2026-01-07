import { API_BASE } from "../api/client"

export default function Sidebar() {
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

  return (
    <div className="sidebar">
      <h2>Web Scanner</h2>
      <a href="/">Dashboard</a>
      <button onClick={logout}>Logout</button>
    </div>
  )
}
