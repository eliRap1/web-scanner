import { useState } from "react"
import { API_BASE } from "../api/client"
import { Link } from "react-router-dom"

export default function Login() {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")

  async function submit() {
    const res = await fetch(`${API_BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    })

    const data = await res.json()
    if (data.token) {
      localStorage.setItem("token", data.token)
      window.location.href = "/"
    } else {
      setError("Invalid credentials")
    }
  }

  return (
    <div className="center">
      <div className="card">
        <h2>Login</h2>

        <input
          placeholder="Username"
          onChange={e => setUsername(e.target.value)}
        />

        <input
          type="password"
          placeholder="Password"
          onChange={e => setPassword(e.target.value)}
        />

        <button onClick={submit}>Login</button>

        {error && <p className="error">{error}</p>}

        <p style={{ marginTop: "12px", textAlign: "center" }}>
          Don’t have an account?{" "}
          <Link to="/register" className="link">
            Register
          </Link>
        </p>
      </div>
    </div>
  )
}
