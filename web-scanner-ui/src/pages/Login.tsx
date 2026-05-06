import { FormEvent, useState } from "react"
import { Link, useNavigate } from "react-router-dom"
import { API_BASE } from "../api/client"

export default function Login() {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setError("")
    setLoading(true)
    try {
      const res = await fetch(`${API_BASE}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      })

      const data = await res.json().catch(() => ({}))

      if (res.ok && data.token) {
        localStorage.setItem("token", data.token)
        navigate("/", { replace: true })
        return
      }

      setError(data.detail || "Invalid credentials")
    } catch {
      setError("Network error. Please try again.")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="center">
      <form className="card" onSubmit={submit}>
        <h2>Login</h2>

        <label htmlFor="login-username" className="sr-only">Username</label>
        <input
          id="login-username"
          name="username"
          autoComplete="username"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />

        <label htmlFor="login-password" className="sr-only">Password</label>
        <input
          id="login-password"
          name="password"
          type="password"
          autoComplete="current-password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />

        <button type="submit" disabled={loading}>
          {loading ? "Signing in…" : "Login"}
        </button>

        {error && <p className="error">{error}</p>}

        <p style={{ marginTop: "12px", textAlign: "center" }}>
          Don't have an account?{" "}
          <Link to="/register" className="link">
            Register
          </Link>
        </p>
      </form>
    </div>
  )
}
