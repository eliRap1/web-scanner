import { useState } from "react"
import { API_BASE } from "../api/client"
import { Link, useNavigate } from "react-router-dom"

export default function Register() {
  const [form, setForm] = useState<any>({})
  const [msg, setMsg] = useState("")
  const [isSuccess, setIsSuccess] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const navigate = useNavigate()

  async function submit() {
    setMsg("")
    setIsSuccess(false)
    setIsLoading(true)

    try {
      const res = await fetch(`${API_BASE}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form)
      })
      const data = await res.json()

      if (res.ok && data.status === "ok") {
        setIsSuccess(true)
        setMsg("Registration successful! Redirecting to login...")
        setTimeout(() => {
          navigate("/login")
        }, 1500)
      } else {
        setMsg(data.detail || data.message || "Registration failed")
      }
    } catch (err) {
      setMsg("Network error. Please try again.")
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="center">
      <div className="card">
        <h2>Register</h2>

        <input placeholder="Username" onChange={e => setForm({ ...form, username: e.target.value })} />
        <input placeholder="Email" onChange={e => setForm({ ...form, email: e.target.value })} />
        <input type="password" placeholder="Password" onChange={e => setForm({ ...form, password: e.target.value })} />
        <input type="password" placeholder="Confirm Password" onChange={e => setForm({ ...form, confirm_password: e.target.value })} />

        <button onClick={submit} disabled={isLoading || isSuccess}>
          {isLoading ? "Creating..." : isSuccess ? "Redirecting..." : "Create Account"}
        </button>

        {msg && (
          <p style={{ color: isSuccess ? "#22c55e" : "#ef4444", marginTop: "12px" }}>
            {msg}
          </p>
        )}

        <p style={{ marginTop: "12px", textAlign: "center" }}>
          Already have an account?{" "}
          <Link to="/login" className="link">
            Login
          </Link>
        </p>
      </div>
    </div>
  )
}
