import { useState } from "react"
import { API_BASE } from "../api/client"
import { Link } from "react-router-dom"

export default function Register() {
  const [form, setForm] = useState<any>({})
  const [msg, setMsg] = useState("")

  async function submit() {
    const res = await fetch(`${API_BASE}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(form)
    })
    const data = await res.json()
    setMsg(data.message || data.detail || "Registered")
  }

  return (
    <div className="center">
      <div className="card">
        <h2>Register</h2>

        <input placeholder="Username" onChange={e => setForm({ ...form, username: e.target.value })} />
        <input placeholder="Email" onChange={e => setForm({ ...form, email: e.target.value })} />
        <input type="password" placeholder="Password" onChange={e => setForm({ ...form, password: e.target.value })} />
        <input type="password" placeholder="Confirm Password" onChange={e => setForm({ ...form, confirm_password: e.target.value })} />

        <button onClick={submit}>Create Account</button>

        {msg && <p>{msg}</p>}

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
