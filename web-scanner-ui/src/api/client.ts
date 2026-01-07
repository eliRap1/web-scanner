export const API_BASE = "http://localhost:8000"

export function getToken() {
  return localStorage.getItem("token")
}

export async function apiFetch(
  path: string,
  options: RequestInit = {}
) {
  const token = getToken()
  return fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {})
    }
  })
}
