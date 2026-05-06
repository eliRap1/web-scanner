// API base URL — override per environment via VITE_API_URL.
// In dev, defaults to the local FastAPI port.
export const API_BASE: string =
  (import.meta.env?.VITE_API_URL as string | undefined) ?? "http://localhost:8000"

export class ApiError extends Error {
  constructor(public status: number, public detail: string) {
    super(detail)
    this.name = "ApiError"
  }
}

export function getToken(): string | null {
  return localStorage.getItem("token")
}

export function clearToken(): void {
  localStorage.removeItem("token")
}

/**
 * Fetch wrapper that injects the bearer token, sets JSON headers when a body is present,
 * and converts non-2xx responses into an ApiError. On 401 it clears the stored token so
 * the next render redirects to /login.
 */
export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const token = getToken()
  const hasJsonBody =
    options.body !== undefined &&
    !(options.body instanceof FormData) &&
    !(options.body instanceof Blob)

  const headers: Record<string, string> = {
    ...(hasJsonBody ? { "Content-Type": "application/json" } : {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...((options.headers as Record<string, string>) || {}),
  }

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers })

  if (res.status === 401) {
    clearToken()
  }

  return res
}

export async function getGraphData(scanId: string) {
  const res = await apiFetch(`/scan/${scanId}/graph`)
  if (!res.ok) return null
  return res.json()
}
