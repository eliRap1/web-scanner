import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { BrowserRouter } from 'react-router-dom'
import Login from '../pages/Login'

// Mock fetch globally
const mockFetch = vi.fn()
global.fetch = mockFetch

// Wrap component with router for Link to work
function renderLogin() {
  return render(
    <BrowserRouter>
      <Login />
    </BrowserRouter>
  )
}

describe('Login Component', () => {
  beforeEach(() => {
    mockFetch.mockClear()
    localStorage.clear()
  })

  it('renders login form', () => {
    renderLogin()

    expect(screen.getByPlaceholderText('Username')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Password')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /login/i })).toBeInTheDocument()
    expect(screen.getByText(/don't have an account/i)).toBeInTheDocument()
  })

  it('shows error on invalid login', async () => {
    mockFetch.mockResolvedValueOnce({
      json: async () => ({ error: 'Invalid credentials' })
    })

    renderLogin()

    fireEvent.change(screen.getByPlaceholderText('Username'), {
      target: { value: 'wronguser' }
    })
    fireEvent.change(screen.getByPlaceholderText('Password'), {
      target: { value: 'wrongpass' }
    })
    fireEvent.click(screen.getByRole('button', { name: /login/i }))

    await waitFor(() => {
      expect(screen.getByText('Invalid credentials')).toBeInTheDocument()
    })
  })

  it('handles form submission', async () => {
    mockFetch.mockResolvedValueOnce({
      json: async () => ({ token: 'test-token-123' })
    })

    // Mock window.location
    const originalLocation = window.location
    Object.defineProperty(window, 'location', {
      writable: true,
      value: { href: '' }
    })

    renderLogin()

    fireEvent.change(screen.getByPlaceholderText('Username'), {
      target: { value: 'testuser' }
    })
    fireEvent.change(screen.getByPlaceholderText('Password'), {
      target: { value: 'testpass' }
    })
    fireEvent.click(screen.getByRole('button', { name: /login/i }))

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/login'),
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: 'testuser', password: 'testpass' })
        })
      )
    })

    await waitFor(() => {
      expect(localStorage.getItem('token')).toBe('test-token-123')
    })

    // Restore window.location
    window.location = originalLocation
  })
})
