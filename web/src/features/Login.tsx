import { ShieldCheck } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { api } from '../api/client'

export function Login() {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await api.login(username, password)
      window.location.reload()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign in failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div className="rail-brand-mark" style={{ marginBottom: 16, width: 34, height: 34 }}>
          <ShieldCheck size={18} aria-hidden="true" />
        </div>
        <h1>ProtAI Console</h1>
        <p className="muted" style={{ margin: 0, fontSize: 13 }}>
          Security operations and integration health. Read-only by design.
        </p>
        <div className="field">
          <label htmlFor="username">Username</label>
          <input
            id="username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            required
          />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
            required
          />
        </div>
        {error ? <div className="login-error" role="alert">{error}</div> : null}
        <button className="btn primary" type="submit" disabled={busy} style={{ width: '100%', marginTop: 18 }}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
