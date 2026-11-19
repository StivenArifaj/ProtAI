import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { useSession } from './api/hooks'
import { AppShell } from './components/AppShell'
import { ToastProvider } from './components/ui'
import { Alerts } from './features/Alerts'
import { Approvals } from './features/Approvals'
import { AuditExplorer } from './features/AuditExplorer'
import { Evaluations } from './features/Evaluations'
import { Login } from './features/Login'
import { Logs } from './features/Logs'
import { Overview } from './features/Overview'
import { Policy } from './features/Policy'
import { Settings } from './features/Settings'
import { Tools } from './features/Tools'
import { LiveProvider } from './state/live'

const client = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false },
  },
})

function Authenticated() {
  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/audit" element={<AuditExplorer />} />
        <Route path="/logs" element={<Logs />} />
        <Route path="/approvals" element={<Approvals />} />
        <Route path="/tools" element={<Tools />} />
        <Route path="/policy" element={<Policy />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/evaluations" element={<Evaluations />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppShell>
  )
}

function Gate() {
  const session = useSession()
  if (session.isLoading) {
    return (
      <div className="login-wrap">
        <div className="login-card">
          <div className="skeleton" style={{ height: 20, width: '60%' }} />
          <div className="skeleton" style={{ height: 12, marginTop: 12 }} />
        </div>
      </div>
    )
  }
  if (session.isError) return <Login />
  return <Authenticated />
}

export default function App() {
  return (
    <QueryClientProvider client={client}>
      <BrowserRouter>
        <ToastProvider>
          <LiveProvider>
            <Gate />
          </LiveProvider>
        </ToastProvider>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
