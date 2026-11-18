import {
  Activity,
  BellRing,
  ChevronLeft,
  ChevronRight,
  FileSearch,
  KeyRound,
  LayoutDashboard,
  LogOut,
  PanelLeftClose,
  PanelLeftOpen,
  Settings,
  Shield,
  Wrench,
} from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { api } from '../api/client'
import { useOverview, useSession } from '../api/hooks'
import { useLive } from '../state/live'
import { CommandPalette } from './CommandPalette'
import { shortHash, timeLabel } from './ui'

const NAV = [
  {
    group: 'Monitor',
    items: [
      { label: 'Overview', to: '/', icon: LayoutDashboard },
      { label: 'Alerts', to: '/alerts', icon: BellRing },
      { label: 'Audit Explorer', to: '/audit', icon: FileSearch },
      { label: 'Approvals', to: '/approvals', icon: KeyRound },
    ],
  },
  {
    group: 'Configure',
    items: [
      { label: 'Tools & Connectors', to: '/tools', icon: Wrench },
      { label: 'Policy', to: '/policy', icon: Shield },
      { label: 'Settings', to: '/settings', icon: Settings },
    ],
  },
  {
    group: 'System',
    items: [{ label: 'Evaluations', to: '/evaluations', icon: Activity }],
  },
]

export function AppShell({ children }: { children: ReactNode }) {
  const [collapsed, setCollapsed] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const { paused, toggle } = useLive()
  const location = useLocation()
  const session = useSession()
  const overview = useOverview()
  const title = NAV.flatMap((group) => group.items).find(
    (item) => item.to === location.pathname,
  )?.label ?? 'Overview'

  return (
    <div className="app">
      <aside className={`rail${collapsed ? ' collapsed' : ''}`}>
        <div className="rail-brand">
          <span className="rail-brand-mark">P</span>
          {!collapsed ? <span className="rail-brand-name">ProtAI Console</span> : null}
        </div>
        {NAV.map((group) => (
          <div key={group.group}>
            <div className="rail-group">{group.group}</div>
            {group.items.map((item) => {
              const Icon = item.icon
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === '/'}
                  className={({ isActive }) => `rail-link${isActive ? ' active' : ''}`}
                  title={collapsed ? item.label : undefined}
                >
                  <Icon size={17} aria-hidden="true" />
                  {!collapsed ? <span className="rail-label">{item.label}</span> : null}
                </NavLink>
              )
            })}
          </div>
        ))}
        <div className="rail-spacer" />
        <button
          className="rail-link"
          onClick={() => setCollapsed((value) => !value)}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <PanelLeftOpen size={17} /> : <PanelLeftClose size={17} />}
          {!collapsed ? <span className="rail-label">Collapse</span> : null}
        </button>
      </aside>

      <header className="topbar">
        <span className="topbar-title">{title}</span>
        <span className="topbar-spacer" />
        <button className="search-trigger" onClick={() => setPaletteOpen(true)}>
          <span>Search or jump to…</span>
          <span className="kbd">⌘K</span>
        </button>
        {session.data ? (
          <>
            <span className="badge info">{session.data.role}</span>
            <span className="mono faint" style={{ fontSize: 12 }}>{session.data.username}</span>
            <button
              className="btn ghost"
              title="Sign out"
              aria-label="Sign out"
              onClick={() => {
                void api.logout().finally(() => window.location.reload())
              }}
            >
              <LogOut size={15} />
            </button>
          </>
        ) : null}
      </header>

      <main className="main">{children}</main>

      <footer className="statusbar">
        <span>
          <i className={`status-dot ${paused ? 'paused' : 'live'}`} />
          {paused ? 'PAUSED' : 'LIVE'}
        </span>
        <button
          className="btn ghost"
          style={{ minHeight: 18, padding: '0 6px', fontSize: 11 }}
          onClick={toggle}
        >
          {paused ? <ChevronRight size={12} /> : <ChevronLeft size={12} />}
          {paused ? 'Resume' : 'Pause'}
        </button>
        <span>chain #{overview.data?.chain_head_sequence ?? '—'}</span>
        <span title={overview.data?.chain_head_hash}>head {shortHash(overview.data?.chain_head_hash)}</span>
        <span>policy {overview.data?.policy_version ?? '—'}</span>
        <span className="topbar-spacer" />
        <span>updated {timeLabel(overview.data?.generated_at)}</span>
      </footer>

      <CommandPalette
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        onTogglePause={toggle}
      />
    </div>
  )
}
