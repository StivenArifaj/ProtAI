import { Command } from 'cmdk'
import { Activity, FileSearch, KeyRound, LayoutDashboard, ListTree, Settings, Shield, Wrench, BellRing } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'

const NAV = [
  { label: 'Overview', to: '/', icon: LayoutDashboard, group: 'Navigate' },
  { label: 'Alerts', to: '/alerts', icon: BellRing, group: 'Navigate' },
  { label: 'Audit Explorer', to: '/audit', icon: FileSearch, group: 'Navigate' },
  { label: 'Logs', to: '/logs', icon: ListTree, group: 'Navigate' },
  { label: 'Approvals', to: '/approvals', icon: KeyRound, group: 'Navigate' },
  { label: 'Tools & Connectors', to: '/tools', icon: Wrench, group: 'Navigate' },
  { label: 'Policy', to: '/policy', icon: Shield, group: 'Navigate' },
  { label: 'Settings', to: '/settings', icon: Settings, group: 'Navigate' },
  { label: 'Evaluations', to: '/evaluations', icon: Activity, group: 'Navigate' },
]

export function CommandPalette({
  open,
  onOpenChange,
  onTogglePause,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onTogglePause: () => void
}) {
  const navigate = useNavigate()
  const [search, setSearch] = useState('')

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        onOpenChange(!open)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [open, onOpenChange])

  if (!open) return null

  const go = (to: string) => {
    navigate(to)
    onOpenChange(false)
    setSearch('')
  }

  return (
    <div className="cmd-overlay" onMouseDown={() => onOpenChange(false)}>
      <div className="cmd" onMouseDown={(event) => event.stopPropagation()}>
        <Command label="Command palette">
          <Command.Input
            value={search}
            onValueChange={setSearch}
            placeholder="Jump to a screen or run a read-only action…"
            autoFocus
          />
          <Command.List>
            <Command.Empty className="empty">No matching command.</Command.Empty>
            <Command.Group heading="Navigate">
              {NAV.filter((item) => item.label.toLowerCase().includes(search.toLowerCase())).map(
                (item) => {
                  const Icon = item.icon
                  return (
                    <Command.Item key={item.to} onSelect={() => go(item.to)}>
                      <Icon size={14} /> {item.label}
                    </Command.Item>
                  )
                },
              )}
            </Command.Group>
            <Command.Group heading="Actions">
              <Command.Item
                onSelect={() => {
                  onTogglePause()
                  onOpenChange(false)
                }}
              >
                <Activity size={14} /> Toggle live stream pause
              </Command.Item>
              <Command.Item onSelect={() => go('/audit?decision=BLOCK')}>
                <FileSearch size={14} /> Show blocked decisions
              </Command.Item>
              <Command.Item onSelect={() => go('/alerts')}>
                <BellRing size={14} /> Open alert triage queue
              </Command.Item>
            </Command.Group>
          </Command.List>
        </Command>
      </div>
    </div>
  )
}
