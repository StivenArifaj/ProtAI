import * as Dialog from '@radix-ui/react-dialog'
import { X } from 'lucide-react'
import type { ReactNode } from 'react'
import { createContext, useCallback, useContext, useMemo, useState } from 'react'

type Tone = 'ok' | 'bad' | 'warn' | 'info' | 'neutral'

export function Badge({ tone = 'neutral', children }: { tone?: Tone; children: ReactNode }) {
  return <span className={`badge ${tone === 'neutral' ? '' : tone}`}>{children}</span>
}

export function Stat({
  label,
  value,
  note,
}: {
  label: string
  value: ReactNode
  note?: ReactNode
}) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {note ? <div className="stat-note">{note}</div> : null}
    </div>
  )
}

export function Panel({
  title,
  actions,
  children,
}: {
  title: string
  actions?: ReactNode
  children: ReactNode
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <span className="panel-title">{title}</span>
        <span className="topbar-spacer" />
        {actions}
      </div>
      <div className="panel-body">{children}</div>
    </section>
  )
}

export function Empty({ title, hint }: { title: string; hint: string }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      <span>{hint}</span>
    </div>
  )
}

export function Skeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div style={{ display: 'grid', gap: 8, padding: 14 }}>
      {Array.from({ length: rows }, (_, index) => (
        <div className="skeleton" key={index} style={{ width: `${90 - index * 7}%` }} />
      ))}
    </div>
  )
}

export function Drawer({
  open,
  onOpenChange,
  title,
  subtitle,
  children,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  subtitle?: ReactNode
  children: ReactNode
}) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="drawer-backdrop" />
        <Dialog.Content className="drawer" aria-describedby={undefined}>
          <div className="drawer-head">
            <div style={{ minWidth: 0 }}>
              <Dialog.Title style={{ fontSize: 15 }}>{title}</Dialog.Title>
              {subtitle ? <div className="faint mono" style={{ fontSize: 11 }}>{subtitle}</div> : null}
            </div>
            <span className="topbar-spacer" />
            <Dialog.Close asChild>
              <button className="btn ghost" aria-label="Close detail panel">
                <X size={16} />
              </button>
            </Dialog.Close>
          </div>
          <div className="drawer-body">{children}</div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

interface ToastState {
  message: string
  ok: boolean
}

const ToastContext = createContext<(message: string, ok?: boolean) => void>(() => undefined)

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toast, setToast] = useState<ToastState | null>(null)
  const show = useCallback((message: string, ok = true) => {
    setToast({ message, ok })
    window.setTimeout(() => setToast(null), 4200)
  }, [])
  const value = useMemo(() => show, [show])
  return (
    <ToastContext.Provider value={value}>
      {children}
      {toast ? (
        <div
          role="status"
          style={{
            position: 'fixed',
            bottom: 40,
            right: 20,
            zIndex: 'var(--z-toast)' as unknown as number,
            padding: '10px 14px',
            borderRadius: 'var(--radius)',
            border: `1px solid ${toast.ok ? 'var(--operational)' : 'var(--incident)'}`,
            background: 'var(--surface-raised)',
            maxWidth: 420,
            fontSize: 13,
          }}
        >
          {toast.message}
        </div>
      ) : null}
    </ToastContext.Provider>
  )
}

export const useToast = () => useContext(ToastContext)

export function timeLabel(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function shortHash(value: string | null | undefined): string {
  if (!value) return '—'
  return value.length > 14 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value
}
