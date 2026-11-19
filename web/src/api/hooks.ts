import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { api } from './client'

export const keys = {
  session: ['session'] as const,
  overview: ['overview'] as const,
  audit: (params: string) => ['audit', params] as const,
  alerts: ['alerts'] as const,
  rules: ['rules'] as const,
  approvals: ['approvals'] as const,
  tools: ['tools'] as const,
  connectors: ['connectors'] as const,
  policy: ['policy'] as const,
  configs: ['configs'] as const,
  limiter: ['limiter'] as const,
  settings: ['settings'] as const,
  reports: ['reports'] as const,
  users: ['users'] as const,
  checkpoints: ['checkpoints'] as const,
}

export const useSession = () => useQuery({ queryKey: keys.session, queryFn: api.session, retry: false })
export const useOverview = () =>
  useQuery({ queryKey: keys.overview, queryFn: api.overview, refetchInterval: 15_000 })
export const useAudit = (params: string) =>
  useQuery({ queryKey: keys.audit(params), queryFn: () => api.audit(new URLSearchParams(params)) })
export const useAlerts = () => useQuery({ queryKey: keys.alerts, queryFn: api.alerts, refetchInterval: 10_000 })
export const useRules = () => useQuery({ queryKey: keys.rules, queryFn: api.alertRules })
export const useApprovals = () =>
  useQuery({ queryKey: keys.approvals, queryFn: api.approvals, refetchInterval: 10_000 })
export const useTools = () => useQuery({ queryKey: keys.tools, queryFn: api.tools })
export const useConnectors = () => useQuery({ queryKey: keys.connectors, queryFn: api.connectors })
export const usePolicy = () => useQuery({ queryKey: keys.policy, queryFn: api.policy })
export const useConfigs = () => useQuery({ queryKey: keys.configs, queryFn: api.configs })
export const useLimiter = () => useQuery({ queryKey: keys.limiter, queryFn: api.limiter })
export const useSettings = () => useQuery({ queryKey: keys.settings, queryFn: api.settings })
export const useReports = () => useQuery({ queryKey: keys.reports, queryFn: api.reports })
export const useUsers = () => useQuery({ queryKey: keys.users, queryFn: api.users })
export const useMetrics = () =>
  useQuery({ queryKey: ['metrics'], queryFn: api.metrics, refetchInterval: 15_000 })

export function useLogs(params: string, live: boolean) {
  return useQuery({
    queryKey: ['logs', params],
    queryFn: () => api.logs(params),
    refetchInterval: live ? 2000 : false,
  })
}

export const useLogServices = () =>
  useQuery({ queryKey: ['log-services'], queryFn: api.logServices, refetchInterval: 15_000 })
export const useCheckpoints = () => useQuery({ queryKey: keys.checkpoints, queryFn: api.checkpoints })

export function useInvalidate() {
  const client = useQueryClient()
  return () => void client.invalidateQueries()
}

export function useLiveStream(paused: boolean) {
  const [lastAlertCount, setLastAlertCount] = useState<number | null>(null)
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null)
  const invalidate = useInvalidate()

  useEffect(() => {
    if (paused) return
    const source = new EventSource('/admin/events/stream')
    const onSnapshot = (event: MessageEvent<string>) => {
      try {
        const data = JSON.parse(event.data) as { alerts: number }
        setLastAlertCount(data.alerts)
        setUpdatedAt(new Date())
      } catch {
        // ignore malformed heartbeat
      }
    }
    const onAlerts = (event: MessageEvent<string>) => {
      onSnapshot(event)
      void invalidate()
    }
    source.addEventListener('snapshot', onSnapshot as EventListener)
    source.addEventListener('alerts', onAlerts as EventListener)
    return () => {
      source.removeEventListener('snapshot', onSnapshot as EventListener)
      source.removeEventListener('alerts', onAlerts as EventListener)
      source.close()
    }
  }, [paused, invalidate])

  return { lastAlertCount, updatedAt }
}

export function useMutationToast(action: () => Promise<{ message: string }>, onDone?: () => void) {
  return useMutation({
    mutationFn: action,
    onSuccess: () => onDone?.(),
  })
}
