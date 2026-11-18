import { createContext, useContext, useMemo, useState, type ReactNode } from 'react'

interface LiveState {
  paused: boolean
  toggle: () => void
}

const LiveContext = createContext<LiveState>({ paused: false, toggle: () => undefined })

export function LiveProvider({ children }: { children: ReactNode }) {
  const [paused, setPaused] = useState(false)
  const value = useMemo(
    () => ({ paused, toggle: () => setPaused((current) => !current) }),
    [paused],
  )
  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>
}

export const useLive = () => useContext(LiveContext)
