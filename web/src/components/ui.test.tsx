import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { Badge, Stat, shortHash, timeLabel } from './ui'
import { DecisionTrace } from './DecisionTrace'
import type { AuditEvent } from '../api/types'

function event(overrides: Partial<AuditEvent>): AuditEvent {
  return {
    sequence_number: 1,
    occurred_at: '2026-01-01T12:00:00Z',
    event_type: 'POLICY_EVALUATED',
    component: 'firewall.gateway',
    request_id: 'req-1',
    trace_id: null,
    call_id: 'call-1',
    decision: 'ALLOW',
    reason: 'authorized_read',
    outcome: null,
    tool_id: 'mock_email.read',
    action_id: 'read',
    principal_subject_id: 'user-1',
    destination: null,
    risk_score: 10,
    policy_version: 'dev-1',
    policy_hash: 'a'.repeat(64),
    event_hash: 'b'.repeat(64),
    previous_hash: '0'.repeat(64),
    has_dlp_evidence: false,
    has_input_evidence: false,
    resource_count: 1,
    result_bytes: null,
    duration_ms: 5,
    ...overrides,
  }
}

describe('ui primitives', () => {
  it('renders semantic badges with labels', () => {
    render(<Badge tone="bad">BLOCK</Badge>)
    expect(screen.getByText('BLOCK')).toBeTruthy()
  })

  it('renders compact stats', () => {
    render(<Stat label="Audit events" value={42} note="chain v1" />)
    expect(screen.getByText('Audit events')).toBeTruthy()
    expect(screen.getByText('42')).toBeTruthy()
  })

  it('formats hashes without leaking the full value', () => {
    expect(shortHash('a'.repeat(64))).toContain('…')
    expect(shortHash(null)).toBe('—')
  })

  it('formats or passes through timestamps', () => {
    expect(timeLabel(null)).toBe('—')
    expect(timeLabel('invalid')).toBe('invalid')
  })
})

describe('DecisionTrace', () => {
  it('shows stage states from correlated audit evidence', () => {
    const events = [
      event({ sequence_number: 1, event_type: 'REQUEST_RECEIVED', decision: null }),
      event({ sequence_number: 2, event_type: 'INPUT_INSPECTED', decision: null }),
      event({ sequence_number: 3, event_type: 'POLICY_EVALUATED', decision: 'BLOCK' }),
    ]
    render(<DecisionTrace events={events} />)
    expect(screen.getByLabelText('INGRESS: seen')).toBeTruthy()
    expect(screen.getByLabelText('INPUT: seen')).toBeTruthy()
    expect(screen.getByLabelText('POLICY: BLOCK')).toBeTruthy()
    expect(screen.getByLabelText('APPROVAL: —')).toBeTruthy()
  })

  it('renders allow state distinctly from block', () => {
    const events = [event({ event_type: 'POLICY_EVALUATED', decision: 'ALLOW' })]
    render(<DecisionTrace events={events} />)
    expect(screen.getByLabelText('POLICY: ALLOW')).toBeTruthy()
  })
})
