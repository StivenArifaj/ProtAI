import type { ReactNode } from 'react'
import type { AuditEvent, Checkpoint } from '../api/types'

export function ChainRibbon({
  events,
  checkpoints,
  headSequence,
}: {
  events: AuditEvent[]
  checkpoints: Checkpoint[]
  headSequence: number
}) {
  const recent = events.slice(0, 48).reverse()
  const checkpointSequences = new Set(checkpoints.map((item) => item.sequence_number))
  const sequences = new Set(recent.map((event) => event.sequence_number))
  const cells: ReactNode[] = []

  for (const event of recent) {
    const previous = sequences.has(event.sequence_number - 1) || event.sequence_number === 1
    const isHead = event.sequence_number === headSequence
    const isCheckpoint = checkpointSequences.has(event.sequence_number)
    const className = `ribbon-cell${isHead ? ' head' : isCheckpoint ? ' checkpoint' : !previous ? ' gap' : ''}`
    cells.push(
      <span
        key={event.sequence_number}
        className={className}
        title={`Sequence ${event.sequence_number}${isCheckpoint ? ' · checkpoint' : ''}${!previous ? ' · gap' : ''}`}
      />,
    )
  }

  return (
    <div>
      <div className="ribbon">{cells}</div>
      <div className="ribbon-legend">
        <span><i className="ribbon-cell" style={{ display: 'inline-block', width: 8, height: 10 }} /> event</span>
        <span><i className="ribbon-cell checkpoint" style={{ display: 'inline-block', width: 8, height: 10 }} /> checkpoint</span>
        <span><i className="ribbon-cell head" style={{ display: 'inline-block', width: 8, height: 10 }} /> head</span>
        <span><i className="ribbon-cell gap" style={{ display: 'inline-block', width: 8, height: 10 }} /> gap</span>
      </div>
    </div>
  )
}
