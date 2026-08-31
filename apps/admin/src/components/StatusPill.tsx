import { CheckCircle, Clock, WarningCircle } from '@phosphor-icons/react'

type StatusTone = 'ready' | 'waiting' | 'attention'

interface StatusPillProps {
  tone: StatusTone
  children: string
}

const toneClass = {
  ready: 'bg-success-soft text-success-strong',
  waiting: 'bg-kumo-tint text-kumo-subtle',
  attention: 'bg-warning-soft text-warning-strong',
}

export function StatusPill({ tone, children }: StatusPillProps) {
  const Icon = tone === 'ready' ? CheckCircle : tone === 'attention' ? WarningCircle : Clock
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-medium tabular-nums ${toneClass[tone]}`}
    >
      <Icon size={13} aria-hidden="true" />
      {children}
    </span>
  )
}
