import { CheckCircle, Clock, WarningCircle } from '@phosphor-icons/react'

type StatusTone = 'ready' | 'waiting' | 'attention'

interface StatusPillProps {
  tone: StatusTone
  children: string
}

const toneClass: Record<StatusTone, string> = {
  ready: 'bg-success-soft text-success-strong',
  waiting: 'bg-kumo-tint text-kumo-subtle',
  attention: 'bg-brand-soft text-brand-strong',
}

export function StatusPill({ tone, children }: StatusPillProps) {
  const Icon = tone === 'ready' ? CheckCircle : tone === 'attention' ? WarningCircle : Clock
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium tabular-nums ${toneClass[tone]}`}
    >
      <Icon size={13} weight="fill" />
      {children}
    </span>
  )
}
