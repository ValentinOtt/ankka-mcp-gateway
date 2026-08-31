import type { ReactNode } from 'react'

interface PageHeaderProps {
  title: string
  description?: string
  action?: ReactNode
}

export function PageHeader({ title, description, action }: PageHeaderProps) {
  return (
    <header className="flex flex-wrap items-center justify-between gap-3 border-b border-kumo-line/70 pb-5">
      <div className="min-w-0">
        <h1 className="text-balance text-xl font-semibold leading-snug tracking-tight text-kumo-strong">
          {title}
        </h1>
        {description ? (
          <p className="mt-1.5 max-w-[65ch] text-pretty text-sm leading-relaxed text-kumo-subtle">
            {description}
          </p>
        ) : null}
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </header>
  )
}
