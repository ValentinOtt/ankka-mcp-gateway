import type { ReactNode } from 'react'

interface PageHeaderProps {
  eyebrow?: string
  title: string
  description: string
  action?: ReactNode
}

export function PageHeader({ eyebrow, title, description, action }: PageHeaderProps) {
  return (
    <header className="flex flex-col justify-between gap-5 sm:flex-row sm:items-start">
      <div>
        {eyebrow ? (
          <p className="mb-2 text-[0.6875rem] font-semibold uppercase leading-4 tracking-[0.04em] text-brand">
            {eyebrow}
          </p>
        ) : null}
        <h1 className="text-balance text-2xl font-semibold leading-8 tracking-[-0.02em] text-kumo-strong">
          {title}
        </h1>
        <p className="mt-2 max-w-[65ch] text-pretty text-[0.9375rem] leading-6 text-kumo-subtle">
          {description}
        </p>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </header>
  )
}
