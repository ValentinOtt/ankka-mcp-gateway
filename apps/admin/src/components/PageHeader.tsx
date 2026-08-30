import type { ReactNode } from 'react'

interface PageHeaderProps {
  title: string
  description?: string
  action?: ReactNode
}

export function PageHeader({ title, description, action }: PageHeaderProps) {
  return (
    <header className="flex flex-col justify-between gap-5 sm:flex-row sm:items-start">
      <div>
        <h1 className="text-balance text-2xl font-semibold leading-8 tracking-[-0.02em] text-kumo-strong">
          {title}
        </h1>
        {description ? (
          <p className="mt-2 max-w-[65ch] text-pretty text-[0.9375rem] leading-6 text-kumo-subtle">
            {description}
          </p>
        ) : null}
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </header>
  )
}
