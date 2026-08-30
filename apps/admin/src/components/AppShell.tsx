import { ArrowsClockwise, Cloud, Database, House, Users, WarningCircle, X } from '@phosphor-icons/react'
import { Link, Outlet } from '@tanstack/react-router'
import { Button, Loader } from '@cloudflare/kumo'
import type { ComponentType } from 'react'
import { useGateway } from '../GatewayContext'
import { BrandMark } from './BrandMark'

type AppPath = '/' | '/sources' | '/team' | '/updates'

interface NavItem {
  to: AppPath
  label: string
  icon: ComponentType<{ size?: number; weight?: 'regular' | 'fill' | 'bold' }>
}

const navigation: NavItem[] = [
  { to: '/', label: 'Overview', icon: House },
  { to: '/sources', label: 'Sources', icon: Database },
  { to: '/team', label: 'Team', icon: Users },
  { to: '/updates', label: 'Updates', icon: ArrowsClockwise },
]

export function AppShell() {
  const { error, hasLoaded, isLoading, reload, clearError, status } = useGateway()

  if (isLoading && !hasLoaded) {
    return (
      <div className="flex min-h-dvh items-center justify-center bg-canvas px-5">
        <div className="flex flex-col items-center text-center">
          <BrandMark className="text-brand" />
          <Loader size="lg" className="mt-5" />
          <p className="mt-3 text-sm text-kumo-subtle">Loading your gateway…</p>
        </div>
      </div>
    )
  }

  if (error && !hasLoaded) {
    return (
      <div className="flex min-h-dvh items-center justify-center bg-canvas px-5">
        <div className="surface-card w-full max-w-md p-6 text-center">
          <div className="mx-auto flex size-11 items-center justify-center rounded-xl bg-danger-soft text-danger">
            <WarningCircle size={21} weight="fill" />
          </div>
          <h1 className="mt-4 text-lg font-semibold text-kumo-strong">Couldn’t load the gateway</h1>
          <p className="mt-2 text-pretty text-sm leading-6 text-kumo-subtle">{error}</p>
          <Button variant="primary" className="pressable mt-5" onClick={() => void reload()}>
            Try again
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-dvh bg-canvas text-kumo-default">
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-60 bg-sidebar px-2 py-5 text-sidebar-ink lg:flex lg:flex-col">
        <div className="px-2 py-1">
          <BrandMark className="w-[136px] opacity-70" />
          <p className="mt-3 text-xs font-medium text-sidebar-ink">MCP Gateway</p>
        </div>

        <nav className="mt-8" aria-label="Gateway management">
          {navigation.map(({ to, label, icon: Icon }) => (
            <Link
              key={to}
              to={to}
              activeOptions={{ exact: to === '/' }}
              className="nav-item"
              activeProps={{ className: 'nav-item nav-item-active' }}
            >
              <Icon size={17} weight="regular" />
              <span>{label}</span>
            </Link>
          ))}
        </nav>

        <div className="mx-2 mt-auto rounded-lg border border-white/10 bg-white/5 p-3">
          <div className="flex items-center gap-2.5">
            <Cloud size={18} className="text-sidebar-accent" weight="fill" />
            <div className="min-w-0">
              <p className="text-xs font-medium text-sidebar-ink">Customer-owned</p>
              <p className="mt-0.5 truncate text-xs text-sidebar-muted">
                {status?.gateway.hostname ?? 'Cloudflare account'}
              </p>
            </div>
          </div>
        </div>
      </aside>

      <div className="lg:pl-60">
        <header className="sticky top-0 z-10 bg-sidebar px-4 py-3 text-sidebar-ink lg:hidden">
          <div className="flex items-center gap-3">
            <BrandMark className="text-sidebar-ink opacity-75" />
            <p className="border-l border-white/15 pl-3 text-xs font-medium text-sidebar-ink">MCP Gateway</p>
          </div>
          <nav className="scrollbar-none -mx-1 mt-3 flex gap-1 overflow-x-auto" aria-label="Gateway management">
            {navigation.map(({ to, label }) => (
              <Link
                key={to}
                to={to}
                activeOptions={{ exact: to === '/' }}
                className="mobile-nav-item"
                activeProps={{ className: 'mobile-nav-item mobile-nav-item-active' }}
              >
                {label}
              </Link>
            ))}
          </nav>
        </header>

        <main className="mx-auto min-h-dvh w-full max-w-[1180px] px-5 py-8 sm:px-8 sm:py-10 xl:px-10">
          {error ? (
            <div role="alert" className="mb-5 flex items-start gap-3 rounded-xl border border-danger/15 bg-danger-soft px-4 py-3 text-danger">
              <WarningCircle size={17} className="mt-0.5 shrink-0" weight="fill" />
              <p className="min-w-0 flex-1 text-sm leading-5">{error}</p>
              <button type="button" className="pressable inline-flex size-6 shrink-0 items-center justify-center rounded-md" aria-label="Dismiss error" onClick={clearError}>
                <X size={14} weight="bold" />
              </button>
            </div>
          ) : null}
          <Outlet />
        </main>
      </div>
    </div>
  )
}
