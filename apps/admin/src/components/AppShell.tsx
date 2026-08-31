import { ArrowUpRight, Database, GearSix, Users, WarningCircle, X } from '@phosphor-icons/react'
import { Link, Outlet } from '@tanstack/react-router'
import { Loader } from '@cloudflare/kumo'
import { Button } from './Button'
import type { ComponentType } from 'react'
import { useGateway } from '../GatewayContext'
import { BrandMark } from './BrandMark'

type AppPath = '/sources' | '/team' | '/settings'

interface NavItem {
  to: AppPath
  label: string
  icon: ComponentType<{ size?: number; weight?: 'regular' | 'fill' | 'bold' }>
}

const navigation: NavItem[] = [
  { to: '/sources', label: 'Sources', icon: Database },
  { to: '/team', label: 'Team', icon: Users },
  { to: '/settings', label: 'Settings', icon: GearSix },
]

export function AppShell() {
  const { error, hasLoaded, isLoading, reload, clearError, status, update } = useGateway()

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
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-60 gap-6 bg-sidebar p-3 text-sidebar-ink lg:flex lg:flex-col">
        <div className="-mb-3 grid gap-1 rounded-lg px-2 py-1 text-sidebar-ink">
          <BrandMark className="sidebar-wordmark w-[100%] opacity-40" />
        </div>

        <nav className="flex min-h-0 flex-1 flex-col gap-1" aria-label="Gateway management">
          {navigation.map(({ to, label, icon: Icon }) => (
            <div key={to} className={to === '/settings' ? 'mt-auto pt-4' : undefined}>
              <Link
                to={to}
                activeOptions={{ exact: true }}
                className="nav-item"
                activeProps={{ className: 'nav-item nav-item-active' }}
              >
                <Icon size={18} weight="regular" />
                <span>{label}</span>
              </Link>
            </div>
          ))}
        </nav>

        <div className="border-t border-white/10 px-2 pb-1 pt-4">
          <p className="text-xs font-medium text-sidebar-ink">MCP Gateway</p>
          {status?.release ? (
            <p className="mt-1 truncate text-xs text-sidebar-muted" title={status.release}>
              {status.release}
            </p>
          ) : null}
          {update?.status === 'available' && update.available ? (
            <Link
              to="/settings"
              className="mt-3 flex items-center justify-between gap-2 rounded-lg bg-warning-soft px-3 py-2 text-xs text-warning-strong underline-offset-4 hover:underline"
            >
              <span className="min-w-0">
                <span className="block font-medium">Update available</span>
                <span className="mt-0.5 block break-all">{update.available.release}</span>
              </span>
              <ArrowUpRight size={15} className="shrink-0" aria-hidden="true" />
            </Link>
          ) : null}
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
                activeOptions={{ exact: true }}
                className="mobile-nav-item"
                activeProps={{ className: 'mobile-nav-item mobile-nav-item-active' }}
              >
                {label}
              </Link>
            ))}
          </nav>
        </header>

        <main className="mx-auto min-h-dvh w-full max-w-5xl px-5 py-6 sm:px-8 lg:py-8">
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
