import { Button } from '@cloudflare/kumo'
import { ArrowSquareOut, Cloud, Database, GearSix, LockKey, ShieldCheck } from '@phosphor-icons/react'
import { Link } from '@tanstack/react-router'
import { useGateway } from '../GatewayContext'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'

function safeMcpUrl(value: string | undefined): string | null {
  try {
    const url = new URL(value ?? '')
    return url.protocol === 'https:' && !url.username && !url.password ? url.href : null
  } catch { return null }
}

export function OverviewPage() {
  const { isLoading, reload, sources, status, update } = useGateway()
  if (!status || !sources) return null
  const mcpUrl = safeMcpUrl(status.gateway.mcpUrl)
  const installed = sources.sources.filter((source) => source.status === 'installed').length
  const drafts = sources.sources.length - installed

  return (
    <div>
      <PageHeader
        eyebrow="Your gateway"
        title={status.gateway.name}
        description="Manage approved MCP sources and software updates from the Worker running inside your Cloudflare account. MCP source credentials stay in Cloudflare, and the gateway sends no telemetry to Ankka."
        action={
          <Button variant="secondary" className="pressable" loading={isLoading} onClick={() => void reload()}>
            Refresh
          </Button>
        }
      />

      <section className="mt-8 grid gap-5 lg:grid-cols-[minmax(0,1.45fr)_minmax(280px,0.85fr)]">
        <article className="surface-card p-5 sm:p-6">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <p className="text-xs font-medium text-kumo-subtle">Gateway endpoint</p>
              <h2 className="mt-1 text-lg font-semibold tracking-[-0.02em] text-kumo-strong">Ready for your agents</h2>
            </div>
            <StatusPill tone="ready">Ready</StatusPill>
          </div>

          <dl className="mt-6 grid gap-5 border-y border-kumo-line py-5 sm:grid-cols-2">
            <div>
              <dt className="text-xs font-medium text-kumo-subtle">Hostname</dt>
              <dd className="mt-1 truncate font-mono text-sm text-kumo-strong">{status.gateway.hostname}</dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-kumo-subtle">Installed release</dt>
              <dd className="mt-1 font-mono text-sm text-kumo-strong">{status.release}</dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-kumo-subtle">Capability</dt>
              <dd className="mt-1 text-sm text-kumo-strong">Read-only intent</dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-kumo-subtle">Portal users</dt>
              <dd className="mt-1 text-sm text-kumo-strong">
                {status.access.administratorCount + status.access.memberCount}
              </dd>
            </div>
          </dl>

          {mcpUrl ? (
            <a className="mt-5 inline-flex items-center gap-2 text-sm font-medium text-brand no-underline" href={mcpUrl} rel="noreferrer">
              Open MCP endpoint <ArrowSquareOut size={15} />
            </a>
          ) : null}
        </article>

        <aside className="surface-card p-5 sm:p-6">
          <div className="flex size-10 items-center justify-center rounded-xl bg-brand-soft text-brand-strong">
            <Cloud size={20} weight="fill" />
          </div>
          <h2 className="mt-5 text-lg font-semibold tracking-[-0.02em] text-kumo-strong">Your account stays in control</h2>
          <p className="mt-2 text-pretty text-sm leading-6 text-kumo-subtle">
            Your runtime, login settings, policies, DNS, credentials, and logs stay in your Cloudflare account.
          </p>
          <div className="mt-6 space-y-4 border-t border-kumo-line pt-5">
            <div className="flex gap-3">
              <LockKey size={17} className="mt-0.5 shrink-0 text-kumo-subtle" />
              <p className="text-xs leading-5 text-kumo-subtle"><strong className="text-kumo-strong">MCP source credentials</strong><br />Never stored by Ankka</p>
            </div>
            <div className="flex gap-3">
              <ShieldCheck size={17} className="mt-0.5 shrink-0 text-kumo-subtle" />
              <p className="text-xs leading-5 text-kumo-subtle"><strong className="text-kumo-strong">Telemetry</strong><br />No Ankka telemetry</p>
            </div>
          </div>
        </aside>
      </section>

      <section className="mt-5 grid gap-5 sm:grid-cols-2">
        <Link to="/sources" className="surface-card group block p-5 no-underline sm:p-6">
          <div className="flex items-center justify-between gap-3">
            <div className="flex size-9 items-center justify-center rounded-lg bg-kumo-tint text-kumo-subtle"><Database size={17} /></div>
            <StatusPill tone={drafts > 0 ? 'attention' : installed > 0 ? 'ready' : 'waiting'}>
              {drafts > 0 ? `${drafts} draft${drafts === 1 ? '' : 's'}` : `${installed} installed`}
            </StatusPill>
          </div>
          <h2 className="mt-5 text-base font-semibold text-kumo-strong">MCP sources</h2>
          <p className="mt-1.5 text-sm leading-6 text-kumo-subtle">Discover catalogues, freeze exact allowlists, and apply drafts with one-time authorization.</p>
        </Link>

        <Link to="/settings" className="surface-card group block p-5 no-underline sm:p-6">
          <div className="flex items-center justify-between gap-3">
            <div className="flex size-9 items-center justify-center rounded-lg bg-kumo-tint text-kumo-subtle"><GearSix size={17} /></div>
            <StatusPill tone={update?.status === 'available' ? 'attention' : update?.status === 'unavailable' ? 'waiting' : 'ready'}>
              {update?.status === 'available' ? 'Update available' : update?.status === 'unavailable' ? 'Channel unavailable' : 'Up to date'}
            </StatusPill>
          </div>
          <h2 className="mt-5 text-base font-semibold text-kumo-strong">Gateway settings</h2>
          <p className="mt-1.5 text-sm leading-6 text-kumo-subtle">Review signed releases, roll back safely, or manage the gateway lifecycle.</p>
        </Link>
      </section>
    </div>
  )
}
