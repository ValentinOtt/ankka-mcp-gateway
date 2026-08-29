import { Button } from '@cloudflare/kumo'
import { ArrowSquareOut, Cloud, Database, LockKey, ShieldCheck, Trash } from '@phosphor-icons/react'
import { Link } from '@tanstack/react-router'
import { useEffect, useRef } from 'react'
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
  const { isBusy, isLoading, prepareTeardownAction, reload, sources, status, update } = useGateway()
  const teardownSection = useRef<HTMLElement>(null)
  const teardownRequested = new URLSearchParams(window.location.search).get('teardown') === 'review'
  useEffect(() => {
    if (!teardownRequested) return
    teardownSection.current?.focus({ preventScroll: true })
    teardownSection.current?.scrollIntoView?.({ behavior: 'smooth', block: 'center' })
  }, [teardownRequested])
  if (!status || !sources) return null
  const mcpUrl = safeMcpUrl(status.gateway.mcpUrl)
  const installed = sources.sources.filter((source) => source.status === 'installed').length
  const drafts = sources.sources.length - installed

  return (
    <div>
      <PageHeader
        eyebrow="Customer-owned gateway"
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
            Cloudflare owns the runtime, login surface, policies, DNS, credentials, and logs.
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

        <Link to="/updates" className="surface-card group block p-5 no-underline sm:p-6">
          <div className="flex items-center justify-between gap-3">
            <div className="flex size-9 items-center justify-center rounded-lg bg-kumo-tint text-kumo-subtle"><Cloud size={17} /></div>
            <StatusPill tone={update?.status === 'available' ? 'attention' : update?.status === 'unavailable' ? 'waiting' : 'ready'}>
              {update?.status === 'available' ? 'Update available' : update?.status === 'unavailable' ? 'Channel unavailable' : 'Up to date'}
            </StatusPill>
          </div>
          <h2 className="mt-5 text-base font-semibold text-kumo-strong">Software updates</h2>
          <p className="mt-1.5 text-sm leading-6 text-kumo-subtle">Review signed releases, update safely, or return to the retained previous Worker version.</p>
        </Link>
      </section>

      <section
        ref={teardownSection}
        tabIndex={-1}
        className="mt-8 rounded-2xl border border-red-200 bg-red-50/60 p-5 outline-none sm:p-6"
        aria-labelledby="teardown-title"
      >
        <div className="flex flex-col gap-5 sm:flex-row sm:items-center sm:justify-between">
          <div className="max-w-2xl">
            <div className="flex items-center gap-2 text-red-800">
              <Trash size={18} />
              <h2 id="teardown-title" className="text-base font-semibold">Teardown gateway</h2>
            </div>
            <p className="mt-2 text-sm leading-6 text-red-900/75">
              Generate a one-time receipt proof, then review the exact zero-write removal plan in the signed installer. Cloudflare authorization is requested only after that review.
            </p>
          </div>
          <Button
            variant="secondary"
            className="pressable shrink-0 border-red-300 text-red-800"
            loading={isBusy}
            onClick={() => void prepareTeardownAction()
              .then((action) => window.location.assign(action.handoffUrl))
              .catch(() => undefined)}
          >
            Review teardown plan
          </Button>
        </div>
      </section>
    </div>
  )
}
