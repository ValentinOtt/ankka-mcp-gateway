import { Button } from '@cloudflare/kumo'
import { ArrowsClockwise, CheckCircle, ClockCounterClockwise, ShieldCheck, X } from '@phosphor-icons/react'
import { useGateway } from '../GatewayContext'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'

export function UpdatesPage() {
  const {
    clearUpdateNotice,
    isBusy,
    prepareRuntimeAction,
    refreshUpdate,
    update,
    updateNotice,
  } = useGateway()
  if (!update) return null

  const authorize = async (operation: 'update' | 'rollback') => {
    try {
      const prepared = await prepareRuntimeAction(operation)
      window.location.assign(prepared.handoffUrl)
    } catch { /* The provider keeps the safe error visible. */ }
  }

  const statusLabel = update.status === 'available' ? 'Update available'
    : update.status === 'unavailable' ? 'Channel unavailable' : 'Up to date'

  return (
    <div>
      <PageHeader
        eyebrow="Signed software"
        title="Updates"
        description="Only signed Worker code and management assets change. Sources, Access policies, DNS, credentials, and Durable Object data remain in your Cloudflare account."
        action={
          <Button variant="secondary" className="pressable" loading={isBusy} onClick={() => void refreshUpdate()}>
            Check again
          </Button>
        }
      />

      {updateNotice ? (
        <div role="status" className={`notice-banner mt-6 notice-${updateNotice.tone}`}>
          <p>{updateNotice.message}</p>
          <button type="button" className="pressable" aria-label="Dismiss update notice" onClick={clearUpdateNotice}><X size={14} /></button>
        </div>
      ) : null}

      <section className="surface-card mt-7 overflow-hidden">
        <div className="flex flex-wrap items-start justify-between gap-4 border-b border-kumo-line px-5 py-5 sm:px-6">
          <div>
            <p className="text-xs font-medium text-kumo-subtle">Gateway runtime</p>
            <h2 className="mt-1 text-base font-semibold text-kumo-strong">Stable release channel</h2>
          </div>
          <StatusPill tone={update.status === 'available' ? 'attention' : update.status === 'unavailable' ? 'waiting' : 'ready'}>
            {statusLabel}
          </StatusPill>
        </div>

        <dl className="grid gap-px bg-kumo-line sm:grid-cols-3">
          <div className="bg-white px-5 py-5 sm:px-6">
            <dt className="text-xs font-medium text-kumo-subtle">Installed</dt>
            <dd className="mt-1.5 font-mono text-sm text-kumo-strong">{update.current?.release ?? 'Unavailable'}</dd>
          </div>
          <div className="bg-white px-5 py-5 sm:px-6">
            <dt className="text-xs font-medium text-kumo-subtle">Channel</dt>
            <dd className="mt-1.5 font-mono text-sm text-kumo-strong">{update.available?.release ?? update.current?.release ?? 'Unavailable'}</dd>
          </div>
          <div className="bg-white px-5 py-5 sm:px-6">
            <dt className="text-xs font-medium text-kumo-subtle">Classification</dt>
            <dd className="mt-1.5 text-sm text-kumo-strong">
              {update.available?.classification.kind === 'normal' ? 'Normal update' : update.status === 'unavailable' ? 'Unverified' : 'No change'}
            </dd>
          </div>
        </dl>

        <div className="px-5 py-5 sm:px-6">
          {update.status === 'unavailable' ? (
            <p className="text-sm leading-6 text-kumo-subtle">The signed channel could not be verified. Gateway management and an already available rollback remain usable.</p>
          ) : update.available?.notes?.length ? (
            <ul className="space-y-2 text-sm leading-6 text-kumo-subtle">
              {update.available.notes.map((note) => <li key={note} className="flex gap-2"><CheckCircle size={16} className="mt-1 shrink-0 text-success-strong" />{note}</li>)}
            </ul>
          ) : (
            <p className="text-sm leading-6 text-kumo-subtle">The installed runtime matches the {update.channel} channel.</p>
          )}

          <div className="mt-5 flex flex-wrap gap-2 border-t border-kumo-line pt-5">
            {update.status === 'available' ? (
              <Button variant="primary" className="pressable" loading={isBusy} onClick={() => void authorize('update')}>
                <ArrowsClockwise size={16} /> Review and authorize update
              </Button>
            ) : null}
            {update.rollback.available ? (
              <Button variant="secondary" className="pressable" disabled={isBusy} onClick={() => void authorize('rollback')}>
                <ClockCounterClockwise size={16} /> Review rollback to {update.rollback.release}
              </Button>
            ) : null}
          </div>
        </div>
      </section>

      <aside className="mt-5 flex gap-3 rounded-xl border border-kumo-line bg-kumo-tint/55 p-4">
        <ShieldCheck size={18} className="mt-0.5 shrink-0 text-success-strong" weight="fill" />
        <p className="text-xs leading-5 text-kumo-subtle"><strong className="text-kumo-strong">Normal update boundary:</strong> the candidate is staged at 0%, probed at its exact version, then activated. Durable Object data is never rolled back.</p>
      </aside>
    </div>
  )
}
