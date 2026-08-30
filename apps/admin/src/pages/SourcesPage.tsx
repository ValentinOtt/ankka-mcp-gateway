import { Button, Input } from '@cloudflare/kumo'
import { Database, LockKey, MagnifyingGlass, Plus, ShieldCheck, X } from '@phosphor-icons/react'
import { type FormEvent, useMemo, useState } from 'react'
import { SOURCE_ADDITION_PAUSED_MESSAGE, type SourceDiscovery } from '../api'
import { useGateway } from '../GatewayContext'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'

function annotation(tool: SourceDiscovery['tools'][number]): string {
  const flags = []
  if (tool.readOnlyHint === true) flags.push('read-only hint')
  if (tool.destructiveHint === true) flags.push('destructive hint')
  if (tool.openWorldHint === true) flags.push('open-world hint')
  return flags.length ? flags.join(' · ') : 'No safety annotations'
}

function manualTools(value: string): string[] {
  return [...new Set(value.split(/\r?\n/u).map((tool) => tool.trim()).filter(Boolean))].sort()
}

export function SourcesPage() {
  const {
    clearSourceNotice,
    discoverSource,
    isBusy,
    prepareSourceApply,
    saveSourceDraft,
    sourceNotice,
    sources,
  } = useGateway()
  const [showForm, setShowForm] = useState(false)
  const [label, setLabel] = useState('')
  const [url, setUrl] = useState('')
  const [discovery, setDiscovery] = useState<SourceDiscovery | null>(null)
  const [selected, setSelected] = useState<string[]>([])
  const [manual, setManual] = useState('')
  const [catalogueFilter, setCatalogueFilter] = useState('')
  const [formError, setFormError] = useState<string | null>(null)

  const enabledTools = useMemo(
    () => discovery?.authentication === 'oauth' ? manualTools(manual) : [...selected].sort(),
    [discovery?.authentication, manual, selected],
  )
  const selectedNames = useMemo(() => new Set(selected), [selected])
  const visibleTools = useMemo(() => {
    if (!discovery || discovery.authentication === 'oauth') return []
    const query = catalogueFilter.trim().toLocaleLowerCase()
    if (!query) return discovery.tools
    return discovery.tools.filter((tool) => (
      tool.name.toLocaleLowerCase().includes(query) ||
      tool.title?.toLocaleLowerCase().includes(query) === true ||
      tool.description?.toLocaleLowerCase().includes(query) === true
    ))
  }, [catalogueFilter, discovery])

  if (!sources) return null
  const installationEnabled = sources.installationEnabled === true

  const inspect = async () => {
    if (!installationEnabled) return
    setFormError(null)
    try {
      const next = await discoverSource(url.trim())
      setDiscovery(next)
      setSelected(next.tools.filter((tool) => tool.defaultSelected === true).map((tool) => tool.name))
      setManual('')
      setCatalogueFilter('')
      setUrl(next.endpoint)
    } catch (error) { setFormError(error instanceof Error ? error.message : 'Tool discovery failed.') }
  }

  const save = async (event: FormEvent) => {
    event.preventDefault()
    if (!installationEnabled) return
    if (!discovery || label.trim().length < 2 || enabledTools.length === 0) {
      setFormError('Give the source a name and select at least one exact tool.')
      return
    }
    setFormError(null)
    try {
      await saveSourceDraft({
        label: label.trim(),
        url: discovery.endpoint,
        authMode: discovery.authentication,
        enabledTools,
      })
      setLabel('')
      setUrl('')
      setDiscovery(null)
      setSelected([])
      setManual('')
      setCatalogueFilter('')
      setShowForm(false)
    } catch (error) { setFormError(error instanceof Error ? error.message : 'The source draft could not be saved.') }
  }

  const authorize = async (sourceId: string) => {
    if (!installationEnabled) return
    try {
      const prepared = await prepareSourceApply(sourceId)
      window.location.assign(prepared.handoffUrl)
    } catch { /* The provider keeps the safe error visible. */ }
  }

  return (
    <div>
      <PageHeader
        eyebrow="Customer-owned catalogue"
        title="Sources"
        description={installationEnabled ? 'Discover MCP tool catalogues, save deny-by-default allowlists, and apply each draft with a fresh one-time Cloudflare authorization.' : 'Review your existing MCP sources and their exact tool allowlists. New-source installation is paused in this release.'}
        action={
          <Button variant="primary" className="pressable" disabled={!installationEnabled} onClick={() => setShowForm((visible) => !visible)}>
            {showForm ? <X size={16} /> : <Plus size={16} weight="bold" />}
            {showForm ? 'Close' : 'Add source'}
          </Button>
        }
      />

      {!installationEnabled ? <p role="status" className="notice-banner notice-neutral mt-6">{SOURCE_ADDITION_PAUSED_MESSAGE} Saved drafts are retained but cannot be applied.</p> : null}

      {sourceNotice ? (
        <div role="status" className={`notice-banner mt-6 notice-${sourceNotice.tone}`}>
          <p>{sourceNotice.message}</p>
          <button type="button" className="pressable" aria-label="Dismiss source notice" onClick={clearSourceNotice}><X size={14} /></button>
        </div>
      ) : null}

      {showForm && installationEnabled ? (
        <section className="surface-card mt-7 p-5 sm:p-6" aria-labelledby="add-source-title">
          <div className="flex flex-col justify-between gap-4 border-b border-kumo-line pb-5 sm:flex-row sm:items-start">
            <div>
              <h2 id="add-source-title" className="text-base font-semibold text-kumo-strong">Add an MCP source</h2>
              <p className="mt-1 max-w-[65ch] text-sm leading-6 text-kumo-subtle">The gateway reads the public catalogue or verifies the standard OAuth challenge. This form never accepts credentials.</p>
            </div>
            <StatusPill tone="attention">Exact tools only</StatusPill>
          </div>

          <form className="mt-6" onSubmit={save}>
            <div className="grid gap-5 sm:grid-cols-2">
              <Input className="w-full" label="Source name" placeholder="Company knowledge" value={label} maxLength={80} onChange={(event) => setLabel(event.target.value)} />
              <Input className="w-full" label="MCP URL" type="url" inputMode="url" placeholder="https://knowledge.example.com/mcp" value={url} onChange={(event) => { setUrl(event.target.value); setDiscovery(null); setCatalogueFilter('') }} />
            </div>
            <div className="mt-4 flex flex-wrap items-center gap-3">
              <Button type="button" variant="secondary" className="pressable" loading={isBusy} onClick={() => void inspect()}>
                <MagnifyingGlass size={16} /> Inspect source
              </Button>
              <p className="text-xs leading-5 text-kumo-subtle">Source-authored names, descriptions, and safety hints are untrusted review aids.</p>
            </div>

            {formError ? <p className="field-error" role="alert">{formError}</p> : null}

            {discovery ? (
              <section className="mt-6 border-t border-kumo-line pt-6" aria-labelledby="catalogue-title">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h3 id="catalogue-title" className="text-sm font-semibold text-kumo-strong">Tool allowlist</h3>
                    <p className="mt-1 text-xs leading-5 text-kumo-subtle">
                      {discovery.authentication === 'oauth'
                        ? 'Standard OAuth protection detected. Enter independently verified exact tool names.'
                        : `${discovery.tools.length} tools discovered with MCP ${discovery.protocolVersion ?? 'compatible protocol'}.`}
                    </p>
                  </div>
                  <StatusPill tone="waiting">{discovery.authentication === 'oauth' ? 'OAuth protected' : 'Public endpoint'}</StatusPill>
                </div>

                {discovery.authentication === 'oauth' ? (
                  <div className="mt-5">
                    <p className="mb-5 rounded-xl border border-kumo-line bg-kumo-tint/55 p-4 text-xs leading-5 text-kumo-subtle">
                      <strong className="block text-sm text-kumo-strong">One Gateway login</strong>
                      A customer operator connects this source once in Cloudflare. Team members are not asked for a second source login.
                    </p>
                    <label htmlFor="manual-tools" className="mb-1.5 block text-sm font-medium text-kumo-default">Exact tool names</label>
                    <textarea id="manual-tools" className="text-input min-h-32 w-full font-mono" placeholder={'search\nfetch_document'} value={manual} onChange={(event) => setManual(event.target.value)} />
                    <p className="mt-1.5 text-xs leading-5 text-kumo-subtle">One exact tool per line. Wildcards are never accepted.</p>
                  </div>
                ) : (
                  <div className="mt-5">
                    <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
                      <label className="block" htmlFor="catalogue-filter">
                        <span className="mb-1.5 block text-sm font-medium text-kumo-default">Filter tools</span>
                        <input
                          id="catalogue-filter"
                          className="text-input w-full"
                          type="search"
                          placeholder="Name, title, or description"
                          value={catalogueFilter}
                          onChange={(event) => setCatalogueFilter(event.target.value)}
                        />
                      </label>
                      <div className="flex flex-wrap gap-2">
                        <Button
                          type="button"
                          variant="secondary"
                          className="pressable"
                          disabled={visibleTools.length === 0}
                          onClick={() => setSelected((current) => [
                            ...new Set([...current, ...visibleTools.map((tool) => tool.name)]),
                          ])}
                        >Select shown</Button>
                        <Button
                          type="button"
                          variant="secondary"
                          className="pressable"
                          disabled={visibleTools.every((tool) => !selectedNames.has(tool.name))}
                          onClick={() => {
                            const visibleNames = new Set(visibleTools.map((tool) => tool.name))
                            setSelected((current) => current.filter((name) => !visibleNames.has(name)))
                          }}
                        >Clear shown</Button>
                      </div>
                    </div>
                    <p className="mt-2 text-xs text-kumo-subtle">
                      Showing {visibleTools.length} of {discovery.tools.length} tools; {selected.length} selected.
                    </p>
                    <div className="mt-4 grid max-h-[38rem] gap-3 overflow-y-auto pr-1" tabIndex={0} aria-label="Discovered tools">
                      {visibleTools.map((tool) => (
                        <label key={tool.name} className="tool-option-card">
                          <input
                            type="checkbox"
                            checked={selectedNames.has(tool.name)}
                            onChange={(event) => setSelected((current) => event.target.checked
                              ? [...new Set([...current, tool.name])]
                              : current.filter((name) => name !== tool.name))}
                          />
                          <span className="min-w-0">
                            <span className="flex flex-wrap items-baseline gap-x-2"><strong className="text-sm text-kumo-strong">{tool.title || tool.name}</strong><code className="text-xs text-kumo-subtle">{tool.name}</code></span>
                            <span className="mt-1 block text-xs leading-5 text-kumo-subtle">{tool.description || 'No description supplied by this MCP server.'}</span>
                            <small className="mt-1 block text-[0.6875rem] text-kumo-inactive">{annotation(tool)}</small>
                          </span>
                        </label>
                      ))}
                      {visibleTools.length === 0 ? (
                        <p className="rounded-lg border border-dashed border-kumo-line p-5 text-center text-sm text-kumo-subtle">No tools match this filter.</p>
                      ) : null}
                    </div>
                  </div>
                )}

                <div className="mt-5 flex items-center gap-3 border-t border-kumo-line pt-5">
                  <Button type="submit" variant="primary" className="pressable" loading={isBusy} disabled={enabledTools.length === 0}>Save draft</Button>
                  <span className="text-xs text-kumo-subtle">{enabledTools.length} exact tool{enabledTools.length === 1 ? '' : 's'} selected</span>
                </div>
              </section>
            ) : null}
          </form>
        </section>
      ) : null}

      <section className="mt-7" aria-label="MCP sources">
        {sources.sources.length === 0 ? (
          <div className="empty-card">
            <div className="flex size-12 items-center justify-center rounded-2xl bg-kumo-tint text-kumo-subtle"><Database size={23} /></div>
            <h2 className="mt-4 text-base font-semibold text-kumo-strong">No sources yet</h2>
            <p className="mt-1.5 max-w-[48ch] text-pretty text-sm leading-6 text-kumo-subtle">{installationEnabled ? 'Start with one useful MCP server and an exact allowlist you have independently verified as read-only.' : 'Source installation will be available in a compatible gateway release.'}</p>
            <Button variant="secondary" className="pressable mt-5" disabled={!installationEnabled} onClick={() => setShowForm(true)}><Plus size={16} weight="bold" /> Add your first source</Button>
          </div>
        ) : (
          <div className="grid gap-3">
            {sources.sources.map((source) => (
              <article key={source.id} className="surface-card px-5 py-4 sm:px-6 sm:py-5">
                <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2.5">
                      <h2 className="text-sm font-semibold text-kumo-strong">{source.label}</h2>
                      <StatusPill tone={source.status === 'installed' ? 'ready' : 'attention'}>{source.status === 'installed' ? 'Installed' : 'Saved draft'}</StatusPill>
                      <StatusPill tone="waiting">{source.authMode === 'oauth'
                        ? source.onBehalfOfUser ? 'Legacy user-bound OAuth' : 'Operator-connected OAuth'
                        : 'Public'}</StatusPill>
                    </div>
                    <p className="mt-1.5 truncate font-mono text-xs text-kumo-subtle">{source.url}</p>
                  </div>
                  {source.status === 'draft' ? (
                    <Button variant="primary" className="pressable shrink-0" disabled={!installationEnabled} loading={isBusy} onClick={() => void authorize(source.id)}>{installationEnabled ? 'Authorize and apply' : 'Installation unavailable'}</Button>
                  ) : null}
                </div>
                <details className="mt-4 border-t border-kumo-line pt-4">
                  <summary className="cursor-pointer text-xs font-medium text-kumo-subtle">
                    {source.enabledTools.length} exact tool{source.enabledTools.length === 1 ? '' : 's'}
                  </summary>
                  <div className="mt-3 flex max-h-52 flex-wrap gap-2 overflow-y-auto pr-1">
                    {source.enabledTools.map((tool) => <code key={tool} className="tool-chip">{tool}</code>)}
                  </div>
                </details>
              </article>
            ))}
          </div>
        )}
      </section>

      <aside className="mt-5 grid gap-3 rounded-xl border border-kumo-line bg-kumo-tint/55 p-4 sm:grid-cols-2">
        <div className="flex gap-3"><ShieldCheck size={18} className="mt-0.5 shrink-0 text-success-strong" weight="fill" /><p className="text-xs leading-5 text-kumo-subtle"><strong className="text-kumo-strong">Deny by default</strong><br />Only the frozen exact names are mapped.</p></div>
        <div className="flex gap-3"><LockKey size={18} className="mt-0.5 shrink-0 text-kumo-subtle" /><p className="text-xs leading-5 text-kumo-subtle"><strong className="text-kumo-strong">No credential forwarding</strong><br />Source OAuth credentials remain inside Cloudflare.</p></div>
      </aside>
    </div>
  )
}
