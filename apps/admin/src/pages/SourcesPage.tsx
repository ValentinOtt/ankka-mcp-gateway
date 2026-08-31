import { Input } from '@cloudflare/kumo'
import { Button } from '../components/Button'
import { ArrowRight, Database, GlobeSimple, MagnifyingGlass, Plus, X } from '@phosphor-icons/react'
import { type FormEvent, useMemo, useState } from 'react'
import { GOOGLE_SHARED_OAUTH_BLOCK_MESSAGE, SOURCE_ADDITION_PAUSED_MESSAGE, type SourceDiscovery } from '../api'
import { SOURCE_CATALOG, type SourceCatalog, type SourceCatalogSource } from '../catalog'
import { useGateway } from '../GatewayContext'
import { GatewayEndpoint } from '../components/GatewayEndpoint'
import { PageHeader } from '../components/PageHeader'
import { NativeConnectorGuides } from '../components/NativeConnectorGuides'
import { StatusPill } from '../components/StatusPill'
import { SourceList } from '../components/SourceList'

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

interface SourcesPageProps {
  catalog?: SourceCatalog
}

export function SourcesPage({ catalog = SOURCE_CATALOG }: SourcesPageProps) {
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
  const [sourceMode, setSourceMode] = useState<'catalog' | 'custom'>(catalog.sources.length > 0 ? 'catalog' : 'custom')
  const [catalogSourceId, setCatalogSourceId] = useState<string | null>(null)
  const [label, setLabel] = useState('')
  const [url, setUrl] = useState('')
  const [discovery, setDiscovery] = useState<SourceDiscovery | null>(null)
  const [selected, setSelected] = useState<string[]>([])
  const [manual, setManual] = useState('')
  const [catalogueFilter, setCatalogueFilter] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const catalogSource = useMemo(
    () => catalog.sources.find((source) => source.sourceId === catalogSourceId) ?? null,
    [catalog.sources, catalogSourceId],
  )

  const enabledTools = useMemo(
    () => discovery?.authentication === 'oauth' && discovery.tools.length === 0 ? manualTools(manual) : [...selected].sort(),
    [discovery, manual, selected],
  )
  const selectedNames = useMemo(() => new Set(selected), [selected])
  const missingRecommendedTools = useMemo(() => {
    if (!catalogSource || !discovery || discovery.tools.length === 0) return []
    const discoveredNames = new Set(discovery.tools.map((tool) => tool.name))
    return catalogSource.implementation.recommendedTools.filter((tool) => !discoveredNames.has(tool))
  }, [catalogSource, discovery])
  const visibleTools = useMemo(() => {
    if (!discovery) return []
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

  const clearDraftForm = () => {
    setCatalogSourceId(null)
    setLabel('')
    setUrl('')
    setDiscovery(null)
    setSelected([])
    setManual('')
    setCatalogueFilter('')
    setFormError(null)
  }

  const chooseCatalogSource = (source: SourceCatalogSource) => {
    clearDraftForm()
    setSourceMode('catalog')
    setCatalogSourceId(source.sourceId)
    setLabel(source.displayName)
    setUrl(source.implementation.deployment.url)
  }

  const chooseSourceMode = (mode: 'catalog' | 'custom') => {
    if (sourceMode === mode) return
    clearDraftForm()
    setSourceMode(mode)
  }

  const inspect = async () => {
    if (!installationEnabled) return
    setFormError(null)
    setDiscovery(null)
    setSelected([])
    setManual('')
    setCatalogueFilter('')
    try {
      const next = await discoverSource(url.trim())
      if (catalogSource && next.endpoint !== catalogSource.implementation.deployment.url) {
        setDiscovery(null)
        setFormError('The inspected endpoint no longer matches this reviewed catalog entry. Choose a different source or use the custom URL flow.')
        return
      }
      if (catalogSource && next.authentication !== catalogSource.implementation.connection.authMode) {
        setDiscovery(null)
        setFormError('The endpoint authentication no longer matches this reviewed catalog entry. The preset cannot be used until it is reviewed again.')
        return
      }
      const recommended = catalogSource?.implementation.recommendedTools ?? []
      const recommendedNames = new Set(recommended)
      setDiscovery(next)
      setSelected(next.tools
        .filter((tool) => !next.connectionBlock && (catalogSource ? recommendedNames.has(tool.name) : tool.defaultSelected === true))
        .map((tool) => tool.name))
      setManual(catalogSource && next.authentication === 'oauth' ? recommended.join('\n') : '')
      setCatalogueFilter('')
      setUrl(next.endpoint)
    } catch (error) { setFormError(error instanceof Error ? error.message : 'Tool discovery failed.') }
  }

  const save = async (event: FormEvent) => {
    event.preventDefault()
    if (!installationEnabled) return
    if (discovery?.connectionBlock) {
      setFormError(GOOGLE_SHARED_OAUTH_BLOCK_MESSAGE)
      return
    }
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
      clearDraftForm()
      setSourceMode(catalog.sources.length > 0 ? 'catalog' : 'custom')
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
        title="Sources"
        action={
          <Button variant="primary" className="pressable" disabled={!installationEnabled} onClick={() => setShowForm((visible) => !visible)}>
            {showForm ? <X size={16} /> : <Plus size={16} weight="bold" />}
            {showForm ? 'Close' : 'Add source'}
          </Button>
        }
      />

      <GatewayEndpoint />

      {!installationEnabled ? <p role="status" className="notice-banner notice-warning mt-6">{SOURCE_ADDITION_PAUSED_MESSAGE} Saved drafts are retained but cannot be applied.</p> : null}
      {installationEnabled ? <p className="notice-banner notice-warning mt-6">Before authorizing: once source provisioning starts, automatic gateway removal and rollback below this runtime release are unavailable. Saving a draft does not activate this restriction.</p> : null}

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
              <h2 id="add-source-title" className="text-base font-semibold text-subheading">Add an MCP source</h2>
              <p className="mt-1 max-w-[65ch] text-sm leading-6 text-kumo-subtle">Choose allowed tools. New sources start with nobody assigned; grant access in Team. Do not enter credentials here.</p>
            </div>
            <StatusPill tone="attention">Exact tools only</StatusPill>
          </div>

          <NativeConnectorGuides />

          <form className="mt-6" onSubmit={save}>
            <fieldset>
              <legend className="text-sm font-medium text-kumo-default">Start with</legend>
              <div className="mt-2 flex flex-wrap gap-2">
                <button
                  type="button"
                  className="source-mode-button pressable"
                  aria-pressed={sourceMode === 'catalog'}
                  disabled={isBusy || catalog.sources.length === 0}
                  onClick={() => chooseSourceMode('catalog')}
                >
                  Reviewed catalog
                  {catalog.sources.length > 0 ? <span>{catalog.sources.length}</span> : null}
                </button>
                <button
                  type="button"
                  className="source-mode-button pressable"
                  aria-pressed={sourceMode === 'custom'}
                  disabled={isBusy}
                  onClick={() => chooseSourceMode('custom')}
                >
                  <GlobeSimple size={15} /> Custom MCP URL
                </button>
              </div>
              {catalog.sources.length === 0 ? (
                <p className="mt-2 text-xs leading-5 text-kumo-subtle">No reviewed presets ship in this release. Add a compatible remote MCP endpoint directly.</p>
              ) : null}
            </fieldset>

            {sourceMode === 'catalog' && catalogSource === null ? (
              <div className="mt-5 grid gap-3 sm:grid-cols-2" aria-label="Reviewed source catalog">
                {catalog.sources.map((source) => (
                  <article key={source.sourceId} className="catalog-source-card">
                    <div className="flex flex-wrap gap-2">
                      <StatusPill tone="waiting">{source.implementation.connection.authMode === 'oauth' ? 'OAuth' : 'Public'}</StatusPill>
                    </div>
                    <h3 className="mt-4 text-sm font-semibold text-kumo-strong">{source.displayName}</h3>
                    <p className="mt-1 text-xs leading-5 text-kumo-subtle">{source.description}</p>
                    <p className="mt-3 text-[0.6875rem] text-kumo-inactive">
                      {source.implementation.recommendedTools.length} recommended exact tool{source.implementation.recommendedTools.length === 1 ? '' : 's'}
                    </p>
                    <Button type="button" variant="secondary" className="pressable mt-4" disabled={isBusy} onClick={() => chooseCatalogSource(source)}>
                      Select {source.displayName} <ArrowRight size={15} />
                    </Button>
                  </article>
                ))}
              </div>
            ) : null}

            {catalogSource ? (
              <div className="mt-5 rounded-xl border border-kumo-line bg-kumo-tint/55 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-semibold text-kumo-strong">{catalogSource.displayName}</h3>
                    <p className="mt-1 text-xs leading-5 text-kumo-subtle">
                      Expected {catalogSource.implementation.connection.authMode === 'oauth' ? 'operator-connected OAuth' : 'public access'}. Live inspection must confirm it before you can save.
                    </p>
                  </div>
                  <Button type="button" variant="secondary" className="pressable" disabled={isBusy} onClick={clearDraftForm}>Change source</Button>
                </div>
                <div className="mt-4 flex flex-wrap gap-2" aria-label="Catalog-recommended tools">
                  {catalogSource.implementation.recommendedTools.map((tool) => <code key={tool} className="tool-chip">{tool}</code>)}
                </div>
                <p className="mt-2 text-[0.6875rem] leading-5 text-kumo-inactive">Recommendations are preselected only after inspection. Review every exact name before saving.</p>
              </div>
            ) : null}

            {sourceMode === 'custom' || catalogSource ? (
              <>
                <div className="mt-5 grid gap-5 sm:grid-cols-2">
                  <Input className="w-full" label="Source name" placeholder="Company knowledge" value={label} maxLength={80} onChange={(event) => setLabel(event.target.value)} />
                  <Input
                    className="w-full"
                    label="MCP URL"
                    type="url"
                    inputMode="url"
                    placeholder="https://knowledge.example.com/mcp"
                    value={url}
                    readOnly={catalogSource !== null}
                    onChange={(event) => { setUrl(event.target.value); setDiscovery(null); setCatalogueFilter('') }}
                  />
                </div>
                <div className="mt-4 flex flex-wrap items-center gap-3">
                  <Button type="button" variant="secondary" className="pressable" loading={isBusy} onClick={() => void inspect()}>
                    <MagnifyingGlass size={16} /> Inspect source
                  </Button>
                  <p className="text-xs leading-5 text-kumo-subtle">Source-authored names, descriptions, and safety hints are untrusted review aids.</p>
                </div>
              </>
            ) : null}

            {formError ? <p className="field-error" role="alert">{formError}</p> : null}

            {discovery ? (
              <section className="mt-6 border-t border-kumo-line pt-6" aria-labelledby="catalogue-title">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h3 id="catalogue-title" className="text-sm font-semibold text-subheading">Tool allowlist</h3>
                    <p className="mt-1 text-xs leading-5 text-kumo-subtle">
                      {discovery.authentication === 'oauth' && discovery.tools.length === 0
                        ? catalogSource
                          ? `${catalogSource.implementation.recommendedTools.length} catalog-recommended exact tool names are prefilled for your review.`
                          : 'Standard OAuth protection detected. Enter independently verified exact tool names.'
                        : `${discovery.tools.length} tools discovered with MCP ${discovery.protocolVersion ?? 'compatible protocol'}.${catalogSource ? ' Catalog recommendations that still exist are preselected for review.' : ''}`}
                    </p>
                  </div>
                  <StatusPill tone="waiting">{discovery.authentication === 'oauth' ? 'OAuth protected' : 'Public endpoint'}</StatusPill>
                </div>

                {discovery.connectionBlock ? (
                  <p className="mt-5 rounded-xl border border-warning/30 bg-warning-soft p-4 text-xs leading-5 text-warning-strong" role="alert">
                    <strong className="block text-sm">Google connection blocked</strong>
                    {GOOGLE_SHARED_OAUTH_BLOCK_MESSAGE}{' '}
                    <a className="underline" href="https://github.com/ValentinOtt/ankka-mcp-gateway/blob/main/docs/BIGQUERY_GOOGLE_AUTH.md" target="_blank" rel="noreferrer">BigQuery setup guide</a>
                  </p>
                ) : null}

                {discovery.authentication === 'oauth' && discovery.tools.length === 0 ? (
                  <div className="mt-5">
                    {!discovery.connectionBlock ? <p className="mb-5 text-xs leading-5 text-kumo-subtle">
                      Connect this source as a gateway operator. The connection is shared with team members who have access.
                    </p> : null}
                    <label htmlFor="manual-tools" className="mb-1.5 block text-sm font-medium text-kumo-default">Exact tool names</label>
                    <textarea id="manual-tools" className="text-input min-h-32 w-full" placeholder={'search\nfetch_document'} value={manual} onChange={(event) => setManual(event.target.value)} />
                    <p className="mt-1.5 text-xs leading-5 text-kumo-subtle">One exact tool per line. Wildcards are never accepted.</p>
                  </div>
                ) : (
                  <div className="mt-5">
                    {missingRecommendedTools.length > 0 ? (
                      <div className="mb-4 rounded-xl border border-kumo-line bg-kumo-tint/55 p-4 text-xs leading-5 text-kumo-subtle" role="status">
                        <strong className="block text-sm text-kumo-strong">Catalog recommendation changed</strong>
                        {missingRecommendedTools.length} recommended exact tool{missingRecommendedTools.length === 1 ? ' is' : 's are'} absent from the current endpoint. Review the live catalogue before saving.
                        <div className="mt-2 flex flex-wrap gap-2">
                          {missingRecommendedTools.map((tool) => <code key={tool} className="tool-chip">{tool}</code>)}
                        </div>
                      </div>
                    ) : null}
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
                  <Button type="submit" variant="primary" className="pressable" loading={isBusy} disabled={enabledTools.length === 0 || Boolean(discovery.connectionBlock)}>Save draft</Button>
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
            <p className="mt-1.5 max-w-[48ch] text-pretty text-sm leading-6 text-kumo-subtle">{installationEnabled ? 'Add an MCP source and verify that each allowed tool is read-only.' : 'Source installation will be available in a compatible gateway release.'}</p>
            <Button variant="secondary" className="pressable mt-5" disabled={!installationEnabled} onClick={() => setShowForm(true)}><Plus size={16} weight="bold" /> Add your first source</Button>
          </div>
        ) : (
          <SourceList sources={sources.sources} installationEnabled={installationEnabled} isBusy={isBusy} onAuthorize={(sourceId) => void authorize(sourceId)} />
        )}
      </section>
    </div>
  )
}
