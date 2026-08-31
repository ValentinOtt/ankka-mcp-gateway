import { Button } from './Button'
import { CaretDown, CaretRight, Check, Clock, MagnifyingGlass } from '@phosphor-icons/react'
import { Fragment, useId, useState } from 'react'
import type { ManagedSource } from '../api'

const filters = [
  { value: 'all', label: 'All' },
  { value: 'installed', label: 'Installed' },
  { value: 'draft', label: 'Drafts' },
] as const

interface SourceListProps {
  sources: ManagedSource[]
  installationEnabled: boolean
  isBusy: boolean
  onAuthorize(sourceId: string): void
}

export function SourceList({ sources, installationEnabled, isBusy, onAuthorize }: SourceListProps) {
  const [filter, setFilter] = useState<(typeof filters)[number]['value']>('all')
  const [search, setSearch] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const detailsId = useId()
  const query = search.trim().toLocaleLowerCase()
  const visibleSources = sources.filter((source) => (
    (filter === 'all' || source.status === filter)
    && (!query || source.label.toLocaleLowerCase().includes(query) || source.url.toLocaleLowerCase().includes(query))
  ))

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex gap-1" role="group" aria-label="Filter sources">
          {filters.map(({ value, label }) => (
            <Button
              key={value}
              type="button"
              variant={filter === value ? 'secondary' : 'ghost'}
              className="pressable"
              aria-pressed={filter === value}
              onClick={() => setFilter(value)}
            >
              {label}
            </Button>
          ))}
        </div>
        <label className="flex w-full items-center gap-2 rounded-lg bg-kumo-tint/55 px-3 sm:w-56">
          <MagnifyingGlass aria-hidden="true" size={16} className="shrink-0 text-kumo-subtle" />
          <input
            type="search"
            aria-label="Search sources"
            placeholder="Search sources"
            className="min-h-10 min-w-0 w-full rounded-sm bg-transparent text-base text-kumo-default placeholder:text-kumo-subtle sm:min-h-9 sm:text-sm"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </label>
      </div>

      <table className="w-full table-fixed border-collapse text-left text-sm" aria-label="Source list">
        <thead className="text-kumo-subtle">
          <tr className="border-b border-kumo-line">
            <th scope="col" className="w-[55%] px-3 py-3 font-normal sm:w-[45%]">Source</th>
            <th scope="col" className="hidden w-[25%] px-3 py-3 font-normal sm:table-cell">Connection</th>
            <th scope="col" className="px-3 py-3 font-normal">Status</th>
          </tr>
        </thead>
        <tbody>
          {visibleSources.map((source) => {
            const isExpanded = expanded === source.id
            const sourceDetailsId = `${detailsId}-${source.id}`
            const connection = source.authMode === 'oauth'
              ? source.onBehalfOfUser ? 'Legacy user-bound OAuth' : 'Operator-connected OAuth'
              : 'Public'

            return (
              <Fragment key={source.id}>
                <tr className={`border-b border-kumo-line/70 hover:bg-kumo-tint/40 ${isExpanded ? 'bg-kumo-tint/40' : ''}`}>
                  <th scope="row" className="px-3 py-2 text-left font-medium">
                    <button
                      type="button"
                      className="flex min-h-12 w-full cursor-pointer items-center gap-3 rounded-md py-2 text-left text-kumo-strong"
                      aria-expanded={isExpanded}
                      aria-controls={isExpanded ? sourceDetailsId : undefined}
                      onClick={() => setExpanded(isExpanded ? null : source.id)}
                    >
                      <span aria-hidden="true" className="flex size-8 shrink-0 items-center justify-center rounded-lg border border-kumo-line bg-kumo-overlay text-xs font-semibold text-kumo-subtle">
                        {source.label.slice(0, 1).toLocaleUpperCase()}
                      </span>
                      <span className="min-w-0 flex-1 break-words">{source.label}</span>
                      {isExpanded ? <CaretDown aria-hidden="true" size={14} className="shrink-0 text-kumo-subtle" /> : <CaretRight aria-hidden="true" size={14} className="shrink-0 text-kumo-subtle" />}
                    </button>
                  </th>
                  <td className="hidden px-3 py-3 text-kumo-subtle sm:table-cell">
                    {source.authMode === 'oauth' ? source.onBehalfOfUser ? 'Legacy OAuth' : 'OAuth' : 'Public'}
                  </td>
                  <td className="px-3 py-3">
                    {source.status === 'installed' ? (
                      <span className="inline-flex items-center gap-2 text-success-strong"><Check aria-hidden="true" size={17} className="shrink-0" />Installed</span>
                    ) : (
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="inline-flex items-center gap-1.5 text-warning-strong"><Clock aria-hidden="true" size={16} />Draft</span>
                        <Button
                          type="button"
                          variant="secondary"
                          className="pressable h-auto min-h-9 max-w-full whitespace-normal py-1.5"
                          disabled={!installationEnabled}
                          loading={isBusy}
                          onClick={() => onAuthorize(source.id)}
                        >
                          {installationEnabled ? 'Authorize and apply' : 'Installation unavailable'}
                        </Button>
                      </div>
                    )}
                  </td>
                </tr>
                {isExpanded ? (
                  <tr id={sourceDetailsId} className="border-b border-kumo-line/70 bg-kumo-tint/40">
                    <td colSpan={3} className="px-5 py-5 sm:pl-14">
                      <p className="text-xs text-kumo-subtle">{connection}</p>
                      <code className="mt-2 block select-all break-all text-xs text-kumo-default">{source.url}</code>
                      <p className="mt-4 text-xs font-medium text-kumo-subtle">{source.enabledTools.length} exact tool{source.enabledTools.length === 1 ? '' : 's'}</p>
                      <div className="mt-2 flex max-h-52 flex-wrap gap-2 overflow-y-auto pr-1" role="region" aria-label={`${source.label} allowed tools`} tabIndex={0}>
                        {source.enabledTools.map((tool) => <code key={tool} className="tool-chip break-all">{tool}</code>)}
                      </div>
                    </td>
                  </tr>
                ) : null}
              </Fragment>
            )
          })}
          {visibleSources.length === 0 ? (
            <tr><td colSpan={3} className="px-3 py-10 text-center text-kumo-subtle">{query ? 'No matching sources.' : filter === 'installed' ? 'No installed sources.' : filter === 'draft' ? 'No drafts.' : 'No sources yet.'}</td></tr>
          ) : null}
        </tbody>
      </table>
    </div>
  )
}
