import { useId, useState } from 'react'
import {
  NATIVE_CONNECTOR_RECIPES,
  NATIVE_RECIPE_NOTICE,
  NATIVE_RECIPE_STATUS_LABELS,
} from '../connectors/native-recipes'
import { StatusPill } from './StatusPill'

/** Documentation is deliberately separate from draft creation and tool selection. */
export function NativeConnectorGuides() {
  const selectId = useId()
  const [selectedId, setSelectedId] = useState('linear')
  const recipe = NATIVE_CONNECTOR_RECIPES.find((entry) => entry.id === selectedId)

  return (
    <details className="mt-5 rounded-xl border border-kumo-line p-4">
      <summary className="cursor-pointer text-sm font-medium text-subheading">Provider setup guides</summary>
      <p className="mt-3 max-w-[75ch] text-xs leading-5 text-kumo-subtle">{NATIVE_RECIPE_NOTICE}</p>
      <label htmlFor={selectId} className="mt-4 block text-xs font-medium text-kumo-default">Choose a provider guide</label>
      <select
        id={selectId}
        value={selectedId}
        onChange={(event) => setSelectedId(event.target.value)}
        className="mt-2 min-h-11 w-full max-w-md rounded-lg border border-kumo-line bg-kumo-base px-3 text-sm text-kumo-strong"
      >
        {NATIVE_CONNECTOR_RECIPES.map((entry) => <option key={entry.id} value={entry.id}>{entry.displayName}</option>)}
      </select>
      {recipe ? (
        <article className="mt-5" aria-label={`${recipe.displayName} setup guide`}>
          <div className="flex flex-wrap items-center gap-3">
            <h3 className="text-sm font-semibold text-kumo-strong">{recipe.displayName}</h3>
            <StatusPill tone="attention">{NATIVE_RECIPE_STATUS_LABELS[recipe.status]}</StatusPill>
          </div>
          <p className="mt-2 text-xs leading-5 text-kumo-subtle">{recipe.description}</p>
          {recipe.id === 'bigquery' ? (
            <section className="mt-4 rounded-lg border border-kumo-line bg-kumo-tint/55 p-4" aria-label="Self-hosted BigQuery setup">
              <h4 className="text-xs font-semibold text-subheading">Connect through a self-hosted bridge</h4>
              <p className="mt-2 text-xs leading-5 text-kumo-subtle">
                Deploy the BigQuery bridge in your Cloudflare account, then add its /mcp address as a custom source.
                Your Google key goes directly to the bridge Worker. The direct Google endpoint below has separate authentication requirements.
              </p>
              <a
                href="https://github.com/ankka-ai/ankka-mcp-gateway/blob/main/apps/read-only-connectors/BIGQUERY_MCP_EXPERIMENT.md"
                target="_blank"
                rel="noopener noreferrer"
                className="mt-3 inline-block text-xs text-brand underline underline-offset-2"
              >
                Set up the BigQuery bridge
              </a>
            </section>
          ) : null}
          <p className="mt-3 text-xs text-kumo-subtle">{recipe.id === 'bigquery' ? 'Direct Google endpoint — shared authentication unavailable' : 'Provider endpoint'}</p>
          <code className="mt-1 block select-all break-all text-xs leading-5 text-kumo-default">{recipe.endpoint}</code>
          <div className="mt-4 grid gap-5 lg:grid-cols-2">
            <section aria-label="Required provider controls">
              <h4 className="text-xs font-semibold text-subheading">Required provider controls</h4>
              <ul className="mt-2 list-disc space-y-2 pl-4 text-xs leading-5 text-kumo-subtle">
                {recipe.upstreamControls.map((control) => <li key={control}>{control}</li>)}
              </ul>
              {recipe.requiredScopes.length ? (
                <p className="mt-3 break-words text-xs leading-5 text-kumo-default">Scopes: {recipe.requiredScopes.join(', ')}</p>
              ) : null}
              <p className="mt-2 text-xs leading-5 text-kumo-subtle">{recipe.scopeNote}</p>
            </section>
            <section aria-label="Before connecting">
              <h4 className="text-xs font-semibold text-subheading">Before connecting</h4>
              <ol className="mt-2 list-decimal space-y-2 pl-4 text-xs leading-5 text-kumo-subtle">
                {recipe.setupSteps.map((step) => <li key={step}>{step}</li>)}
              </ol>
            </section>
          </div>
          <details className="mt-4 text-xs leading-5 text-kumo-subtle">
            <summary className="cursor-pointer font-medium text-kumo-default">Remaining verification</summary>
            <ul className="mt-2 list-disc space-y-1 pl-4">
              {recipe.blockers.map((blocker) => <li key={blocker}>{blocker}</li>)}
            </ul>
          </details>
          <div className="mt-4 flex flex-wrap gap-x-4 gap-y-2" aria-label="Provider documentation">
            {recipe.evidenceUrls.map((url, index) => (
              <a key={url} href={url} target="_blank" rel="noopener noreferrer" className="text-xs text-brand underline underline-offset-2">
                Provider reference {index + 1}
              </a>
            ))}
          </div>
        </article>
      ) : null}
    </details>
  )
}
