import { type FormEvent, useState } from 'react'
import { Input } from '@cloudflare/kumo'
import { ArrowRight } from '@phosphor-icons/react'
import { type BigQuerySetupInput, validHandoffUrl } from '../api'
import { useGateway } from '../GatewayContext'
import { Button } from './Button'

const PROJECT = /^[a-z][a-z0-9-]{4,61}[a-z0-9]$/u

export function parseBigQueryDatasets(text: string): BigQuerySetupInput['configuration']['allowedDatasets'] | null {
  const lines = text.trim().split(/\r?\n/u).map((line) => line.trim()).filter(Boolean)
  if (lines.length < 1 || lines.length > 16 || new Set(lines).size !== lines.length) return null
  const datasets = lines.map((line) => {
    const parts = line.split('.')
    return { projectId: parts[0] ?? '', datasetId: parts.length === 2 ? parts[1] ?? '' : '' }
  })
  return datasets.every(({ projectId, datasetId }) => PROJECT.test(projectId) && /^[A-Za-z0-9_]{1,1024}$/u.test(datasetId)) ? datasets : null
}

export function BigQuerySetupForm({ disabled }: { disabled: boolean }) {
  const { api, sources, refreshSources, refreshSourceActions } = useGateway()
  const [label, setLabel] = useState('BigQuery')
  const [queryProjectId, setQueryProjectId] = useState('')
  const [datasets, setDatasets] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (disabled || submitting || !sources) return
    const allowedDatasets = parseBigQueryDatasets(datasets)
    if (!PROJECT.test(queryProjectId.trim()) || !allowedDatasets || label.trim().length < 2 || !confirmed) {
      setError('Enter a query project and 1–16 unique datasets as project.dataset, then confirm the Google permissions.')
      return
    }
    setError(null)
    setSubmitting(true)
    try {
      const prepared = await api.prepareBigQuery({ revision: sources.revision, label: label.trim(),
        configuration: { queryProjectId: queryProjectId.trim(), allowedDatasets }, readOnlyConfirmed: true })
      const destination = validHandoffUrl(prepared.handoffUrl, window.location.origin)
      if (destination === null) throw new Error('The gateway returned an invalid authorization link.')
      window.location.assign(destination)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'BigQuery setup could not start.')
      await Promise.allSettled([refreshSources(), refreshSourceActions()])
      setSubmitting(false)
    }
  }
  return (
    <section className="surface-card mt-7 p-5 sm:p-6" aria-labelledby="bigquery-title">
      <h2 id="bigquery-title" className="text-base font-semibold text-subheading">Add BigQuery</h2>
      <p className="mt-2 max-w-[70ch] text-sm leading-6 text-kumo-subtle">Give your team read-only SQL and table discovery through a bridge in your Cloudflare account.</p>
      <ol className="mt-5 grid list-inside list-decimal gap-2 text-sm text-kumo-subtle sm:grid-cols-3" aria-label="BigQuery setup steps">
        <li>Choose your data</li><li>Approve and upload key</li><li>Connect and grant access</li>
      </ol>
      <form className="mt-6" onSubmit={(event) => void submit(event)}>
        <fieldset disabled={disabled || submitting}>
          <legend className="sr-only">BigQuery connection</legend>
          <div className="grid gap-5 sm:grid-cols-2">
            <Input label="Source name" value={label} maxLength={80} onChange={(event) => setLabel(event.target.value)} required />
            <Input label="Query project ID" placeholder="analytics-query-project" value={queryProjectId} maxLength={63} onChange={(event) => setQueryProjectId(event.target.value)} required />
          </div>
          <p className="mt-2 text-xs leading-5 text-kumo-subtle">Google runs and bills query jobs in this project. It may differ from the projects containing your data.</p>
          <label htmlFor="bigquery-datasets" className="mb-1.5 mt-5 block text-sm font-medium text-kumo-default">Datasets to discover</label>
          <textarea id="bigquery-datasets" className="text-input min-h-24 w-full" placeholder={'analytics-data-project.reporting'} value={datasets} maxLength={18_000} required onChange={(event) => setDatasets(event.target.value)} />
          <p className="mt-1.5 text-xs leading-5 text-kumo-subtle">One project.dataset per line. Google IAM controls which data SQL can read; keep its dataset permissions scoped to this list.</p>
          <details className="mt-5 rounded-xl border border-kumo-line p-4 text-sm leading-6">
            <summary className="cursor-pointer font-medium text-kumo-strong">Prepare your Google service account</summary>
            <ol className="mt-3 list-inside list-decimal space-y-2 text-kumo-subtle">
              <li>Create a dedicated service account and enable the BigQuery API and Google’s BigQuery MCP service in the projects you will query or inspect.</li>
              <li>Grant BigQuery Job User in the query project, MCP User in each query and data project, and BigQuery Data Viewer on each selected dataset.</li>
              <li>Remove broader inherited data or write access, then create a JSON key. Keep the file ready for the next step.</li>
            </ol>
            <a className="mt-3 inline-block underline underline-offset-4" href="https://github.com/ValentinOtt/ankka-mcp-gateway/blob/main/docs/BIGQUERY_GOOGLE_AUTH.md" target="_blank" rel="noreferrer">Google permissions and setup guide</a>
          </details>
          <label className="mt-5 flex items-start gap-3 text-sm leading-6 text-kumo-subtle">
            <input className="mt-1" type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
            <span>I have a dedicated service account with the read-only permissions above and its JSON key ready.</span>
          </label>
          <p className="mt-3 text-xs leading-5 text-kumo-subtle">After Cloudflare approval, upload the key directly to your gateway. It is stored as a Worker secret in your Cloudflare account. Your team gets three tools: read-only SQL, table details, and table listing. Nobody is assigned access until you grant it.</p>
          {error ? <p role="alert" className="field-error">{error}</p> : null}
          <Button type="submit" variant="primary" className="pressable mt-5" loading={submitting} disabled={!confirmed}>Continue to Cloudflare <ArrowRight size={16} /></Button>
        </fieldset>
      </form>
    </section>
  )
}
