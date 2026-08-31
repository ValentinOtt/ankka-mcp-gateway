import { Button } from './Button'
import { Check, Copy, LinkSimple } from '@phosphor-icons/react'
import { useEffect, useState } from 'react'
import { useGateway } from '../GatewayContext'

function safeMcpUrl(value: string | undefined): string | null {
  try {
    const url = new URL(value ?? '')
    return url.protocol === 'https:' && !url.username && !url.password ? url.href : null
  } catch { return null }
}

export function GatewayEndpoint() {
  const { status } = useGateway()
  const [copyStatus, setCopyStatus] = useState<'idle' | 'copied' | 'error'>('idle')

  useEffect(() => {
    if (copyStatus !== 'copied') return
    const timer = window.setTimeout(() => setCopyStatus('idle'), 2000)
    return () => window.clearTimeout(timer)
  }, [copyStatus])

  if (!status) return null
  const mcpUrl = safeMcpUrl(status.gateway.mcpUrl)

  const copyMcpUrl = async () => {
    if (!mcpUrl) return
    try {
      await navigator.clipboard.writeText(mcpUrl)
      setCopyStatus('copied')
    } catch {
      setCopyStatus('error')
    }
  }

  return (
    <section className="mt-6 rounded-2xl border border-kumo-line bg-kumo-overlay p-5 sm:p-6" aria-labelledby="gateway-endpoint-title">
      <div className="grid grid-cols-[auto_minmax(0,1fr)] items-center gap-x-4 gap-y-4 sm:grid-cols-[auto_minmax(0,1fr)_auto] sm:gap-x-5">
        <div aria-hidden="true" className="flex size-11 items-center justify-center self-start rounded-xl bg-kumo-fill/60 text-kumo-subtle sm:self-center">
          <LinkSimple size={22} />
        </div>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <h2 id="gateway-endpoint-title" className="text-sm font-medium text-subheading">MCP Gateway</h2>
            {mcpUrl ? (
              <span className="inline-flex items-center gap-1.5 text-xs text-success-strong">
                <span aria-hidden="true" className="size-1.5 rounded-full bg-success" />
                Ready
              </span>
            ) : null}
          </div>
          {mcpUrl ? (
            <p className="mt-1.5 select-all break-all text-base font-medium leading-relaxed text-kumo-strong">{mcpUrl}</p>
          ) : <p className="mt-1.5 text-sm text-kumo-subtle">MCP URL unavailable.</p>}
        </div>
        {mcpUrl ? (
          <Button
            type="button"
            variant="secondary"
            className="col-start-2 min-h-10 min-w-28 justify-center justify-self-start sm:col-start-auto sm:justify-self-end"
            aria-label="Copy MCP URL"
            title={copyStatus === 'copied' ? 'Copied' : 'Copy MCP URL'}
            onClick={() => void copyMcpUrl()}
          >
            {copyStatus === 'copied' ? <Check size={16} aria-hidden="true" className="text-success-strong" /> : <Copy size={16} aria-hidden="true" />}
            <span>{copyStatus === 'copied' ? 'Copied' : 'Copy'}</span>
          </Button>
        ) : null}
      </div>
      <p role="status" className="sr-only">{copyStatus === 'copied' ? 'MCP URL copied.' : ''}</p>
      {copyStatus === 'error' ? (
        <p role="alert" className="mt-3 text-sm text-danger">Couldn’t copy automatically. Select the URL and copy it manually.</p>
      ) : null}
    </section>
  )
}
