import { Loader } from '@cloudflare/kumo'
import { type PropsWithChildren, useEffect, useState } from 'react'
import * as v from 'valibot'
import { BrandMark } from './components/BrandMark'
import { Button } from './components/Button'

const installStatusSchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: v.picklist(['CONVERGING', 'READY', 'INCOMPLETE']),
})
type HandoffState = 'checking' | 'ready' | 'incomplete' | 'unavailable' | 'sign_in'
const CHECK_INTERVAL_MS = 3_000
const REQUEST_TIMEOUT_MS = 5_000
const CHECK_LIMIT_MS = 5 * 60_000

/** The query flag selects a loading screen; only the gateway can report readiness. */
export function InstallHandoff({ children }: PropsWithChildren) {
  const [state, setState] = useState<HandoffState>(() =>
    new URL(window.location.href).searchParams.get('setup') === 'finishing' ? 'checking' : 'ready')

  useEffect(() => {
    if (state !== 'checking') return
    let active = true
    let timer: number | undefined
    let controller: AbortController | undefined
    const deadline = Date.now() + CHECK_LIMIT_MS
    const stop = () => {
      active = false
      window.clearTimeout(timer)
      controller?.abort()
    }
    const leave = () => {
      stop()
      // A page restored from the back/forward cache must not show a stopped spinner.
      setState('unavailable')
    }
    const check = async () => {
      controller = new AbortController()
      const timeout = window.setTimeout(() => controller?.abort(), REQUEST_TIMEOUT_MS)
      try {
        // Normal top-level Cloudflare Access login precedes this same-origin read.
        const response = await fetch('/__ankka/install/status', {
          credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal,
        })
        if (!active) return
        if (response.status === 401 || response.status === 403) {
          setState('sign_in')
          return
        }
        if (!response.ok) throw new Error('install_status_unavailable')
        const result = v.safeParse(installStatusSchema, await response.json())
        if (!active) return
        if (result.success && result.output.status === 'READY') {
          const url = new URL(window.location.href)
          url.searchParams.delete('setup')
          window.history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`)
          setState('ready')
          return
        }
        if (result.success && result.output.status === 'INCOMPLETE') {
          setState('incomplete')
          return
        }
      } catch {
        // Static assets are installed first; the final status route can arrive later.
      } finally {
        window.clearTimeout(timeout)
      }
      if (!active) return
      if (Date.now() >= deadline) setState('unavailable')
      else timer = window.setTimeout(() => { void check() }, CHECK_INTERVAL_MS)
    }
    window.addEventListener('pagehide', leave)
    void check()
    return () => { stop(); window.removeEventListener('pagehide', leave) }
  }, [state])

  if (state === 'ready') return children

  const checking = state === 'checking'
  const heading = checking ? 'Finishing your Ankka Gateway'
    : state === 'incomplete' ? 'Setup did not complete'
    : state === 'sign_in' ? 'Sign in to check your gateway'
    : 'Setup is taking longer than expected'
  return (
    <main className="flex min-h-dvh items-center justify-center bg-canvas px-5">
      <div className="w-full max-w-md text-center">
        <div className="mx-auto mb-10 w-full max-w-sm text-brand [mask-image:linear-gradient(to_bottom,black,transparent)]">
          <BrandMark className="w-full" />
        </div>
        {checking ? <Loader size="lg" className="mx-auto mb-5" /> : null}
        <div role="status" aria-live="polite">
          <h1 className="text-xl font-semibold text-kumo-strong">{heading}</h1>
          <p className="mt-3 text-pretty text-sm leading-6 text-kumo-subtle">
            {checking ? 'Your gateway is finishing setup in your Cloudflare account. This page will open your dashboard when setup is ready.'
              : state === 'incomplete' ? 'Your gateway stopped before setup finished. Return to the installer to review this installation and the recovery options.'
              : state === 'sign_in' ? 'Open this page again to continue through Cloudflare Access and check setup.'
              : 'We could not confirm that setup finished. You can check again or return to the installer to review this installation.'}
          </p>
        </div>
        {!checking ? (
          <div className="mt-6 flex flex-col items-center gap-4">
            {state === 'sign_in'
              ? <a className="text-sm text-brand underline underline-offset-4" href="/?setup=finishing">Sign in and check setup</a>
              : <Button variant="primary" onClick={() => setState('checking')}>Check again</Button>}
            <a className="text-sm text-kumo-subtle underline underline-offset-4" href="https://deploy.ankka.ai/">Return to installer</a>
          </div>
        ) : null}
      </div>
    </main>
  )
}
