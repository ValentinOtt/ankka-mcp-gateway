import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { InstallHandoff } from './InstallHandoff'

const statusResponse = (status: string) => Response.json({ schemaVersion: 1, status })
const dashboard = <div>Gateway dashboard</div>

describe('management install handoff', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    window.history.replaceState(null, '', '/?setup=finishing')
  })
  afterEach(() => {
    cleanup()
    vi.useRealTimers()
    vi.unstubAllGlobals()
    window.history.replaceState(null, '', '/')
  })

  it.each(['/', '/?setup=READY', '/?setup=unknown'])('leaves ordinary dashboard navigation unchanged at %s', (path) => {
    window.history.replaceState(null, '', path)
    const request = vi.fn()
    vi.stubGlobal('fetch', request)
    render(<InstallHandoff>{dashboard}</InstallHandoff>)
    expect(screen.getByText('Gateway dashboard')).toBeVisible()
    expect(request).not.toHaveBeenCalled()
  })

  it('waits through an early API failure and convergence, then opens the dashboard on verified readiness', async () => {
    window.history.replaceState(null, '', '/?setup=finishing&keep=value#section')
    const request = vi.fn()
      .mockResolvedValueOnce(new Response(null, { status: 503 }))
      .mockResolvedValueOnce(statusResponse('CONVERGING'))
      .mockResolvedValueOnce(statusResponse('READY'))
    vi.stubGlobal('fetch', request)
    render(<InstallHandoff>{dashboard}</InstallHandoff>)
    await act(async () => {})
    expect(screen.queryByText('Gateway dashboard')).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Finishing your Ankka Gateway' })).toBeVisible()
    await act(() => vi.advanceTimersByTimeAsync(3_000))
    expect(screen.queryByText('Gateway dashboard')).not.toBeInTheDocument()
    await act(() => vi.advanceTimersByTimeAsync(3_000))
    expect(screen.getByText('Gateway dashboard')).toBeVisible()
    expect(window.location.search).toBe('?keep=value')
    expect(window.location.hash).toBe('#section')
    expect(request).toHaveBeenCalledTimes(3)
    for (const call of request.mock.calls) {
      expect(call).toEqual(['/__ankka/install/status', {
        credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: expect.any(AbortSignal),
      }])
    }
  })

  it('stops on an incomplete install and only checks again when requested', async () => {
    const request = vi.fn().mockResolvedValueOnce(statusResponse('INCOMPLETE')).mockResolvedValueOnce(statusResponse('READY'))
    vi.stubGlobal('fetch', request)
    render(<InstallHandoff>{dashboard}</InstallHandoff>)
    await act(async () => {})
    expect(screen.getByRole('heading', { name: 'Setup did not complete' })).toBeVisible()
    expect(screen.queryByText('Gateway dashboard')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Return to installer' })).toHaveAttribute('href', 'https://deploy.ankka.ai/')
    await act(() => vi.advanceTimersByTimeAsync(60_000))
    expect(request).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: 'Check again' }))
    await act(async () => {})
    expect(screen.getByText('Gateway dashboard')).toBeVisible()
  })

  it.each(['CONVERGING', 'READY_WITHOUT_PROOF'])('bounds polling for %s and leaves recovery links', async (status) => {
    const request = vi.fn().mockImplementation(async () => statusResponse(status))
    vi.stubGlobal('fetch', request)
    render(<InstallHandoff>{dashboard}</InstallHandoff>)
    await act(() => vi.advanceTimersByTimeAsync(300_000))
    expect(screen.queryByText('Gateway dashboard')).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Setup is taking longer than expected' })).toBeVisible()
    expect(screen.getByRole('button', { name: 'Check again' })).toBeVisible()
    expect(screen.getByRole('link', { name: 'Return to installer' })).toBeVisible()
    const attempts = request.mock.calls.length
    expect(attempts).toBeLessThanOrEqual(101)
    await act(() => vi.advanceTimersByTimeAsync(60_000))
    expect(request).toHaveBeenCalledTimes(attempts)
    expect(window.location.search).toBe('?setup=finishing')
  })

  it('cannot turn a marker on a gateway without install state into readiness', async () => {
    const request = vi.fn().mockImplementation(async () => new Response(null, { status: 404 }))
    vi.stubGlobal('fetch', request)
    render(<InstallHandoff>{dashboard}</InstallHandoff>)
    await act(() => vi.advanceTimersByTimeAsync(300_000))
    expect(screen.queryByText('Gateway dashboard')).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Setup is taking longer than expected' })).toBeVisible()
    expect(request.mock.calls.every(([path]) => path === '/__ankka/install/status')).toBe(true)
  })

  it.each([401, 403])('keeps a top-level sign-in link after HTTP %s', async (status) => {
    const request = vi.fn().mockResolvedValue(new Response(null, { status }))
    vi.stubGlobal('fetch', request)
    render(<InstallHandoff>{dashboard}</InstallHandoff>)
    await act(async () => {})
    expect(screen.getByRole('link', { name: 'Sign in and check setup' })).toHaveAttribute('href', '/?setup=finishing')
    expect(screen.queryByText('Gateway dashboard')).not.toBeInTheDocument()
    await act(() => vi.advanceTimersByTimeAsync(60_000))
    expect(request).toHaveBeenCalledTimes(1)
  })

  it('times out stalled reads and cancels work when unmounted', async () => {
    const signals: AbortSignal[] = []
    const request = vi.fn((_path: string, init: RequestInit) => new Promise<Response>((_resolve, reject) => {
      const signal = init.signal
      if (!signal) throw new Error('missing abort signal')
      signals.push(signal)
      signal.addEventListener('abort', () => reject(new Error('aborted')))
    }))
    vi.stubGlobal('fetch', request)
    const view = render(<InstallHandoff>{dashboard}</InstallHandoff>)
    await act(() => vi.advanceTimersByTimeAsync(5_000))
    expect(signals[0]?.aborted).toBe(true)
    await act(() => vi.advanceTimersByTimeAsync(3_000))
    expect(request).toHaveBeenCalledTimes(2)
    view.unmount()
    expect(signals[1]?.aborted).toBe(true)
    await act(() => vi.advanceTimersByTimeAsync(60_000))
    expect(request).toHaveBeenCalledTimes(2)
  })

  it('leaves a usable check-again state when a suspended page is restored', async () => {
    const request = vi.fn().mockImplementation(async () => statusResponse('CONVERGING'))
    vi.stubGlobal('fetch', request)
    render(<InstallHandoff>{dashboard}</InstallHandoff>)
    await act(async () => {})
    act(() => { window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })) })
    act(() => { window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })) })
    expect(screen.getByRole('button', { name: 'Check again' })).toBeVisible()
    await act(() => vi.advanceTimersByTimeAsync(60_000))
    expect(request).toHaveBeenCalledTimes(1)
  })
})
