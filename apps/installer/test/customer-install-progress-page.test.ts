import { runInNewContext } from 'node:vm';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { customerInstallProgressPage } from '../src/customer-install-progress-page';
import type { CustomerBootstrapCallbackOutcome } from '../src/customer-bootstrap-router';

function element() {
  return { textContent: '', href: '', append: vi.fn() };
}

async function openPage(outcome: CustomerBootstrapCallbackOutcome, fetch: typeof globalThis.fetch) {
  const response = customerInstallProgressPage('manage.example.com', outcome, []);
  const html = await response.text();
  const script = /<script nonce="[^"]+">([\s\S]*?)<\/script>/u.exec(html)?.[1];
  if (!script) throw new Error('progress script missing');
  const nodes = new Map(['#title', '#message', '#detail'].map((selector) => [selector, element()]));
  const navigate = vi.fn();
  const listeners = new Map<string, () => void>();
  runInNewContext(script, {
    document: { querySelector: (selector: string) => nodes.get(selector), createElement: element },
    location: { replace: navigate },
    fetch, AbortController, setTimeout, clearTimeout,
    addEventListener: (name: string, callback: () => void) => listeners.set(name, callback),
  });
  return { nodes, navigate, listeners, response };
}

const converging: CustomerBootstrapCallbackOutcome = { status: 'CONVERGING', failureCode: null, failureReason: null };

describe('customer install final navigation', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('automatically opens the fixed management waiting screen on READY', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    const page = await openPage({ ...converging, status: 'READY' }, fetch);
    expect(page.navigate).toHaveBeenCalledExactlyOnceWith('https://manage.example.com/?setup=finishing');
    expect(fetch).not.toHaveBeenCalled();
    expect(page.response.headers.get('content-security-policy')).toContain("connect-src 'self'");
    expect(page.response.headers.get('referrer-policy')).toBe('no-referrer');
  });

  it('continues to management after the temporary address retires without claiming readiness', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockRejectedValue(new Error('temporary_address_closed'));
    const page = await openPage(converging, fetch);
    await vi.advanceTimersByTimeAsync(6_000);
    expect(page.navigate).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(3_000);
    expect(page.navigate).toHaveBeenCalledExactlyOnceWith('https://manage.example.com/?setup=finishing');
    expect(page.nodes.get('#title')?.textContent).toBe('Opening your management page');
    expect(page.nodes.get('#message')?.textContent).toContain('will check that setup finished');
    await vi.advanceTimersByTimeAsync(60_000);
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(fetch.mock.calls[0]).toEqual(['/__ankka/install/status', {
      credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: expect.any(AbortSignal),
    }]);
  });

  it('resets transient failures when convergence is observed and navigates on a later READY', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockRejectedValueOnce(new Error('temporary_failure'))
      .mockResolvedValueOnce(Response.json({ status: 'CONVERGING' }))
      .mockResolvedValueOnce(Response.json({ status: 'READY' }));
    const page = await openPage(converging, fetch);
    await vi.advanceTimersByTimeAsync(6_000);
    expect(page.navigate).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(3_000);
    expect(page.navigate).toHaveBeenCalledTimes(1);
  });

  it('stops on an explicit setup failure', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(Response.json({ status: 'INCOMPLETE', failure: { code: 'convergence_failed' } }));
    const page = await openPage(converging, fetch);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(page.navigate).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(page.nodes.get('#title')?.textContent).toBe('Setup did not complete');
    expect(page.nodes.get('#detail')?.textContent).toBe('Reason: convergence_failed');
  });

  it('does not navigate or poll after leaving the page', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockRejectedValue(new Error('closed'));
    const page = await openPage(converging, fetch);
    page.listeners.get('pagehide')?.();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(page.navigate).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });
});
