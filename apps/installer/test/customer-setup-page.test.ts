import { runInNewContext } from 'node:vm';
import { describe, expect, it, vi } from 'vitest';
import { customerSetupPage } from '../src/customer-setup-page';

function element() {
  const listeners = new Map<string, () => void>();
  return {
    textContent: '', value: '', hidden: false, disabled: false,
    replaceChildren: vi.fn(), append: vi.fn(), focus: vi.fn(), listeners,
    addEventListener: (name: string, callback: () => void) => listeners.set(name, callback),
  };
}

async function openPage(fetch: typeof globalThis.fetch) {
  const html = await customerSetupPage().text();
  const script = /<script nonce="[^"]+">([\s\S]*?)<\/script>/u.exec(html)?.[1];
  if (!script) throw new Error('setup script missing');
  const nodes = new Map([...html.matchAll(/\bid="([^"]+)"/gu)].map((match) => [match[1], element()]));
  const node = (id: string) => {
    const value = nodes.get(id);
    if (!value) throw new Error('setup element missing');
    return value;
  };
  for (const id of ['setup', 'review', 'no-domains', 'restart']) node(id).hidden = true;
  const navigate = vi.fn();
  runInNewContext(script, {
    document: {
      getElementById: node, createElement: element,
      querySelectorAll: () => [node('approve'), node('edit'), node('review-button')],
    },
    location: { hash: '', assign: navigate }, history: { replaceState: vi.fn() },
    fetch, URL,
  });
  return { node, navigate, html };
}

const reviewed = {
  availableZones: [{ name: 'example.com' }],
  selection: { basics: {
    gatewayName: 'Example team', zoneName: 'example.com',
    managementHostname: 'manage.example.com', portalHostname: 'mcp.example.com',
    adminEmail: 'admin@example.com', additionalAdminEmails: [],
  } },
  plan: { managementAdminEmails: ['admin@example.com'], managementResources: [], gatewayResources: [] },
};

describe('customer setup approval recovery', () => {
  it('offers fresh consent for the same reviewed configuration without authorizing automatically', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(Response.json({ ...reviewed, approvalExpired: true }))
      .mockResolvedValueOnce(Response.json({ authorizationUrl: 'https://dash.cloudflare.com/oauth2/auth' }));
    const page = await openPage(fetch);
    await vi.waitFor(() => expect(page.node('approve').textContent).toBe('Start a fresh approval'));
    expect(page.node('edit').hidden).toBe(true);
    expect(page.node('review').hidden).toBe(false);
    expect(page.node('message').textContent).toContain('these same gateway details');
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(page.navigate).not.toHaveBeenCalled();

    page.node('approve').listeners.get('click')?.();
    await vi.waitFor(() => expect(page.navigate).toHaveBeenCalledExactlyOnceWith('https://dash.cloudflare.com/oauth2/auth'));
    expect(fetch).toHaveBeenLastCalledWith('/__ankka/install/oauth/start', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
      credentials: 'same-origin', cache: 'no-store',
    });
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('keeps ordinary review editable before its first approval', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(Response.json(reviewed));
    const page = await openPage(fetch);
    await vi.waitFor(() => expect(page.node('approve').textContent).toBe('Approve and finish setup'));
    expect(page.node('edit').hidden).toBe(false);
    expect(page.navigate).not.toHaveBeenCalled();
  });

  it('does not offer a restart for active or potentially applied work', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(Response.json({ error: 'setup_locked' }, { status: 409 }));
    const page = await openPage(fetch);
    await vi.waitFor(() => expect(page.node('message').textContent).toContain('already started'));
    expect(page.node('review').hidden).toBe(true);
    expect(page.navigate).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('explains full setup expiry without claiming the existing gateway was removed', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(Response.json({ error: 'bootstrap_unavailable' }, { status: 410 }));
    const page = await openPage(fetch);
    await vi.waitFor(() => expect(page.node('message').textContent).toContain('review your deployment before starting again'));
    expect(page.node('review').hidden).toBe(true);
    expect(page.node('restart').hidden).toBe(false);
    expect(page.html).toContain('An unfinished gateway may still exist in your Cloudflare account.');
    expect(page.navigate).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
