import { Script } from 'node:vm';
import { bigQueryCredentialPage } from '../src/customer-bigquery-credential-page';

describe('BigQuery credential page script boundary', () => {
  it('keeps callback values inside their JavaScript strings even when called with HTML', async () => {
    const value = '</script><script>throw new Error("injected")</script><!--';
    const response = bigQueryCredentialPage(value, value);
    const html = await response.text();
    expect(html.match(/<script\b/gu)).toHaveLength(1);
    expect(html.match(/<\/script>/gu)).toHaveLength(1);
    expect(html).not.toContain(value);
    const script = html.match(/<script nonce="[^"]+">([\s\S]*)<\/script>/u)?.[1];
    expect(script).toBeDefined();
    expect(() => new Script(script ?? '')).not.toThrow();
    const literals = script?.match(/const code=(.*);const state=(.*);history\.replaceState/u);
    expect(JSON.parse(literals?.[1] ?? 'null')).toBe(value);
    expect(JSON.parse(literals?.[2] ?? 'null')).toBe(value);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
  });
});
