import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { APPROVED_CLOUDFLARE_CONTRACT } from '../apps/installer/scripts/sign-gateway-release.mjs';

const ROOT = new URL('../payload/', import.meta.url);
const ADMIN_ROOT = new URL('../apps/admin/dist/', import.meta.url);
const COMPONENTS = Object.freeze({
  admin: null,
  installer: ['assets/installer-2f74774a.css', 'assets/installer-562e903f.js', 'index.html'],
  worker: ['index.js'],
  'worker-cleanup': ['index.js'],
  'worker-retirement': ['index.js'],
});
const TREE_SHA256 = Object.freeze({
  installer: '1f25a11454fb53aefd600f1bbf4d6eb0c90cd68c4ce314246b0dcacae2acce5b',
  worker: 'fa95721c42f4eeff630eca911c5e2780224929f15c9d1dcc618f2464e9ba8e97',
  'worker-cleanup': '6430ac9d2fe6516022d049f305be0d0135115f9f5e6989f502afc79334bdbc55',
  'worker-retirement': '757311596630d21599397caf0ef43e07c4c8d005148bff280ba8ee538d9d6c9f',
});
const FROZEN_LIFECYCLE_SHA256 = Object.freeze({
  'worker-cleanup/index.js': 'be4d56f0ef065b00cdd6a012e39608293fb24a0b5bb2a1ecf8d9885a580ceae9',
  'worker-retirement/index.js': '506e91323d6f6c89398a15799bfcde6cb4d271a5d6bf28a4fbbd422331751bda',
});
const CONTENT_TYPES = Object.freeze({
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
});

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function componentRoot(component) {
  return component === 'admin' ? ADMIN_ROOT : new URL(`${component}/`, ROOT);
}

function componentUrl(component, relative) {
  return new URL(relative, componentRoot(component));
}

async function componentRecords(component) {
  const files = [];
  const visit = async (directory, relativeDirectory = '') => {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
    for (const entry of entries) {
      const relative = relativeDirectory ? `${relativeDirectory}/${entry.name}` : entry.name;
      const target = componentUrl(component, relative);
      const metadata = await lstat(target);
      assert.equal(metadata.isSymbolicLink(), false, `${component}/${relative} must not be a symlink`);
      if (entry.isDirectory()) {
        await visit(target, relative);
        continue;
      }
      assert.equal(entry.isFile(), true);
      const bytes = await readFile(target);
      const extension = path.extname(relative);
      files.push({
        path: `payload/${component}/${relative}`,
        byteSize: bytes.byteLength,
        sha256: sha256(bytes),
        contentType: component.startsWith('worker')
          ? 'application/javascript+module'
          : CONTENT_TYPES[extension],
      });
    }
  };
  await visit(componentRoot(component));
  return files;
}

function layoutTree(records) {
  const reduced = records.map(({ path: filePath, byteSize, sha256: digest }) => ({
    path: filePath,
    byteSize,
    sha256: digest,
  }));
  return sha256(Buffer.from(JSON.stringify(reduced)));
}

async function componentText(component, extension) {
  const records = await componentRecords(component);
  const bodies = await Promise.all(records
    .filter((record) => record.path.endsWith(extension))
    .map((record) => readFile(componentUrl(component, record.path.slice(`payload/${component}/`.length)), 'utf8')));
  return bodies.join('\n');
}

test('release sources have one generated admin and four exact payload components', async () => {
  const roots = (await readdir(ROOT, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  assert.deepEqual(roots, Object.keys(COMPONENTS).filter((component) => component !== 'admin').sort());
  for (const [component, expectedFiles] of Object.entries(COMPONENTS)) {
    const records = await componentRecords(component);
    const names = records.map(({ path: filePath }) => filePath.slice(`payload/${component}/`.length));
    if (expectedFiles === null) {
      assert.ok(names.includes('index.html'));
      assert.ok(names.includes('LICENSE.txt'));
      assert.ok(names.includes('THIRD_PARTY_LICENSES.txt'));
      assert.ok(names.length >= 5);
      for (const name of names.filter((entry) => ![
        'index.html', 'LICENSE.txt', 'THIRD_PARTY_LICENSES.txt',
      ].includes(entry))) {
        assert.match(name, /^assets\/admin-[a-f0-9]{8}\.(?:css|js)$/u);
      }
    } else {
      assert.deepEqual(names, expectedFiles);
      assert.equal(layoutTree(records), TREE_SHA256[component]);
    }
    for (const record of records) {
      assert.ok(record.byteSize > 0 && record.byteSize < 8 * 1024 * 1024);
      assert.ok(record.contentType);
      assert.match(record.sha256, /^[a-f0-9]{64}$/u);
      const relative = record.path.slice('payload/'.length);
      if (Object.hasOwn(FROZEN_LIFECYCLE_SHA256, relative)) {
        assert.equal(record.sha256, FROZEN_LIFECYCLE_SHA256[relative]);
      }
      const basename = path.posix.basename(record.path);
      const fingerprint = basename.match(/-([a-f0-9]{8})\.(?:css|js)$/u)?.[1];
      if (fingerprint && component !== 'admin') assert.equal(record.sha256.startsWith(fingerprint), true);
    }
  }
});

test('generated admin distribution carries the project and complete production dependency license texts', async () => {
  const [projectLicense, distributedLicense, thirdPartyLicenses, lock] = await Promise.all([
    readFile(new URL('../LICENSE', import.meta.url), 'utf8'),
    readFile(componentUrl('admin', 'LICENSE.txt'), 'utf8'),
    readFile(componentUrl('admin', 'THIRD_PARTY_LICENSES.txt'), 'utf8'),
    readFile(new URL('../package-lock.json', import.meta.url), 'utf8').then(JSON.parse),
  ]);
  assert.equal(distributedLicense, projectLicense);
  assert.doesNotMatch(distributedLicense, /\r/u);
  assert.doesNotMatch(thirdPartyLicenses, /\r/u);
  assert.match(thirdPartyLicenses, /^THIRD-PARTY LICENSE TEXTS FOR ANKKA GATEWAY ADMIN/u);
  const expectedPackages = [];
  for (const [relative, value] of Object.entries(lock.packages)) {
    if (!relative.startsWith('node_modules/') || value.dev === true || value.link === true) continue;
    const manifest = JSON.parse(await readFile(new URL(`../${relative}/package.json`, import.meta.url), 'utf8'));
    assert.ok(thirdPartyLicenses.includes(`Package: ${manifest.name}@${manifest.version}`));
    expectedPackages.push({ relative, heading: `${manifest.name}@${manifest.version}` });
  }
  expectedPackages.sort((left, right) => left.relative < right.relative ? -1 : left.relative > right.relative ? 1 : 0);
  assert.deepEqual(
    [...thirdPartyLicenses.matchAll(/^Package: (.+)$/gmu)].map((match) => match[1]),
    expectedPackages.map((entry) => entry.heading),
  );
  const generator = await readFile(new URL('../scripts/write-admin-license-bundle.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(generator, /localeCompare/u);
  assert.match(generator, /new TextDecoder\('utf-8', \{ fatal: true \}\)/u);
});

test('admin and installer HTML use external same-origin assets without inline execution surfaces', async () => {
  for (const component of ['admin', 'installer']) {
    const html = await readFile(componentUrl(component, 'index.html'), 'utf8');
    assert.match(html, /^<!doctype html>/u);
    assert.match(html, /<html lang="en">/u);
    assert.match(html, /<meta name="viewport" content="width=device-width, initial-scale=1"\s*\/?\s*>/u);
    assert.doesNotMatch(html, /<(?:script|style)(?![^>]*\bsrc=)[^>]*>[^<]/iu);
    assert.doesNotMatch(html, /\s(?:on[a-z]+|style)\s*=/iu);
    assert.doesNotMatch(html, /(?:href|src)="https?:\/\//iu);
    const sources = [...html.matchAll(/<(?:link|script)\b[^>]*(?:href|src)="([^"]+)"/giu)]
      .map((match) => match[1]);
    assert.equal(sources.length >= 2, true);
    if (component === 'installer') assert.equal(sources.length, 2);
    for (const source of sources) {
      assert.match(source, /^\/assets\/[a-z]+-[a-f0-9]{8}\.(?:css|js)$/u);
      const file = await readFile(componentUrl(component, source.slice(1)));
      if (component === 'installer') {
        assert.equal(sha256(file).startsWith(source.match(/-([a-f0-9]{8})\./u)[1]), true);
      }
    }
  }
});

test('installer assets cover the exact hosted session, plan, deploy, result, and removal contract', async () => {
  const html = await readFile(new URL('installer/index.html', ROOT), 'utf8');
  const script = await readFile(new URL('installer/assets/installer-562e903f.js', ROOT), 'utf8');
  for (const route of ['/', '/gateway', '/review', '/deploy', '/manage', '/oauth/handoff', '/oauth/callback', '/result']) {
    if (route !== '/') assert.match(`${html}\n${script}`, new RegExp(route.replace('/', '\\/'), 'u'));
  }
  for (const endpoint of [
    '/api/session', '/api/discovery', '/api/selection', '/api/plan', '/api/deploy', '/api/oauth/handoff',
    '/api/management/authorize', '/api/management/context', '/api/uninstall/plan', '/api/uninstall',
    '/api/returning-uninstall', '/api/returning-uninstall/recovery/plan',
    '/api/returning-uninstall/recovery',
  ]) assert.ok(script.includes(`'${endpoint}'`));
  assert.match(script, /'x-csrf-token'/u);
  assert.match(script, /credentials: 'same-origin'/u);
  assert.match(script, /redirect: 'error'/u);
  assert.match(script, /origin === 'https:\/\/dash\.cloudflare\.com'/u);
  assert.match(script, /origin === 'https:\/\/deploy\.ankka\.ai'/u);
  assert.match(script, /!url\.username && !url\.password && !url\.port/u);
  assert.match(script, /status: 'user_authorization_required'/u);
  assert.match(script, /const management = await managementCallbackContext\(\)/u);
  assert.match(script, /window\.location\.replace\(management\.managementUrl\)/u);
  assert.match(script, /state\.callbackStreamActive \|\| state\.discovery/u);
  assert.match(`${html}\n${script}`, /Create Cloudflare sign-in link/u);
  assert.match(`${html}\n${script}`, /Open Cloudflare sign-in/u);
  assert.match(script, /window\.open\('about:blank', '_blank'\)/u);
  assert.match(script, /Finish connecting Cloudflare in the new tab/u);
  assert.match(script, /suggestedGatewayName\(target\.accountName\)/u);
  assert.doesNotMatch(script, /`\$\{target\.accountName\} Gateway`/u);
  assert.doesNotMatch(script, /window\.location\.assign/u);
  assert.match(script, /document\.modelContext/u);
  for (const tool of [
    'begin_cloudflare_discovery', 'configure_gateway', 'create_review_plan', 'get_installer_status',
    'begin_authorization', 'create_removal_plan', 'begin_removal',
  ]) assert.ok(script.includes(`name: '${tool}'`));
  assert.match(script, /failure: deployment\.failure/u);
  assert.match(script, /Diagnostic: \$\{text\(code\) \|\| 'internal_error'\}/u);
  assert.match(script, /oauth_exchange_failed: 'Cloudflare returned to the installer/u);
  assert.match(script, /admin_email_invalid/u);
  assert.match(script, /plan_hash_mismatch/u);
  assert.match(script, /rate_limited: 'This installer is receiving too many requests/u);
  assert.match(script, /abuse_controls_unavailable: 'The installer request protection/u);
  assert.match(script, /error\.code === 'rate_limited' \|\| error\.status >= 500/u);
  assert.doesNotMatch(script, /(?:localStorage|sessionStorage|document\.cookie|innerHTML|insertAdjacentHTML|eval\s*\()/u);
  assert.doesNotMatch(`${html}\n${script}`, /(?:provider.?id|journal|tombstone|cloudflareAccessToken|client.?secret)/iu);
});

test('admin assets provide safe source discovery, signed updates, one-time apply, and WebMCP tools', async () => {
  const html = await readFile(componentUrl('admin', 'index.html'), 'utf8');
  const script = await componentText('admin', '.js');
  for (const endpoint of [
    '/api/status', '/api/sources', '/api/sources/discover', '/api/source-actions',
    '/api/update', '/api/update-actions',
  ]) {
    assert.ok(script.includes(endpoint));
  }
  for (const tool of [
    'list_mcp_sources', 'discover_mcp_source', 'save_mcp_source_draft', 'apply_mcp_source',
    'check_gateway_update', 'review_gateway_update', 'apply_gateway_update', 'rollback_gateway_update',
  ]) {
    assert.ok(script.includes(tool));
  }
  assert.match(script, /one-time Cloudflare authorization/iu);
  assert.match(script, /No sources yet/u);
  assert.match(script, /Stable release channel/u);
  assert.match(script, /untrustedContentHint/u);
  assert.match(script, /document\.modelContext/u);
  const sourceFiles = (await readdir(new URL('../apps/admin/src/', import.meta.url), { recursive: true }))
    .filter((file) => /\.(?:ts|tsx)$/u.test(file));
  const source = (await Promise.all(sourceFiles.map((file) => readFile(new URL(`../apps/admin/src/${file}`, import.meta.url), 'utf8')))).join('\n');
  assert.doesNotMatch(source, /(?:localStorage|document\.cookie|dangerouslySetInnerHTML|innerHTML|insertAdjacentHTML|eval\s*\(|console\.(?:log|info|warn|error|debug)|\b(?:Sentry|Datadog|Google Analytics|Segment|PostHog)\b)/iu);
});

test('plain CSS keeps the reviewed typography and accessibility floors', async () => {
  const adminCss = await componentText('admin', '.css');
  assert.match(adminCss, /--font-sans:Inter,\s*ui-sans-serif/u);
  assert.match(adminCss, /font-synthesis:none/u);
  assert.match(adminCss, /-webkit-font-smoothing:antialiased/u);
  assert.match(adminCss, /line-height:1\.6/u);
  assert.match(adminCss, /max-width:65ch/u);
  assert.match(adminCss, /text-wrap:balance/u);
  assert.match(adminCss, /:focus-visible/u);
  assert.match(adminCss, /@media\(prefers-reduced-motion:reduce\)/u);
  assert.doesNotMatch(adminCss, /@font-face|\.ttf|\.otf/iu);
  assert.match(adminCss, /--color-canvas:#fbfaf6/u);
  assert.match(adminCss, /--color-brand:#3d132c/u);
  assert.match(adminCss, /--color-sidebar:#250e1c/u);

  const installerCss = await readFile(new URL('installer/assets/installer-2f74774a.css', ROOT), 'utf8');
  {
    const css = installerCss;
    assert.match(css, /font-family:\s*Inter, ui-sans-serif, system-ui/u);
    assert.match(css, /font-synthesis:\s*none/u);
    assert.match(css, /-webkit-font-smoothing:\s*antialiased/u);
    assert.match(css, /line-height:\s*(?:1\.5[5-9]|1\.6)/u);
    assert.match(css, /max-width:\s*65ch/u);
    assert.match(css, /text-wrap:\s*balance/u);
    assert.match(css, /:focus-visible/u);
    assert.match(css, /@media \(prefers-reduced-motion: reduce\)/u);
    assert.doesNotMatch(css, /@font-face|\.ttf|\.otf/iu);
    assert.match(css, /--canvas:\s*#fbfaf6/u);
    assert.match(css, /--accent:\s*#3d132c/u);
    assert.match(css, /--sidebar:\s*#250e1c/u);
  }
  assert.match(installerCss, /--cream:\s*#d3cfb6/u);
  assert.match(installerCss, /font-family:\s*var\(--font-display\)/u);
  assert.match(installerCss, /input,\s*\nselect,\s*\ntextarea[\s\S]*?font-size:\s*1rem/u);
});

test('admin and installer carry the reviewed Ankka wordmark and navigation treatment', async () => {
  const admin = await componentText('admin', '.js');
  const installer = await readFile(new URL('installer/index.html', ROOT), 'utf8');
  assert.match(admin, /viewBox:"0 0 175 19"/u);
  assert.match(installer, /class="wordmark" viewBox="0 0 175 19"/u);
  assert.match(admin, /M0 18\.2697V5\.97501/u);
  assert.match(installer, /M0 18\.2697V5\.97501/u);
  assert.match(admin, /Gateway management/u);
  assert.match(installer, /class="product-label">MCP Gateway installer/u);
  assert.match(installer, /class="step-indicators" aria-label="Installation progress"/u);
  assert.doesNotMatch(installer, /<aside\b/iu);
  assert.doesNotMatch(installer, /class="canary-badge"/u);
});

test('public payload has no source maps, credential literals, browser/customer beacons, or logging', async () => {
  const records = (await Promise.all(Object.keys(COMPONENTS).map(componentRecords))).flat();
  for (const record of records) {
    const [, component, ...segments] = record.path.split('/');
    const body = await readFile(componentUrl(component, segments.join('/')), 'utf8');
    assert.doesNotMatch(body, /sourceMappingURL\s*=/iu);
    assert.doesNotMatch(body, /-----BEGIN [A-Z ]*PRIVATE KEY-----/u);
    if (component !== 'admin') assert.doesNotMatch(body, /\b(?:Sentry|Datadog|Google Analytics|Segment|PostHog)\b/iu);
    if (component !== 'admin') assert.doesNotMatch(body, /console\.(?:log|info|warn|error|debug)/u);
    if (component.startsWith('worker')) {
      assert.doesNotMatch(body, /navigator\.sendBeacon|\bNEL\b|Report-To/iu);
    }
  }
});

test('signed customer Worker variants disable Ankka telemetry independently of hosted NEL', () => {
  const variants = [
    APPROVED_CLOUDFLARE_CONTRACT,
    APPROVED_CLOUDFLARE_CONTRACT.workerVariants.cleanup,
    APPROVED_CLOUDFLARE_CONTRACT.workerVariants.retirement,
  ];
  for (const variant of variants) {
    assert.deepEqual(variant.dependenciesInstrumentation, { enabled: false });
    assert.deepEqual(variant.observability, { enabled: false });
    assert.equal(variant.sendMetrics, false);
  }
});
