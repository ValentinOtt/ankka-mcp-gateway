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
  installer: ['assets/ankka-85bfe235.svg', 'assets/installer-953fc6de.css', 'assets/installer-b2899467.js', 'index.html'],
  worker: ['index.js'],
  'worker-cleanup': ['index.js'],
  'worker-retirement': ['index.js'],
});
const TREE_SHA256 = Object.freeze({
  installer: '1b646d2db0275e2b4d801ff05ff3ea4957e5801b4cbcef1b6328db468bb708d3',
  worker: 'c24ad0424fc2fc5e7a1426eaba838aa3c594dd6241b3d3b9f22aece01275664e',
  'worker-cleanup': '417ff8beb85d4c7122d57052f873914173b9b37456bc0d134c69dd0dbdccdf1d',
  'worker-retirement': '757311596630d21599397caf0ef43e07c4c8d005148bff280ba8ee538d9d6c9f',
});
const FROZEN_LIFECYCLE_SHA256 = Object.freeze({
  'worker-cleanup/index.js': '5e6f32d9d578bb2facb58f7ff6a8d244db2538a55d76c439027413b7226a9261',
  'worker-retirement/index.js': '506e91323d6f6c89398a15799bfcde6cb4d271a5d6bf28a4fbbd422331751bda',
});
const CONTENT_TYPES = Object.freeze({
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
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
        assert.match(name, /^assets\/admin-[a-f0-9]{8}\.(?:css|js|svg)$/u);
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
      const fingerprint = basename.match(/-([a-f0-9]{8})\.(?:css|js|svg)$/u)?.[1];
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
    let manifest;
    try {
      manifest = JSON.parse(await readFile(new URL(`../${relative}/package.json`, import.meta.url), 'utf8'));
    } catch {
      assert.equal(value.optional, true);
      const name = relative.slice('node_modules/'.length);
      assert.match(name, /^@(?:esbuild\/|rolldown\/binding-)/u);
      manifest = { name, version: value.version };
    }
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
    if (component === 'installer') assert.equal(sources.length, 3);
    for (const source of sources) {
      assert.match(source, /^\/assets\/[a-z]+-[a-f0-9]{8}\.(?:css|js|svg)$/u);
      const file = await readFile(componentUrl(component, source.slice(1)));
      if (component === 'installer') {
        assert.equal(sha256(file).startsWith(source.match(/-([a-f0-9]{8})\./u)[1]), true);
      }
    }
  }
});

test('admin and installer package the supplied Ankka favicon as a same-origin SVG', async () => {
  const original = await readFile(new URL('../apps/admin/src/assets/ankka-icon.svg', import.meta.url));
  assert.equal(sha256(original), '85bfe235ef97e3af373044f4af6de88276b788ba620c4b543c4c0708c98616fb');
  for (const component of ['admin', 'installer']) {
    const html = await readFile(componentUrl(component, 'index.html'), 'utf8');
    const icons = [...html.matchAll(/<link\b[^>]*rel="icon"[^>]*>/gu)];
    assert.equal(icons.length, 1);
    assert.match(icons[0][0], /type="image\/svg\+xml"/u);
    assert.match(icons[0][0], /sizes="any"/u);
    const href = icons[0][0].match(/href="([^"]+)"/u)?.[1];
    assert.ok(href);
    assert.match(href, /^\/assets\/(?:ankka|admin)-[a-f0-9]{8}\.svg$/u);
    assert.deepEqual(await readFile(componentUrl(component, href.slice(1))), original);
  }
});

test('installer assets cover the exact hosted session, plan, deploy, result, and removal contract', async () => {
  const html = await readFile(new URL('installer/index.html', ROOT), 'utf8');
  const script = await readFile(new URL('installer/assets/installer-b2899467.js', ROOT), 'utf8');
  assert.doesNotMatch(`${html}\n${script}`, /\bcustomers?\b/iu);
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
  assert.match(script, /origin === window\.location\.origin/u);
  assert.match(script, /!url\.username && !url\.password && !url\.port/u);
  assert.match(script, /status: 'user_authorization_required'/u);
  assert.match(script, /const management = await managementCallbackContext\(\)/u);
  assert.match(script, /window\.location\.replace\(management\.managementUrl\)/u);
  assert.match(script, /state\.callbackStreamActive \|\| state\.discovery/u);
  assert.match(html, /id="authorize"[^>]*>Continue to Cloudflare/u);
  assert.match(`${html}\n${script}`, /Continue to Cloudflare/u);
  assert.doesNotMatch(html, /target="_blank"/u);
  assert.doesNotMatch(script, /window\.open/u);
  assert.match(script, /suggestedGatewayName\(target\.accountName\)/u);
  assert.doesNotMatch(script, /`\$\{target\.accountName\} Gateway`/u);
  assert.match(script, /window\.location\.assign\(handoff\)/u);
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

// Provider names in setup guidance are not telemetry. Reject executable SDK
// imports, instrumentation calls and beacon APIs, including aliased SDK imports.
const ADMIN_TELEMETRY = /(?:\b(?:from\s*|import\s*(?:\(\s*)?|require\s*\(\s*)['"](?:@sentry\/|@datadog\/|@segment\/|posthog(?:-js|-react)?\b|react-ga\b|react-ga4\b|analytics-node\b)|\b(?:Sentry\.(?:init|captureException|captureMessage)|datadogRum\.|datadogLogs\.|posthog\.(?:init|capture|identify)|analytics\.(?:track|page|identify)|gtag\s*\(|sendBeacon\s*\(|dataLayer\.push\s*\())/iu;

test('admin telemetry check distinguishes provider documentation from executable instrumentation', () => {
  assert.doesNotMatch('Sentry, Google Analytics, Segment and PostHog provider setup guides', ADMIN_TELEMETRY);
  assert.doesNotMatch('https://mcp.sentry.dev/mcp', ADMIN_TELEMETRY);
  for (const source of [
    'import { init as observe } from "@sentry/browser"',
    'import("@datadog/browser-rum")',
    'require("posthog-js")',
    'import "@segment/analytics-next"',
    'Sentry.init({})', 'analytics.track("event")', 'posthog.capture("event")',
    'navigator.sendBeacon("https://example.com", body)', 'gtag("event", "visit")',
    'window.dataLayer.push({event: "visit"})',
  ]) assert.match(source, ADMIN_TELEMETRY);
});

test('admin assets provide safe source discovery, signed updates, one-time apply, and WebMCP tools', async () => {
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
  assert.match(script, /one-time Cloudflare OAuth handoff/iu);
  assert.match(script, /No sources yet/u);
  assert.match(script, /release channel/u);
  assert.match(script, /untrustedContentHint/u);
  assert.match(script, /document\.modelContext/u);
  const sourceFiles = (await readdir(new URL('../apps/admin/src/', import.meta.url), { recursive: true }))
    .filter((file) => /\.(?:ts|tsx)$/u.test(file));
  const source = (await Promise.all(sourceFiles.map((file) => readFile(new URL(`../apps/admin/src/${file}`, import.meta.url), 'utf8')))).join('\n');
  assert.doesNotMatch(source, /(?:localStorage|document\.cookie|dangerouslySetInnerHTML|innerHTML|insertAdjacentHTML|eval\s*\(|console\.(?:log|info|warn|error|debug))/iu);
  assert.doesNotMatch(source, ADMIN_TELEMETRY);
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
  assert.match(adminCss, /@media\s*\(prefers-reduced-motion:\s*reduce\)/u);
  assert.doesNotMatch(adminCss, /@font-face|\.ttf|\.otf/iu);
  assert.match(adminCss, /--color-canvas:#191919/u);
  assert.match(adminCss, /--color-brand:#dedede/u);
  assert.match(adminCss, /--color-sidebar:#131313/u);

  const installerCss = await readFile(new URL('installer/assets/installer-953fc6de.css', ROOT), 'utf8');
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
    assert.match(css, /color-scheme:\s*dark/u);
    assert.match(css, /--canvas:\s*#1b1b1b/u);
    assert.match(css, /--accent:\s*#ededed/u);
    assert.match(css, /--sidebar:\s*#1b1b1b/u);
  }
  assert.match(installerCss, /--cream:\s*#141414/u);
  assert.doesNotMatch(installerCss, /--font-display|font-family:\s*var\(--font-display\)/u);
  assert.match(installerCss, /--font-size-body:\s*1rem/u);
  assert.match(installerCss, /input,\s*\nselect,\s*\ntextarea[\s\S]*?font-size:\s*var\(--font-size-body\)/u);
  assert.match(installerCss, /\.step-pill\s*\{[^}]*border-radius:\s*999px/u);
  assert.match(installerCss, /\.operation-copy > p:last-child\s*\{[^}]*font-size:\s*var\(--font-size-body\)/u);
  assert.match(installerCss, /\.stage-position\s*\{[^}]*font-size:\s*0\.8125rem/u);
});

test('admin and installer carry the reviewed Ankka wordmark and navigation treatment', async () => {
  const admin = await componentText('admin', '.js');
  const installer = await readFile(new URL('installer/index.html', ROOT), 'utf8');
  assert.match(admin, /viewBox:["'`]0 0 175 19["'`]/u);
  assert.match(installer, /class="wordmark" viewBox="0 0 175 19"/u);
  assert.match(admin, /M0 18\.2697V5\.97501/u);
  assert.match(installer, /M0 18\.2697V5\.97501/u);
  assert.match(admin, /Gateway management/u);
  assert.doesNotMatch(installer, /class="product-label"/u);
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
