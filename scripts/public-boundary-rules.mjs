import * as v from 'valibot';

const OBJECT_SCHEMA = v.object({});
const STRING_SCHEMA = v.string();

export const forbiddenNames = Object.freeze([
  /^\.env(?:\.|$)/u,
  /^\.dev\.vars(?:\.|$)/u,
  /\.pem$/u,
  /\.key$/u,
  /\.p12$/u,
  /\.tfstate(?:\.|$)/u,
  /^\.DS_Store$/u,
  /^canary\.json$/u,
  /^exact-payload-canary\.state\.json$/u,
  /^isolated-canary-target.*\.json$/u,
  /^(?:github-release-plan|publication-receipt|r2-object-plan|release-envelope|release-verification|reviewed-canary-record|sbom\.cdx)\.json$/u,
  /^(?:reviewed-canary-worker|reviewed-rollback-worker)\.mjs$/u,
  /^wrangler\.(?:canary|rollback)\.toml$/u,
]);

export const allowedExampleNames = Object.freeze(new Set([
  '.env.example',
  '.dev.vars.example',
]));

export const forbiddenGeneratedPath =
  /(?:^|\/)(?:node_modules|coverage|dist|\.wrangler|\.terraform)(?:\/|$)/u;

export const MAX_PUBLIC_TEXT_BYTES = 2_000_000;

const TEXT_FILENAMES = new Set([
  '.editorconfig',
  '.gitattributes',
  '.gitignore',
  '.npmrc',
  '.nvmrc',
  'codeowners',
  'dockerfile',
  'license',
  'makefile',
  'notice',
  'readme',
]);

const TEXT_EXTENSIONS = new Set([
  '.c', '.cjs', '.conf', '.cpp', '.css', '.csv', '.env', '.graphql', '.h', '.html',
  '.ini', '.java', '.js', '.json', '.jsonc', '.jsx', '.lock', '.md', '.mdx', '.mjs',
  '.mts', '.properties', '.py', '.rb', '.rs', '.scss', '.sh', '.sql', '.svg', '.toml',
  '.ts', '.tsx', '.txt', '.xml', '.yaml', '.yml',
]);

const BINARY_EXTENSIONS = new Set([
  '.7z', '.avif', '.bin', '.br', '.bz2', '.dmg', '.eot', '.gif', '.gz', '.ico',
  '.jar', '.jpeg', '.jpg', '.mov', '.mp3', '.mp4', '.ogg', '.otf', '.pdf', '.png',
  '.tar', '.tgz', '.ttf', '.wasm', '.webm', '.webp', '.woff', '.woff2', '.zip',
]);

const CREDENTIAL_NAMES = Object.freeze([
  'BOOTSTRAP_NONCE_DERIVATION_KEY',
  'CLOUDFLARE_API_KEY',
  'CLOUDFLARE_API_TOKEN',
  'CLOUDFLARE_OAUTH_CLIENT_SECRET',
  'CLOUDFLARE_OAUTH_TOKEN',
  'DEPLOY_SESSION_ENCRYPTION_KEY',
  'GITHUB_TOKEN',
  'NPM_TOKEN',
]);

const CREDENTIAL_ASSIGNMENT = new RegExp(
  `\\b(?:${CREDENTIAL_NAMES.join('|')})\\b\\s*(=|:)\\s*` +
    '(?:"([^"\\r\\n]*)"|\'([^\'\\r\\n]*)\'|`([^`\\r\\n]*)`|([^\\s,;}\\]\\\\\\r\\n]+))',
  'gu',
);

const SAFE_PLACEHOLDER =
  /(?:^|[-_.])(?:dummy|example|fake|fixture|never[-_]?store|placeholder|replace[-_]?me|sample|secret[-_]?value|synthetic|test(?:[-_]?only)?|token[-_]?value|key[-_]?value)(?:$|[-_.])/iu;

export const forbiddenContent = Object.freeze([
  { label: 'private key material', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/u },
  { label: 'GitHub token', pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/u },
  {
    label: 'GitHub fine-grained token',
    pattern: new RegExp(`\\b${['github', 'pat'].join('_')}_[A-Za-z0-9_]{20,}\\b`, 'u'),
  },
  {
    label: 'AWS access key',
    pattern: new RegExp(
      `\\b(?:${['AK', 'IA'].join('')}|${['AS', 'IA'].join('')})[A-Z0-9]{16}\\b`,
      'u',
    ),
  },
  {
    label: 'legacy private product name',
    pattern: new RegExp(
      `\\b(?:${['LU', 'NA-BLS'].join('')}|${['OhDear', 'Baby'].join('')})\\b`,
      'iu',
    ),
  },
  {
    label: 'retired gateway product name',
    pattern: new RegExp(
      `(?:\\b${['Ankka', 'Company', 'Gateway'].join('\\s+')}\\b|` +
      `\\b${['Company', 'Gateway'].join('\\s+')}\\b|` +
      `\\b${['ankka', 'company', 'gateway'].join('-')}\\b|` +
      `@ankka/${['company', 'gateway'].join('-')}\\b)`,
      'iu',
    ),
  },
]);

export function classifyPublicPath(relative) {
  const basename = relative.split('/').at(-1).toLowerCase();
  if (TEXT_FILENAMES.has(basename)) return 'text';
  const extension = basename.includes('.') ? `.${basename.split('.').at(-1)}` : '';
  if (TEXT_EXTENSIONS.has(extension)) return 'text';
  if (BINARY_EXTENSIONS.has(extension)) return 'binary';
  return 'unknown';
}

export function findForbiddenContentLabels(text) {
  const labels = new Set();
  for (const check of forbiddenContent) {
    if (check.pattern.test(text)) labels.add(check.label);
  }
  if (hasEmbeddedCredentialAssignment(text)) {
    labels.add('embedded opaque credential assignment');
  }
  return [...labels];
}

export function safeDisplayLocation(value, kind) {
  return findForbiddenContentLabels(value).length === 0
    ? value
    : `<redacted ${kind}>`;
}

export function generatedReleaseArtifactLabel(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isRecord(value)) return null;

  if (
    value.schemaVersion === 2 &&
    v.is(STRING_SCHEMA, value.manifest) &&
    v.is(STRING_SCHEMA, value.signature) &&
    v.is(STRING_SCHEMA, value.signatureContext) &&
    v.is(STRING_SCHEMA, value.keyId) &&
    v.is(STRING_SCHEMA, value.channel)
  ) return 'generated signed release envelope';

  if (
    value.schemaVersion === 1 &&
    isRelease(value.release) &&
    isCommit(value.sourceCommit) &&
    isRecord(value.artifact) &&
    v.is(STRING_SCHEMA, value.artifact.treeSha256) &&
    isRecord(value.components) &&
    isRecord(value.cloudflare) &&
    Array.isArray(value.oauthScopeIds)
  ) return 'generated release candidate manifest';

  if (
    value.schemaVersion === 1 &&
    isRelease(value.release) &&
    Array.isArray(value.objects) &&
    Number.isSafeInteger(value.objectCount) &&
    isRecord(value.immutability) &&
    v.is(STRING_SCHEMA, value.prefix)
  ) return 'generated R2 publication plan';

  if (
    value.schemaVersion === 1 &&
    isRelease(value.release) &&
    isCommit(value.sourceCommit) &&
    Array.isArray(value.assets) &&
    v.is(STRING_SCHEMA, value.repository) &&
    v.is(STRING_SCHEMA, value.tag) &&
    v.is(STRING_SCHEMA, value.title)
  ) return 'generated GitHub release plan';

  if (
    value.schemaVersion === 1 &&
    isRelease(value.release) &&
    isCommit(value.sourceCommit) &&
    v.is(STRING_SCHEMA, value.publicKey) &&
    value.signatureAlgorithm === 'ed25519' &&
    v.is(STRING_SCHEMA, value.releaseEnvelopeSha256)
  ) return 'generated release verification record';

  if (
    value.bomFormat === 'CycloneDX' &&
    isRecord(value.metadata) &&
    isRecord(value.metadata.component) &&
    value.metadata.component.name === '@ankka/mcp-gateway' &&
    String(value.metadata.component['bom-ref'] ?? '').startsWith('urn:ankka:mcp-gateway:')
  ) return 'generated release SBOM';

  if (
    value.schemaVersion === 1 &&
    isRelease(value.release) &&
    v.is(STRING_SCHEMA, value.accountId) &&
    v.is(STRING_SCHEMA, value.bucketName) &&
    v.is(STRING_SCHEMA, value.objectPlanSha256) &&
    v.is(STRING_SCHEMA, value.releaseEnvelopeSha256)
  ) return 'generated publication receipt';

  return null;
}

function hasEmbeddedCredentialAssignment(text) {
  CREDENTIAL_ASSIGNMENT.lastIndex = 0;
  for (const match of text.matchAll(CREDENTIAL_ASSIGNMENT)) {
    const operator = match[1];
    const quoted = match[2] ?? match[3] ?? match[4];
    const bare = match[5];
    const raw = (quoted ?? bare ?? '').trim();
    if (operator === ':' && quoted === undefined && /^[A-Za-z_$][\w$]*$/u.test(raw)) {
      continue;
    }
    if (raw.length === 0 || safeCredentialPlaceholder(raw)) continue;
    return true;
  }
  return false;
}

function safeCredentialPlaceholder(value) {
  return (
    /^<[^>\r\n]+>$/u.test(value) ||
    /^(?:…|\.\.\.)$/u.test(value) ||
    /^\$\{(?:\{)?\s*(?:env|secrets)\./u.test(value) ||
    /^\$[A-Z_{]/u.test(value) ||
    /^(?:process\.)?env\.[A-Z0-9_]+$/u.test(value) ||
    value.startsWith('/') ||
    SAFE_PLACEHOLDER.test(value) ||
    /^[A-Za-z_$][\w$]*(?:\.[\w$]+)*\(/u.test(value)
  );
}

function isRecord(value) {
  return v.is(OBJECT_SCHEMA, value) && !Array.isArray(value);
}

function isRelease(value) {
  return v.is(STRING_SCHEMA, value) && /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u.test(value);
}

function isCommit(value) {
  return v.is(STRING_SCHEMA, value) && /^[a-f0-9]{40}$/u.test(value);
}
