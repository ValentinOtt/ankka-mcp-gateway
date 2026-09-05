/**
 * Offline, secret-free builder for an exact MCP Gateway release candidate.
 *
 * Input: a public `ankka-mcp-gateway` checkout whose release sources are
 * exactly the committed bytes of one stated commit. The React/Kumo admin and
 * the final/bootstrap customer Worker entrypoints are built deterministically;
 * the remaining payload components come from `payload/`. Output: a brand-new
 * directory holding the canonical `manifest.json` and a create-only copy of
 * `payload/` — precisely the `--release-dir` shape `sign-gateway-release.mjs`
 * consumes. The builder never signs, never publishes, never touches the
 * network, and self-verifies its output with the signer's own loader so a
 * successful build means the signer would accept the directory byte-for-byte.
 *
 * Component and artifact tree digests use the signer's definition:
 * SHA-256 over the canonical JSON of the sorted file records (path, byteSize,
 * contentType, sha256). They are not the public repository's layout-test tree
 * digests, which hash a different record shape.
 */
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants as FS_CONSTANTS } from 'node:fs';
import { lstat, mkdir, open, readdir, readFile, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { build as esbuildBuild, version as esbuildRuntimeVersion } from 'esbuild';
import * as v from 'valibot';

import {
  APPROVED_CLOUDFLARE_CONTRACT,
  REQUIRED_OAUTH_SCOPES,
  canonicalJson,
  loadVerifiedPublicRelease,
} from './sign-gateway-release.mjs';

const execFileAsync = promisify(execFile);

const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 32 * 1024 * 1024;
const MAX_FILES = 10_000;
const RELEASE_PATTERN = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const COMMIT_PATTERN = /^[a-f0-9]{40}$/u;
const MAX_CONTROL_PLANE_ORIGIN_LENGTH = 2_048;
const CONTROL_PLANE_ORIGIN_DECLARATION =
  "const CONTROL_PLANE_ORIGIN = 'https://deploy.ankka.ai';";
const CONTROL_PLANE_ORIGIN_MARKER = 'ankka-control-plane-origin:';
const EXPECTED_ESBUILD_VERSION = '0.28.1';
const SAFE_SEGMENT = /^[A-Za-z0-9._-]+$/u;
const STRING_SCHEMA = v.string();
const RELEASE_TOOL_PATHS = Object.freeze([
  'apps/installer/scripts/build-gateway-release-candidate.mjs',
  'apps/installer/scripts/sign-gateway-release.mjs',
]);
const COMPONENTS = Object.freeze([
  Object.freeze({ name: 'admin', directory: 'admin', source: ['apps', 'admin', 'dist'], web: true, required: 'index.html' }),
  Object.freeze({ name: 'installer', directory: 'installer', source: ['payload', 'installer'], web: true, required: 'index.html' }),
  Object.freeze({ name: 'worker', directory: 'worker', generated: 'final', web: false, required: 'index.js' }),
  Object.freeze({ name: 'workerBootstrap', directory: 'worker-bootstrap', generated: 'bootstrap', web: false, required: 'index.js' }),
  Object.freeze({ name: 'workerCleanup', directory: 'worker-cleanup', source: ['payload', 'worker-cleanup'], web: false, required: 'index.js' }),
  Object.freeze({ name: 'workerRetirement', directory: 'worker-retirement', source: ['payload', 'worker-retirement'], web: false, required: 'index.js' }),
]);
const WORKER_CONTENT_TYPES = Object.freeze({
  '.js': 'application/javascript+module',
  '.mjs': 'application/javascript+module',
  '.wasm': 'application/wasm',
});
const WEB_CONTENT_TYPES = Object.freeze({
  '.avif': 'image/avif',
  '.css': 'text/css; charset=utf-8',
  '.gif': 'image/gif',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.jpeg': 'image/jpeg',
  '.jpg': 'image/jpeg',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.otf': 'font/otf',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.ttf': 'font/ttf',
  '.wasm': 'application/wasm',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
});

export class ReleaseCandidateError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ReleaseCandidateError';
    this.code = code;
  }
}

function fail(code) {
  throw new ReleaseCandidateError(code);
}

function lexicalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function extension(filePath) {
  const filename = filePath.slice(filePath.lastIndexOf('/') + 1);
  const dot = filename.lastIndexOf('.');
  return dot < 0 ? '' : filename.slice(dot).toLowerCase();
}

function assertNormalizedText(bytes, contentType) {
  if (!(contentType.includes('; charset=utf-8') ||
      contentType === 'application/javascript+module' ||
      contentType === 'image/svg+xml')) return;
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail('payload_text_invalid');
  }
  if (text.includes('\r') || text.includes('\0')) fail('payload_text_not_lf');
}

function isPlainString(value) {
  return v.is(STRING_SCHEMA, value) && value.length > 0 && !value.includes('\0');
}

export function parseControlPlaneOrigin(value) {
  if (!v.is(STRING_SCHEMA, value) || value.length === 0 || value.length > MAX_CONTROL_PLANE_ORIGIN_LENGTH) {
    fail('invalid_control_plane_origin');
  }
  try {
    const parsed = new URL(value);
    if (
      parsed.protocol !== 'https:' ||
      parsed.username !== '' ||
      parsed.password !== '' ||
      parsed.port !== '' ||
      parsed.pathname !== '/' ||
      parsed.search !== '' ||
      parsed.hash !== '' ||
      parsed.origin !== value ||
      value.includes("'")
    ) fail('invalid_control_plane_origin');
  } catch (error) {
    if (error instanceof ReleaseCandidateError) throw error;
    fail('invalid_control_plane_origin');
  }
  return value;
}

async function validatedWorkerSource(sourceRoot) {
  let bytes;
  try {
    bytes = await readFile(path.join(sourceRoot, 'payload', 'worker', 'index.js'));
  } catch {
    fail('worker_control_plane_origin_anchor_invalid');
  }
  assertNormalizedText(bytes, 'application/javascript+module');
  let source;
  try {
    source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail('worker_control_plane_origin_anchor_invalid');
  }
  const first = source.indexOf(CONTROL_PLANE_ORIGIN_DECLARATION);
  if (
    first < 0 ||
    source.indexOf(
      CONTROL_PLANE_ORIGIN_DECLARATION,
      first + CONTROL_PLANE_ORIGIN_DECLARATION.length,
    ) !== -1
  ) fail('worker_control_plane_origin_anchor_invalid');
  return source;
}

async function git(sourceRoot, args) {
  try {
    const { stdout } = await execFileAsync('git', ['-C', sourceRoot, ...args], {
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
      env: { PATH: process.env.PATH, HOME: process.env.HOME, GIT_CONFIG_NOSYSTEM: '1' },
    });
    return stdout;
  } catch {
    return fail('source_git_unavailable');
  }
}

/**
 * The candidate must be derived from exactly one stated commit. Generated
 * `apps/admin/dist` bytes are intentionally ignored; every source that can
 * influence them, including the generated distribution license bundle, and
 * every hand-authored payload component must be clean.
 */
async function assertExactSourceCommit(sourceRoot, sourceCommit) {
  const head = (await git(sourceRoot, ['rev-parse', '--verify', 'HEAD^{commit}'])).trim();
  if (!COMMIT_PATTERN.test(head)) fail('source_git_unavailable');
  if (head !== sourceCommit) fail('source_commit_mismatch');
  const status = await git(sourceRoot, [
    'status', '--porcelain=v1', '--untracked-files=all', '--',
    'apps/admin', 'apps/installer/package.json', 'apps/installer/src',
    'apps/installer/tsconfig.json', 'package.json', 'package-lock.json', 'LICENSE',
    'scripts/write-admin-license-bundle.mjs',
    'third_party/licenses',
    'apps/installer/scripts/build-reviewed-fault-injection-candidate.mjs',
    ...RELEASE_TOOL_PATHS,
    'payload',
    'apps/read-only-connectors/src',
    'apps/read-only-connectors/package.json',
  ]);
  if (status.trim().length > 0) fail('source_release_inputs_dirty');
}

async function assertReleaseToolingMatchesSource(sourceRoot) {
  for (const relative of RELEASE_TOOL_PATHS) {
    let running;
    let committed;
    try {
      const runningUrl = relative.endsWith('/build-gateway-release-candidate.mjs')
        ? import.meta.url
        : new URL('./sign-gateway-release.mjs', import.meta.url);
      [running, committed] = await Promise.all([
        readFile(fileURLToPath(runningUrl)),
        readFile(path.join(sourceRoot, ...relative.split('/'))),
      ]);
      if (!running.equals(committed)) fail('source_tool_mismatch');
    } catch (error) {
      if (error instanceof ReleaseCandidateError) throw error;
      fail('source_tool_mismatch');
    } finally {
      running?.fill(0);
      committed?.fill(0);
    }
  }
}

async function buildAdminApplication(sourceRoot) {
  try {
    await execFileAsync('npm', ['run', 'build', '--workspace', '@ankka/gateway-admin'], {
      cwd: sourceRoot,
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
      env: { PATH: process.env.PATH, HOME: process.env.HOME },
    });
  } catch {
    fail('admin_build_failed');
  }
}

function customerWorkerOriginPlugin(sourceRoot, controlPlaneOrigin, workerSource) {
  const payloadPath = path.join(sourceRoot, 'payload', 'worker', 'index.js');
  return Object.freeze({
    name: 'ankka-customer-worker-origin',
    setup(build) {
      build.onLoad({ filter: /payload\/worker\/index\.js$/ }, async (args) => {
        if (path.resolve(args.path) !== payloadPath) fail('worker_control_plane_origin_anchor_invalid');
        return {
          contents: workerSource.replace(
            CONTROL_PLANE_ORIGIN_DECLARATION,
            `const CONTROL_PLANE_ORIGIN = '${controlPlaneOrigin}';`,
          ),
          loader: 'js',
        };
      });
    },
  });
}

async function bundleBigQueryWorker(sourceRoot) {
  const result = await esbuildBuild({
    absWorkingDir: sourceRoot, entryPoints: [path.join(sourceRoot, 'apps/read-only-connectors/src/index.ts')],
    bundle: true, format: 'esm', platform: 'browser', target: 'es2022', charset: 'utf8',
    conditions: ['workerd', 'worker', 'browser'], external: ['node:*', 'cloudflare:*'],
    legalComments: 'none', logLevel: 'silent', minify: true, sourcemap: false, write: false,
  });
  if (result.outputFiles.length !== 1 || result.outputFiles[0].contents.byteLength > 4 * 1024 * 1024) fail('bigquery_worker_build_failed');
  return result.outputFiles[0].text;
}

async function bundleCustomerWorker(sourceRoot, controlPlaneOrigin, variant, finalRuntimeSource) {
  if (esbuildRuntimeVersion !== EXPECTED_ESBUILD_VERSION) fail('worker_build_tool_invalid');
  const workerSource = await validatedWorkerSource(sourceRoot);
  const entry = variant === 'final'
    ? path.join(sourceRoot, 'apps', 'installer', 'src', 'customer-gateway-entrypoint.ts')
    : path.join(sourceRoot, 'apps', 'installer', 'src', 'customer-gateway-bootstrap-entrypoint.ts');
  let result;
  try {
    result = await esbuildBuild({
      absWorkingDir: sourceRoot,
      banner: { js: `// ${variant === 'final' ? CONTROL_PLANE_ORIGIN_MARKER + controlPlaneOrigin : 'ankka-bootstrap-runtime:v1'}` },
      bundle: true,
      charset: 'utf8',
      define: variant === 'bootstrap'
        ? { __ANKKA_FINAL_RUNTIME_SOURCE__: JSON.stringify(finalRuntimeSource) }
        : { __ANKKA_BIGQUERY_RUNTIME_SOURCE__: JSON.stringify(await bundleBigQueryWorker(sourceRoot)) },
      entryPoints: [entry],
      format: 'esm',
      legalComments: 'none',
      logLevel: 'silent',
      minify: false,
      platform: 'browser',
      sourcemap: false,
      target: 'es2022',
      treeShaking: true,
      write: false,
      plugins: [customerWorkerOriginPlugin(sourceRoot, controlPlaneOrigin, workerSource)],
    });
  } catch {
    return fail('worker_build_failed');
  }
  if (result.outputFiles.length !== 1) fail('worker_build_failed');
  const output = result.outputFiles[0];
  if (!output || output.contents.byteLength < 1 || output.contents.byteLength > MAX_FILE_BYTES) {
    fail('worker_build_failed');
  }
  const bytes = Buffer.from(output.contents);
  assertNormalizedText(bytes, 'application/javascript+module');
  if (variant === 'final') {
    const marker = `// ${CONTROL_PLANE_ORIGIN_MARKER}${controlPlaneOrigin}\n`;
    const text = bytes.toString('utf8');
    if (
      !text.startsWith(marker) ||
      text.indexOf(marker, marker.length) !== -1 ||
      !text.includes(`var CONTROL_PLANE_ORIGIN = "${controlPlaneOrigin}";`)
    ) {
      bytes.fill(0);
      fail('worker_control_plane_origin_anchor_invalid');
    }
  }
  return bytes;
}

function enumerateGeneratedComponent(component, bytes) {
  const contentType = WORKER_CONTENT_TYPES['.js'];
  const record = Object.freeze({
    byteSize: bytes.byteLength,
    contentType,
    path: `payload/${component.directory}/${component.required}`,
    sha256: sha256Hex(bytes),
  });
  return Object.freeze({
    files: Object.freeze([Object.freeze({ bytes, record })]),
    component: Object.freeze({
      byteSize: record.byteSize,
      fileCount: 1,
      files: Object.freeze([record]),
      treeSha256: sha256Hex(Buffer.from(canonicalJson([record]), 'utf8')),
    }),
  });
}

async function enumerateComponent(sourceRoot, component) {
  const componentRoot = path.join(sourceRoot, ...component.source);
  const rootStat = await lstat(componentRoot).catch(() => null);
  if (!rootStat || rootStat.isSymbolicLink() || !rootStat.isDirectory()) fail('payload_component_missing');
  const files = [];
  const queue = [''];
  let entries = 0;
  while (queue.length > 0) {
    const relativeDirectory = queue.shift();
    const children = await readdir(path.join(componentRoot, relativeDirectory), { withFileTypes: true });
    children.sort((left, right) => lexicalCompare(left.name, right.name));
    for (const child of children) {
      entries += 1;
      if (entries > MAX_FILES || !SAFE_SEGMENT.test(child.name) || child.name === '.' || child.name === '..') {
        fail('payload_entry_unsafe');
      }
      const relative = relativeDirectory ? `${relativeDirectory}/${child.name}` : child.name;
      if (child.isSymbolicLink()) fail('payload_symlink');
      if (child.isDirectory()) {
        queue.push(relative);
        continue;
      }
      if (!child.isFile()) fail('payload_entry_unsafe');
      const manifestPath = `payload/${component.directory}/${relative}`;
      const contentType = (component.web ? WEB_CONTENT_TYPES : WORKER_CONTENT_TYPES)[extension(manifestPath)];
      if (!contentType) fail('payload_content_type_unknown');
      const bytes = await readFile(path.join(componentRoot, relative));
      if (bytes.byteLength === 0 || bytes.byteLength > MAX_FILE_BYTES) fail('payload_file_size');
      assertNormalizedText(bytes, contentType);
      files.push(Object.freeze({
        bytes,
        record: Object.freeze({
          byteSize: bytes.byteLength,
          contentType,
          path: manifestPath,
          sha256: sha256Hex(bytes),
        }),
      }));
    }
  }
  files.sort((left, right) => lexicalCompare(left.record.path, right.record.path));
  if (files.length === 0) fail('payload_component_empty');
  if (!files.some((file) => file.record.path === `payload/${component.directory}/${component.required}`)) {
    fail('payload_component_entry_missing');
  }
  const records = Object.freeze(files.map((file) => file.record));
  const byteSize = records.reduce((total, record) => total + record.byteSize, 0);
  if (!Number.isSafeInteger(byteSize) || byteSize > MAX_PAYLOAD_BYTES) fail('payload_file_size');
  return Object.freeze({
    files,
    component: Object.freeze({
      byteSize,
      fileCount: records.length,
      files: records,
      treeSha256: sha256Hex(Buffer.from(canonicalJson(records), 'utf8')),
    }),
  });
}

async function assertExactPayloadRoot(sourceRoot) {
  const payloadRoot = path.join(sourceRoot, 'payload');
  const payloadStat = await lstat(payloadRoot).catch(() => null);
  if (!payloadStat || payloadStat.isSymbolicLink() || !payloadStat.isDirectory()) fail('payload_missing');
  const entries = await readdir(payloadRoot, { withFileTypes: true });
  const names = entries.map((entry) => entry.name).sort(lexicalCompare);
  const expected = ['installer', 'worker', 'worker-cleanup', 'worker-retirement'].sort(lexicalCompare);
  if (names.length !== expected.length || names.some((name, index) => name !== expected[index])) {
    fail('payload_layout_unexpected');
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink() || !entry.isDirectory()) fail('payload_layout_unexpected');
  }
}

export async function buildReleaseCandidate({ controlPlaneOrigin, sourceDirectory, sourceCommit, release }) {
  if (!isPlainString(sourceDirectory)) fail('invalid_input');
  const parsedControlPlaneOrigin = parseControlPlaneOrigin(controlPlaneOrigin);
  if (!v.is(STRING_SCHEMA, release) || !RELEASE_PATTERN.test(release)) fail('invalid_release');
  if (!v.is(STRING_SCHEMA, sourceCommit) || !COMMIT_PATTERN.test(sourceCommit)) fail('invalid_source_commit');
  let sourceRoot;
  try {
    sourceRoot = await realpath(path.resolve(sourceDirectory));
    if (!(await stat(sourceRoot)).isDirectory()) fail('source_missing');
  } catch (error) {
    if (error instanceof ReleaseCandidateError) throw error;
    fail('source_missing');
  }
  await assertExactSourceCommit(sourceRoot, sourceCommit);
  await assertReleaseToolingMatchesSource(sourceRoot);
  await assertExactPayloadRoot(sourceRoot);
  await enumerateComponent(sourceRoot, Object.freeze({
    name: 'worker-source',
    directory: 'worker',
    source: ['payload', 'worker'],
    web: false,
    required: 'index.js',
  }));
  await buildAdminApplication(sourceRoot);
  await assertExactSourceCommit(sourceRoot, sourceCommit);
  await assertReleaseToolingMatchesSource(sourceRoot);

  const finalRuntime = await bundleCustomerWorker(
    sourceRoot,
    parsedControlPlaneOrigin,
    'final',
    '',
  );
  const bootstrapRuntime = await bundleCustomerWorker(
    sourceRoot,
    parsedControlPlaneOrigin,
    'bootstrap',
    finalRuntime.toString('utf8'),
  );
  const enumerated = {};
  for (const component of COMPONENTS) {
    if (component.generated === 'final') {
      enumerated[component.name] = enumerateGeneratedComponent(component, finalRuntime);
    } else if (component.generated === 'bootstrap') {
      enumerated[component.name] = enumerateGeneratedComponent(component, bootstrapRuntime);
    } else {
      enumerated[component.name] = await enumerateComponent(sourceRoot, component);
    }
  }
  await assertExactSourceCommit(sourceRoot, sourceCommit);
  await assertReleaseToolingMatchesSource(sourceRoot);
  const components = Object.freeze(Object.fromEntries(
    COMPONENTS.map((component) => [component.name, enumerated[component.name].component]),
  ));
  const records = Object.freeze(COMPONENTS
    .flatMap((component) => enumerated[component.name].component.files)
    .sort((left, right) => lexicalCompare(left.path, right.path)));
  for (let index = 1; index < records.length; index += 1) {
    if (records[index - 1].path >= records[index].path) fail('payload_layout_unexpected');
  }
  const byteSize = records.reduce((total, record) => total + record.byteSize, 0);
  if (!Number.isSafeInteger(byteSize) || byteSize > MAX_PAYLOAD_BYTES || records.length > MAX_FILES) {
    fail('payload_file_size');
  }
  const manifest = Object.freeze({
    artifact: Object.freeze({
      byteSize,
      fileCount: records.length,
      treeSha256: sha256Hex(Buffer.from(canonicalJson(records), 'utf8')),
    }),
    cloudflare: APPROVED_CLOUDFLARE_CONTRACT,
    controlPlaneOrigin: parsedControlPlaneOrigin,
    components,
    oauthScopeIds: REQUIRED_OAUTH_SCOPES,
    release,
    schemaVersion: 1,
    sourceCommit,
  });
  const serialized = canonicalJson(manifest);
  const manifestBytes = Buffer.from(serialized, 'utf8');
  return Object.freeze({
    manifest,
    manifestBytes,
    manifestSha256: sha256Hex(manifestBytes),
    files: Object.freeze(COMPONENTS.flatMap((component) => enumerated[component.name].files)),
    sourceRoot,
  });
}

async function writeCreateOnly(target, bytes) {
  const handle = await open(target, FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL, 0o644);
  try {
    await handle.writeFile(bytes);
  } finally {
    await handle.close();
  }
}

/**
 * Materialises `manifest.json` + `payload/` into a directory that must not
 * exist yet, then proves the signer's loader accepts the result.
 */
export async function writeReleaseCandidate(candidate, outputDirectory) {
  if (!isPlainString(outputDirectory)) fail('invalid_output');
  const outputRoot = path.resolve(outputDirectory);
  if (await lstat(outputRoot).catch(() => null)) fail('output_exists');
  const parentStat = await stat(path.dirname(outputRoot)).catch(() => null);
  if (!parentStat || !parentStat.isDirectory()) fail('output_parent_missing');
  await mkdir(outputRoot, { mode: 0o755 });
  for (const file of candidate.files) {
    const target = path.join(outputRoot, ...file.record.path.split('/'));
    await mkdir(path.dirname(target), { recursive: true, mode: 0o755 });
    await writeCreateOnly(target, file.bytes);
  }
  // manifest.json is written last as the completion marker.
  await writeCreateOnly(path.join(outputRoot, 'manifest.json'), candidate.manifestBytes);

  let verified;
  try {
    verified = await loadVerifiedPublicRelease(outputRoot, candidate.manifest.release);
  } catch {
    fail('output_not_signable');
  }
  try {
    if (
      verified.manifest.artifact.treeSha256 !== candidate.manifest.artifact.treeSha256 ||
      !verified.manifestBytes.equals(candidate.manifestBytes)
    ) fail('output_not_signable');
  } finally {
    for (const entry of verified.payload) entry.bytes.fill(0);
    verified.manifestBytes.fill(0);
  }
  return outputRoot;
}

export function candidateSummary(candidate, outputRoot = null) {
  return {
    schemaVersion: 1,
    release: candidate.manifest.release,
    controlPlaneOrigin: candidate.manifest.controlPlaneOrigin,
    sourceCommit: candidate.manifest.sourceCommit,
    artifact: candidate.manifest.artifact,
    components: Object.fromEntries(Object.entries(candidate.manifest.components).map(([name, component]) => [
      name,
      { byteSize: component.byteSize, fileCount: component.fileCount, treeSha256: component.treeSha256 },
    ])),
    manifestSha256: candidate.manifestSha256,
    outputDirectory: outputRoot,
    signed: false,
  };
}

const HELP = `Usage: node scripts/build-gateway-release-candidate.mjs \\
  --source <public ankka-mcp-gateway checkout> \\
  --source-commit <40-hex commit that checkout and release inputs must match> \\
  --control-plane-origin <canonical HTTPS installer origin> \\
  --release <gateway-vX.Y.Z> [--out <new directory>]

Builds the React/Kumo admin, then creates the canonical manifest for that
deterministic output plus the exact committed payload bytes.
Without --out it is a dry run that prints the digests only. With --out it
writes manifest.json plus a create-only copy of payload/ into a directory that
must not exist, then proves the release signer would accept it. Nothing is
signed, published, or uploaded.
`;

function parseCliArguments(argv) {
  if (argv.length === 1 && argv[0] === '--help') return { help: true };
  const valueFlags = new Set(['--source', '--source-commit', '--control-plane-origin', '--release', '--out']);
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    if (!valueFlags.has(flag) || index + 1 >= argv.length || argv[index + 1].startsWith('--') || flag in values) {
      fail('invalid_arguments');
    }
    values[flag] = argv[index + 1];
  }
  if (!v.is(STRING_SCHEMA, values['--source']) || !v.is(STRING_SCHEMA, values['--source-commit']) ||
      !v.is(STRING_SCHEMA, values['--control-plane-origin']) ||
      !v.is(STRING_SCHEMA, values['--release'])) fail('invalid_arguments');
  return {
    help: false,
    sourceDirectory: values['--source'],
    sourceCommit: values['--source-commit'],
    controlPlaneOrigin: values['--control-plane-origin'],
    release: values['--release'],
    outputDirectory: values['--out'],
  };
}

export async function runReleaseCandidateCli({ argv, stdout, stderr }) {
  let parsed;
  try {
    parsed = parseCliArguments(argv);
  } catch {
    stderr.write(HELP);
    return 2;
  }
  if (parsed.help) {
    stdout.write(HELP);
    return 0;
  }
  try {
    const candidate = await buildReleaseCandidate(parsed);
    const outputRoot = parsed.outputDirectory === undefined
      ? null
      : await writeReleaseCandidate(candidate, parsed.outputDirectory);
    stdout.write(`${JSON.stringify(candidateSummary(candidate, outputRoot), null, 2)}\n`);
    return 0;
  } catch (error) {
    const code = error instanceof ReleaseCandidateError ? error.code : 'internal_error';
    stderr.write(`Release candidate build failed: ${code}. Nothing was signed, published, or uploaded.\n`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  runReleaseCandidateCli({ argv: process.argv.slice(2), stdout: process.stdout, stderr: process.stderr })
    .then((code) => { process.exitCode = code; });
}
