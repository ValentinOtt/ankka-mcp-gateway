import { execFileSync } from 'node:child_process';
import path from 'node:path';

import {
  allowedExampleNames,
  classifyPublicPath,
  findForbiddenContentLabels,
  forbiddenGeneratedPath,
  forbiddenNames,
  generatedReleaseArtifactLabel,
  MAX_PUBLIC_TEXT_BYTES,
  safeDisplayLocation,
} from './public-boundary-rules.mjs';

const MAX_REACHABLE_OBJECTS = 1_000_000;
const MAX_TREE_BYTES = 64 * 1024 * 1024;
const MAX_TREE_PATH_CONTEXTS = 1_000_000;
const MAX_BLOB_PATHS = 2_000_000;
const MAX_GIT_OUTPUT = 128 * 1024 * 1024;
const RETIRED_PRODUCT_NAME_LABEL = 'retired gateway product name';

// The publishable surface: the checked-out history, every ref already on the
// public origin remote, and tags (release tags are published). Other remotes
// and other local branches may legitimately hold private history.
const PUBLIC_REV_SCOPE = ['HEAD', '--remotes=origin', '--tags'];
const PUBLIC_REF_PATTERNS = ['refs/remotes/origin', 'refs/tags'];

const args = process.argv.slice(2);
let root = process.cwd();
let retiredProductNameBaseline;

for (let index = 0; index < args.length; index += 1) {
  const argument = args[index];
  const value = args[index + 1];
  if (argument === '--repo' && value) {
    root = path.resolve(value);
    index += 1;
    continue;
  }
  if (argument === '--allow-retired-product-name-through' && value) {
    retiredProductNameBaseline = value;
    index += 1;
    continue;
  }
  throw new Error(
    'Usage: check-public-history.mjs [--repo <path>] ' +
    '[--allow-retired-product-name-through <commit>]',
  );
}

const failures = new Set();
const objectIds = [...new Set(
  git(['rev-list', '--objects', '--no-object-names', ...PUBLIC_REV_SCOPE])
    .trim()
    .split('\n')
    .filter(Boolean),
)];

if (objectIds.length > MAX_REACHABLE_OBJECTS) {
  failImmediately('reachable object count exceeds the bounded public-history inspection limit');
}

const objectInfo = new Map();
if (objectIds.length > 0) {
  const lines = git(
    ['cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)'],
    `${objectIds.join('\n')}\n`,
  ).trim().split('\n').filter(Boolean);
  const wanted = new Set(objectIds);
  for (const line of lines) {
    const [objectId, objectType, rawSize] = line.split(' ');
    const size = Number(rawSize);
    if (!wanted.has(objectId) || !Number.isSafeInteger(size) || size < 0) {
      failImmediately('reachable object metadata is invalid');
    }
    objectInfo.set(objectId, { objectType, size });
  }
  if (objectInfo.size !== objectIds.length) {
    failImmediately('reachable object metadata is incomplete');
  }
}

const commitIds = objectIds.filter((objectId) => objectInfo.get(objectId).objectType === 'commit');
const baseline = resolveRetiredProductNameBaseline(retiredProductNameBaseline, objectInfo);
const baselineCommitIds = baseline === undefined
  ? new Set()
  : new Set(git(['rev-list', baseline]).trim().split('\n').filter(Boolean));
const baselineObjectIds = baseline === undefined
  ? new Set()
  : new Set(
      git(['rev-list', '--objects', baseline, '--no-object-names'])
        .trim()
        .split('\n')
        .filter(Boolean),
    );
const strictCommitIds = new Set(
  commitIds.filter((objectId) => !baselineCommitIds.has(objectId)),
);
const strictTreeRoots = new Set(
  git(['log', ...PUBLIC_REV_SCOPE, '--format=%H%x09%T'])
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => line.split('\t'))
    .filter(([commitId]) => strictCommitIds.has(commitId))
    .map(([, treeId]) => treeId),
);
const treeIds = objectIds.filter((objectId) => objectInfo.get(objectId).objectType === 'tree');
const pathsByObject = enumerateReachableTreePaths(treeIds, objectInfo);
const strictPathsByObject = enumerateReachableTreePaths(treeIds, objectInfo, strictTreeRoots);
let checkedBlobs = 0;

for (const objectId of objectIds) {
  const { objectType, size } = objectInfo.get(objectId);
  if (objectType !== 'blob') continue;

  const objectPaths = [...(pathsByObject.get(objectId) ?? [])].sort(lexicalCompare);
  const strictPaths = strictPathsByObject.get(objectId) ?? new Set();
  for (const objectPath of objectPaths) {
    inspectReachablePath(
      objectId,
      objectPath,
      baselineObjectIds.has(objectId) && !strictPaths.has(objectPath),
    );
  }

  const classifications = objectPaths.map((objectPath) => classifyPublicPath(objectPath));
  const textualPaths = objectPaths.filter((_, index) => classifications[index] === 'text');
  const onlyKnownBinaryPaths = objectPaths.length > 0 && classifications.every((entry) => entry === 'binary');

  if (size > MAX_PUBLIC_TEXT_BYTES) {
    if (textualPaths.length > 0) {
      for (const objectPath of textualPaths) {
        failures.add(
          `${safeDisplayLocation(objectPath, 'path')} is oversized textual content in reachable history`,
        );
      }
    } else if (!onlyKnownBinaryPaths) {
      failures.add(
        `blob ${objectId} exceeds the bounded inspection limit without only known binary paths`,
      );
    }
    continue;
  }

  if (onlyKnownBinaryPaths) continue;
  const bytes = gitBuffer(['cat-file', 'blob', objectId], undefined, MAX_PUBLIC_TEXT_BYTES + 4_096);
  if (bytes.byteLength !== size) {
    failures.add(`blob ${objectId} has inconsistent reachable object bytes`);
    continue;
  }
  if (bytes.includes(0)) {
    if (textualPaths.length > 0) {
      for (const objectPath of textualPaths) {
        failures.add(
          `${safeDisplayLocation(objectPath, 'path')} is textual content containing NUL bytes in reachable history`,
        );
      }
    } else {
      failures.add(`blob ${objectId} has NUL bytes without a known binary path`);
    }
    continue;
  }

  let content;
  try {
    content = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    if (textualPaths.length > 0) {
      for (const objectPath of textualPaths) {
        failures.add(
          `${safeDisplayLocation(objectPath, 'path')} is textual content that is not valid UTF-8 in reachable history`,
        );
      }
    } else {
      failures.add(`blob ${objectId} is not valid UTF-8 and has no known binary path`);
    }
    continue;
  }

  checkedBlobs += 1;
  const location = blobLocation(objectId, objectPaths);
  inspectText(
    content,
    location,
    baselineObjectIds.has(objectId) && strictPaths.size === 0,
  );
  const generatedLabel = generatedReleaseArtifactLabel(content);
  if (generatedLabel !== null) failures.add(`${location} contains ${generatedLabel}`);
}

for (const objectId of commitIds) {
  inspectMetadataObject(objectId, 'commit', baselineCommitIds.has(objectId));
}

const tagIds = objectIds.filter((objectId) => objectInfo.get(objectId).objectType === 'tag');
for (const objectId of tagIds) inspectMetadataObject(objectId, 'annotated tag');

const refLines = git([
  'for-each-ref',
  '--format=%(objectname)%09%(objecttype)%09%(refname)',
  ...PUBLIC_REF_PATTERNS,
]).trim().split('\n').filter(Boolean);
try {
  const headRefName = git(['symbolic-ref', '--quiet', 'HEAD']).trim();
  if (headRefName) {
    const headObjectId = git(['rev-parse', 'HEAD']).trim();
    refLines.push(`${headObjectId}\tcommit\t${headRefName}`);
  }
} catch {
  // A detached HEAD publishes no branch name of its own.
}
for (const line of refLines) {
  const [objectId, , refName] = line.split('\t');
  if (!objectId || !refName) {
    failures.add('a publishable ref has invalid metadata');
    continue;
  }
  const displayRef = safeDisplayLocation(refName, 'ref');
  const refBasename = path.posix.basename(refName);
  if (
    !allowedExampleNames.has(refBasename) &&
    forbiddenNames.some((pattern) => pattern.test(refBasename))
  ) failures.add(`${displayRef} targeting ${objectId} has a forbidden generated or sensitive name`);
  if (forbiddenGeneratedPath.test(refName)) {
    failures.add(`${displayRef} targeting ${objectId} names forbidden generated output`);
  }
  for (const label of findForbiddenContentLabels(refName)) {
    failures.add(`${displayRef} targeting ${objectId} contains ${label}`);
  }
}

if (failures.size > 0) {
  console.error(`Public-history check failed:\n- ${[...failures].join('\n- ')}`);
  process.exitCode = 1;
} else {
  console.log(
    `Public-history check passed for ${checkedBlobs} reachable text blobs, ` +
    `${commitIds.length} commits, ${tagIds.length} annotated tags, and ` +
    `${refLines.length} publishable refs.`,
  );
}

function enumerateReachableTreePaths(treeIds, info, requestedRoots) {
  const totalTreeBytes = treeIds.reduce((total, objectId) => total + info.get(objectId).size, 0);
  if (!Number.isSafeInteger(totalTreeBytes) || totalTreeBytes > MAX_TREE_BYTES) {
    failures.add('reachable tree metadata exceeds the bounded public-history inspection limit');
    return new Map();
  }
  if (treeIds.length === 0) return new Map();

  const objectFormat = git(['rev-parse', '--show-object-format']).trim();
  const objectIdBytes = objectFormat === 'sha1' ? 20 : objectFormat === 'sha256' ? 32 : 0;
  if (objectIdBytes === 0) failImmediately('repository object format is unsupported');

  const rawTrees = readBatchObjects(treeIds, totalTreeBytes + (treeIds.length * 96) + 1_024);
  const entriesByTree = new Map();
  const childTreeIds = new Set();
  for (const treeId of treeIds) {
    const entries = parseTree(treeId, rawTrees.get(treeId), objectIdBytes);
    entriesByTree.set(treeId, entries);
    for (const entry of entries) {
      if (entry.type === 'tree') childTreeIds.add(entry.objectId);
    }
  }

  const roots = requestedRoots === undefined
    ? new Set(git(['log', ...PUBLIC_REV_SCOPE, '--format=%T']).trim().split('\n').filter(Boolean))
    : new Set(requestedRoots);
  if (requestedRoots === undefined) {
    for (const treeId of treeIds) {
      if (!childTreeIds.has(treeId)) roots.add(treeId);
    }
  }

  const result = new Map();
  const queue = [...roots].map((treeId) => ({ prefix: '', treeId }));
  const visited = new Set();
  let blobPathCount = 0;
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    if (queue.length > MAX_TREE_PATH_CONTEXTS) {
      failures.add('reachable tree path contexts exceed the bounded inspection limit');
      break;
    }
    const { prefix, treeId } = queue[cursor];
    const visitKey = `${treeId}\0${prefix}`;
    if (visited.has(visitKey)) continue;
    visited.add(visitKey);
    const entries = entriesByTree.get(treeId);
    if (!entries) {
      failures.add(`reachable tree ${treeId} has incomplete metadata`);
      continue;
    }
    for (const entry of entries) {
      const objectPath = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.type === 'tree') {
        queue.push({ prefix: objectPath, treeId: entry.objectId });
      } else if (entry.type === 'gitlink') {
        failures.add(
          `${safeDisplayLocation(objectPath, 'path')} is a gitlink in reachable history`,
        );
      } else {
        if (entry.type === 'symlink') {
          failures.add(
            `${safeDisplayLocation(objectPath, 'path')} is a symbolic link in reachable history`,
          );
        }
        if (!result.has(entry.objectId)) result.set(entry.objectId, new Set());
        const paths = result.get(entry.objectId);
        if (!paths.has(objectPath)) {
          paths.add(objectPath);
          blobPathCount += 1;
          if (blobPathCount > MAX_BLOB_PATHS) {
            failures.add('reachable blob paths exceed the bounded inspection limit');
            return result;
          }
        }
      }
    }
  }
  return result;
}

function readBatchObjects(objectIds, maxBuffer) {
  const output = gitBuffer(
    ['cat-file', '--batch'],
    Buffer.from(`${objectIds.join('\n')}\n`, 'ascii'),
    Math.min(MAX_GIT_OUTPUT, Math.max(maxBuffer, 4 * 1024 * 1024)),
  );
  const objects = new Map();
  let cursor = 0;
  for (const expectedId of objectIds) {
    const headerEnd = output.indexOf(0x0a, cursor);
    if (headerEnd === -1) failImmediately('reachable tree batch is incomplete');
    const [objectId, objectType, rawSize] = output.subarray(cursor, headerEnd).toString('ascii').split(' ');
    const size = Number(rawSize);
    const contentStart = headerEnd + 1;
    const contentEnd = contentStart + size;
    if (
      objectId !== expectedId || objectType !== 'tree' ||
      !Number.isSafeInteger(size) || size < 0 ||
      contentEnd >= output.byteLength || output[contentEnd] !== 0x0a
    ) failImmediately('reachable tree batch is invalid');
    objects.set(objectId, output.subarray(contentStart, contentEnd));
    cursor = contentEnd + 1;
  }
  if (cursor !== output.byteLength) failImmediately('reachable tree batch has trailing data');
  return objects;
}

function parseTree(treeId, bytes, objectIdBytes) {
  const entries = [];
  let cursor = 0;
  while (cursor < bytes.byteLength) {
    const modeEnd = bytes.indexOf(0x20, cursor);
    const nameEnd = modeEnd === -1 ? -1 : bytes.indexOf(0x00, modeEnd + 1);
    if (modeEnd === -1 || nameEnd === -1 || nameEnd + 1 + objectIdBytes > bytes.byteLength) {
      failImmediately(`reachable tree ${treeId} has invalid encoding`);
    }
    const mode = bytes.subarray(cursor, modeEnd).toString('ascii');
    const nameBytes = bytes.subarray(modeEnd + 1, nameEnd);
    let name;
    try {
      name = new TextDecoder('utf-8', { fatal: true }).decode(nameBytes);
    } catch {
      failures.add(`reachable tree ${treeId} contains a non-UTF-8 path`);
      name = `<non-utf8-path-${entries.length}>`;
    }
    const objectStart = nameEnd + 1;
    const objectId = bytes.subarray(objectStart, objectStart + objectIdBytes).toString('hex');
    const type = mode === '40000'
      ? 'tree'
      : mode === '160000'
        ? 'gitlink'
        : mode === '120000'
          ? 'symlink'
          : 'blob';
    entries.push({ name, objectId, type });
    cursor = objectStart + objectIdBytes;
  }
  return entries;
}

function inspectReachablePath(objectId, objectPath, allowRetiredProductName = false) {
  const displayPath = safeDisplayLocation(objectPath, 'path');
  const basename = path.posix.basename(objectPath);
  if (
    !allowedExampleNames.has(basename) &&
    forbiddenNames.some((pattern) => pattern.test(basename))
  ) failures.add(`${displayPath} has a forbidden filename in reachable history`);
  if (forbiddenGeneratedPath.test(objectPath)) {
    failures.add(`${displayPath} is forbidden generated output in reachable history`);
  }
  for (const label of findForbiddenContentLabels(objectPath)) {
    if (allowRetiredProductName && label === RETIRED_PRODUCT_NAME_LABEL) continue;
    failures.add(`blob ${objectId} has a reachable path containing ${label}`);
  }
}

function inspectMetadataObject(objectId, label, allowRetiredProductName = false) {
  const { size } = objectInfo.get(objectId);
  if (size > MAX_PUBLIC_TEXT_BYTES) {
    failures.add(`${label} ${objectId} exceeds the bounded text inspection limit`);
    return;
  }
  const bytes = gitBuffer(['cat-file', label === 'commit' ? 'commit' : 'tag', objectId]);
  let content;
  try {
    content = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    failures.add(`${label} ${objectId} is not valid UTF-8`);
    return;
  }
  inspectText(content, `${label} ${objectId}`, allowRetiredProductName);
}

function inspectText(text, location, allowRetiredProductName = false) {
  for (const label of findForbiddenContentLabels(text)) {
    if (allowRetiredProductName && label === RETIRED_PRODUCT_NAME_LABEL) continue;
    failures.add(`${location} contains ${label}`);
  }
}

function resolveRetiredProductNameBaseline(value, info) {
  if (value === undefined) return undefined;
  if (!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u.test(value)) {
    failImmediately('retired-product-name baseline must be a full commit object ID');
  }
  if (info.get(value)?.objectType !== 'commit') {
    failImmediately('retired-product-name baseline is not a reachable commit');
  }
  const headCommitIds = new Set(git(['rev-list', 'HEAD']).trim().split('\n').filter(Boolean));
  if (!headCommitIds.has(value)) {
    failImmediately('retired-product-name baseline is not an ancestor of HEAD');
  }
  return value;
}

function blobLocation(objectId, objectPaths) {
  if (objectPaths.length === 1) return safeDisplayLocation(objectPaths[0], 'path');
  return `blob ${objectId} with ${objectPaths.length} reachable paths`;
}

function lexicalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function failImmediately(message) {
  console.error(`Public-history check failed:\n- ${message}`);
  process.exit(1);
}

function git(commandArgs, input) {
  return execFileSync('git', ['-C', root, ...commandArgs], {
    encoding: 'utf8',
    input,
    maxBuffer: MAX_GIT_OUTPUT,
  });
}

function gitBuffer(commandArgs, input, maxBuffer = 4 * 1024 * 1024) {
  return execFileSync('git', ['-C', root, ...commandArgs], {
    encoding: 'buffer',
    input,
    maxBuffer,
  });
}
