import { execFileSync } from 'node:child_process';
import { lstat, readFile } from 'node:fs/promises';
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

const args = process.argv.slice(2);
let root = process.cwd();

for (let index = 0; index < args.length; index += 1) {
  if (args[index] !== '--repo' || !args[index + 1]) {
    throw new Error('Usage: check-public-boundary.mjs [--repo <path>]');
  }
  root = path.resolve(args[index + 1]);
  index += 1;
}

const files = gitPaths([
  'ls-files',
  '--cached',
  '--others',
  '--exclude-standard',
  '-z',
]);
const failures = [];

for (const relative of files) {
  const displayPath = safeDisplayLocation(relative, 'path');
  if (forbiddenGeneratedPath.test(relative)) {
    failures.push(`${displayPath} is forbidden generated output`);
  }

  for (const label of findForbiddenContentLabels(relative)) {
    failures.push(`${displayPath} contains ${label} in its path`);
  }

  const basename = path.posix.basename(relative);
  if (
    !allowedExampleNames.has(basename) &&
    forbiddenNames.some((pattern) => pattern.test(basename))
  ) {
    failures.push(`${displayPath} has a forbidden filename`);
    continue;
  }

  const file = path.join(root, ...relative.split('/'));
  const metadata = await lstat(file).catch(() => null);
  if (metadata === null) continue;
  if (metadata.isSymbolicLink()) {
    failures.push(`${displayPath} is a symbolic link`);
    continue;
  }
  if (!metadata.isFile()) continue;

  const classification = classifyPublicPath(relative);
  if (classification === 'binary') continue;
  if (metadata.size > MAX_PUBLIC_TEXT_BYTES) {
    failures.push(
      classification === 'text'
        ? `${displayPath} is oversized textual content and cannot be published`
        : `${displayPath} exceeds the bounded inspection limit without a known binary type`,
    );
    continue;
  }

  const bytes = await readFile(file).catch(() => null);
  if (bytes === null) continue;
  if (bytes.includes(0)) {
    failures.push(
      classification === 'text'
        ? `${displayPath} is textual content containing NUL bytes`
        : `${displayPath} contains NUL bytes without a known binary type`,
    );
    continue;
  }

  let content;
  try {
    content = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    failures.push(
      classification === 'text'
        ? `${displayPath} is textual content that is not valid UTF-8`
        : `${displayPath} is not valid UTF-8 and has no known binary type`,
    );
    continue;
  }
  for (const label of findForbiddenContentLabels(content)) {
    failures.push(`${displayPath} contains ${label}`);
  }
  const generatedLabel = generatedReleaseArtifactLabel(content);
  if (generatedLabel !== null) {
    failures.push(`${displayPath} contains ${generatedLabel}`);
  }
}

if (failures.length > 0) {
  console.error(`Public-boundary check failed:\n- ${failures.join('\n- ')}`);
  process.exitCode = 1;
} else {
  console.log(`Public-boundary check passed for ${files.length} publishable files.`);
}

function gitPaths(commandArgs) {
  const output = execFileSync('git', ['-C', root, ...commandArgs], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  return output.split('\0').filter(Boolean);
}
