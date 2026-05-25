#!/usr/bin/env node
import { readFileSync } from 'node:fs';

const DEFAULT_MARKER_PATH = '.github/pyschlage-version.json';
const DEFAULT_PACKAGE = 'pyschlage';
const DEFAULT_PYPI_URL = 'https://pypi.org/pypi/pyschlage/json';

export function compareVersions(left, right) {
  const leftParts = parseVersion(left);
  const rightParts = parseVersion(right);
  const length = Math.max(leftParts.length, rightParts.length);

  for (let index = 0; index < length; index += 1) {
    const leftPart = leftParts[index] ?? 0;
    const rightPart = rightParts[index] ?? 0;
    if (leftPart > rightPart) return 1;
    if (leftPart < rightPart) return -1;
  }

  return 0;
}

export function buildIssue({ packageName, latestVersion, currentVersion }) {
  const title = `${packageName} ${latestVersion} is available`;
  const body = [
    `PyPI has published \`${packageName}@${latestVersion}\`.`,
    '',
    `Tracked baseline: \`${currentVersion}\``,
    `PyPI: https://pypi.org/project/${packageName}/${latestVersion}/`,
    '',
    'Parity checklist:',
    '',
    '- [ ] Review upstream changelog/release notes.',
    '- [ ] Compare API/protocol changes against schlage-ts.',
    '- [ ] Port relevant behavior or document why it does not apply.',
    '- [ ] Add or update tests for any parity changes.',
    '- [ ] Run local and live verification as appropriate.',
  ].join('\n');

  return { title, body };
}

export function hasOpenIssueForVersion(issues, packageName, latestVersion) {
  const expectedTitle = `${packageName} ${latestVersion} is available`;
  return issues.some((issue) => issue.title === expectedTitle);
}

export async function checkPyschlageRelease(options = {}) {
  const env = options.env ?? process.env;
  const fetchFn = options.fetch ?? fetch;
  const markerPath = options.markerPath ?? DEFAULT_MARKER_PATH;
  const packageName = options.packageName ?? DEFAULT_PACKAGE;
  const pypiUrl = options.pypiUrl ?? DEFAULT_PYPI_URL;
  const marker = readMarker(markerPath);
  const latestVersion = await fetchLatestVersion(fetchFn, pypiUrl);

  if (compareVersions(latestVersion, marker.version) <= 0) {
    return {
      action: 'none',
      currentVersion: marker.version,
      latestVersion,
    };
  }

  const issue = buildIssue({
    packageName,
    latestVersion,
    currentVersion: marker.version,
  });
  const repository = env.GITHUB_REPOSITORY;
  const token = env.GITHUB_TOKEN;

  if (!repository || !token) {
    return {
      action: 'would-create',
      currentVersion: marker.version,
      latestVersion,
      issue,
    };
  }

  const issues = await listOpenIssues(fetchFn, repository, token);
  if (hasOpenIssueForVersion(issues, packageName, latestVersion)) {
    return {
      action: 'already-open',
      currentVersion: marker.version,
      latestVersion,
      issue,
    };
  }

  await createIssue(fetchFn, repository, token, issue);
  return {
    action: 'created',
    currentVersion: marker.version,
    latestVersion,
    issue,
  };
}

async function main() {
  const result = await checkPyschlageRelease();
  console.log(JSON.stringify(result, null, 2));
}

function readMarker(path) {
  const parsed = JSON.parse(readFileSync(path, 'utf8'));
  if (typeof parsed.version !== 'string' || parsed.version.trim() === '') {
    throw new Error(`${path} must contain a string version field.`);
  }

  return { version: parsed.version };
}

async function fetchLatestVersion(fetchFn, pypiUrl) {
  const response = await fetchFn(pypiUrl, {
    headers: { accept: 'application/json' },
  });
  if (!response.ok) {
    throw new Error(`PyPI request failed with HTTP ${response.status}.`);
  }

  const payload = await response.json();
  const version = payload?.info?.version;
  if (typeof version !== 'string' || version.trim() === '') {
    throw new Error('PyPI response omitted info.version.');
  }

  return version;
}

async function listOpenIssues(fetchFn, repository, token) {
  const response = await fetchFn(
    `https://api.github.com/repos/${repository}/issues?state=open&per_page=100`,
    githubRequestOptions(token),
  );
  if (!response.ok) {
    throw new Error(`GitHub issue list failed with HTTP ${response.status}.`);
  }

  const payload = await response.json();
  return Array.isArray(payload)
    ? payload.filter((issue) => !issue.pull_request)
    : [];
}

async function createIssue(fetchFn, repository, token, issue) {
  const response = await fetchFn(
    `https://api.github.com/repos/${repository}/issues`,
    {
      ...githubRequestOptions(token),
      method: 'POST',
      body: JSON.stringify({
      title: issue.title,
      body: issue.body,
      }),
    },
  );
  if (!response.ok) {
    throw new Error(`GitHub issue create failed with HTTP ${response.status}.`);
  }
}

function githubRequestOptions(token) {
  return {
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'x-github-api-version': '2022-11-28',
    },
  };
}

function parseVersion(version) {
  return version
    .split(/[.-]/u)
    .map((part) => Number.parseInt(part, 10))
    .map((part) => (Number.isNaN(part) ? 0 : part));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
