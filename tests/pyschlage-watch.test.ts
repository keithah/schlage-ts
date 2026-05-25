import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  buildIssue,
  checkPyschlageRelease,
  compareVersions,
  hasOpenIssueForVersion,
} from '../scripts/check-pyschlage-release.mjs';

const tempRoots: string[] = [];

async function tempMarker(version: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'schlage-pyschlage-watch-test-'));
  tempRoots.push(root);
  const path = join(root, 'pyschlage-version.json');
  await writeFile(path, `${JSON.stringify({ version })}\n`, 'utf8');
  return path;
}

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(
    tempRoots.splice(0).map((dir) => rm(dir, { force: true, recursive: true })),
  );
});

describe('pyschlage release watcher', () => {
  it('compares dotted versions numerically', () => {
    expect(compareVersions('0.10.0', '0.9.9')).toBe(1);
    expect(compareVersions('1.0.0', '1.0')).toBe(0);
    expect(compareVersions('0.2.0', '0.2.1')).toBe(-1);
  });

  it('builds a dependabot-style parity issue', () => {
    const issue = buildIssue({
      packageName: 'pyschlage',
      latestVersion: '0.3.0',
      currentVersion: '0.2.0',
    });

    expect(issue.title).toBe('pyschlage 0.3.0 is available');
    expect(issue.body).toContain('Tracked baseline: `0.2.0`');
    expect(issue.body).toContain('https://pypi.org/project/pyschlage/0.3.0/');
    expect(issue.body).toContain('Parity checklist:');
  });

  it('recognizes an already-open issue for the latest version', () => {
    expect(
      hasOpenIssueForVersion(
        [{ title: 'pyschlage 0.3.0 is available' }],
        'pyschlage',
        '0.3.0',
      ),
    ).toBe(true);
  });

  it('does nothing when the marker is current', async () => {
    const markerPath = await tempMarker('0.3.0');
    const fetchMock = vi.fn(async () =>
      jsonResponse({ info: { version: '0.3.0' } }),
    );

    const result = await checkPyschlageRelease({
      markerPath,
      fetch: fetchMock,
      env: {},
    });

    expect(result).toEqual({
      action: 'none',
      currentVersion: '0.3.0',
      latestVersion: '0.3.0',
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('creates one issue for a newer PyPI version when no duplicate is open', async () => {
    const markerPath = await tempMarker('0.2.0');
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ info: { version: '0.3.0' } }))
      .mockResolvedValueOnce(jsonResponse([]))
      .mockResolvedValueOnce(jsonResponse({ number: 12 }));

    const result = await checkPyschlageRelease({
      markerPath,
      fetch: fetchMock,
      env: {
        GITHUB_REPOSITORY: 'keithah/schlage-ts',
        GITHUB_TOKEN: 'github-token-value',
      },
    });

    expect(result.action).toBe('created');
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[2][0]).toBe(
      'https://api.github.com/repos/keithah/schlage-ts/issues',
    );
    expect(JSON.parse(fetchMock.mock.calls[2][1].body)).toMatchObject({
      title: 'pyschlage 0.3.0 is available',
    });
  });

  it('does not create a duplicate issue for an already-open version', async () => {
    const markerPath = await tempMarker('0.2.0');
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ info: { version: '0.3.0' } }))
      .mockResolvedValueOnce(
        jsonResponse([{ title: 'pyschlage 0.3.0 is available' }]),
      );

    const result = await checkPyschlageRelease({
      markerPath,
      fetch: fetchMock,
      env: {
        GITHUB_REPOSITORY: 'keithah/schlage-ts',
        GITHUB_TOKEN: 'github-token-value',
      },
    });

    expect(result.action).toBe('already-open');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
