import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const repoRoot = join(import.meta.dirname, '..');

function readRepoFile(path: string): string {
  return readFileSync(join(repoRoot, path), 'utf8');
}

function nonCommentLines(fileContents: string): string[] {
  return fileContents
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));
}

describe('local secret and cache conventions', () => {
  it('gitignores local credentials, config, cache, and generated outputs while keeping examples trackable', () => {
    const gitignore = nonCommentLines(readRepoFile('.gitignore'));

    expect(gitignore).toEqual(
      expect.arrayContaining([
        'node_modules/',
        'dist/',
        'coverage/',
        '.env',
        '.env.*',
        '!.env.example',
        '.schlage-cache/',
        '*.local.yaml',
        'config.yaml',
        'config.*.yaml',
        '!config.example.yaml',
      ]),
    );
  });

  it('keeps env examples as placeholder-only key declarations', () => {
    const envExample = readRepoFile('.env.example');
    const assignments = nonCommentLines(envExample);

    expect(assignments).toEqual([
      'SCHLAGE_USERNAME=',
      'SCHLAGE_PASSWORD=',
      'SCHLAGE_LOCK_ID=',
      'SCHLAGE_CONFIG=./config.yaml',
      'SCHLAGE_CACHE_DIR=./.schlage-cache',
      'SCHLAGE_API_KEY=',
      'SCHLAGE_CLIENT_ID=',
      'SCHLAGE_CLIENT_SECRET=',
      'SCHLAGE_USER_POOL_ID=',
    ]);
    expect(envExample).not.toMatch(/^.*password[^=]*=[ \t]*[^\s#].*$/im);
    expect(envExample).not.toMatch(/^.*token[^=]*=[ \t]*[^\s#].*$/im);
    expect(envExample).not.toContain('@example.com');
  });

  it('documents only environment indirection and gitignored cache paths in config examples', () => {
    const configExample = readRepoFile('config.example.yaml');

    expect(configExample).toContain('usernameEnv: SCHLAGE_USERNAME');
    expect(configExample).toContain('passwordEnv: SCHLAGE_PASSWORD');
    expect(configExample).toContain('lockIdEnv: SCHLAGE_LOCK_ID');
    expect(configExample).toContain('cacheDir: ./.schlage-cache');
    expect(configExample).toContain(
      'redactedOutputDir: ./.schlage-cache/diagnostics',
    );
    expect(configExample).not.toMatch(/username:\s*['"]?[^\s'"]+/i);
    expect(configExample).not.toMatch(/password:\s*['"]?[^\s'"]+/i);
    expect(configExample).not.toMatch(/token:\s*['"]?[^\s'"]+/i);
  });

  it('README explains the local operator workflow without publishing secret-shaped values', () => {
    const readme = readRepoFile('README.md');

    expect(readme).toContain('export SCHLAGE_USERNAME=');
    expect(readme).toContain('export SCHLAGE_CONFIG=./config.yaml');
    expect(readme).toContain('SCHLAGE_CACHE_DIR="./.schlage-cache"');
    expect(readme).toContain('`.env`, local YAML config, and `.schlage-cache/` are ignored');
    expect(readme).toContain('not to expose credentials, passwords, access tokens');
    expect(readme).not.toContain('password=hunter2');
    expect(readme).not.toContain('your-password-value');
    expect(readme).not.toContain('SCHLAGE_TOKEN=');
  });
});
