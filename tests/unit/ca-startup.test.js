import { describe, expect, test } from '@jest/globals';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const cwd = fileURLToPath(new URL('../..', import.meta.url));
describe('CA startup errors', () => {
  test.each([
    ['CAMOFOX_TRUST_SYSTEM_CA', 'yes', 'exactly true or false'],
    ['CAMOFOX_EXTRA_CA_CERT', 'relative.pem', 'absolute path'],
    ['CAMOFOX_EXTRA_CA_CERT', '/camofox-missing-ca-fixture.pem', 'readable regular file'],
  ])('%s fails before listening with one JSON error', (variable, value, problem) => {
    const env = { ...process.env };
    delete env.CAMOFOX_TRUST_SYSTEM_CA;
    delete env.CAMOFOX_EXTRA_CA_CERT;
    env[variable] = value;
    const result = spawnSync(process.execPath, ['server.js'], { cwd, env, encoding: 'utf8', timeout: 15000 });
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stdout).toBe('');
    const lines = result.stderr.trim().split('\n');
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0])).toMatchObject({ level: 'error', msg: 'startup configuration failed' });
    expect(JSON.parse(lines[0]).error).toContain(variable);
    expect(JSON.parse(lines[0]).error).toContain(problem);
  });
});
