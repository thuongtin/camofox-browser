import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, jest, test } from '@jest/globals';
import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';
import { prepareCaTrust } from '../../lib/ca-trust.js';

let fixtures;
let caPem;
let otherCaPem;
let leafPem;
let workspace;
let executablePath;
let policyPath;
let tempDir;
const cleanups = [];

beforeAll(() => {
  fixtures = mkdtempSync(join(tmpdir(), 'camofox-ca-trust-fixtures-'));
  for (const [name, isCa] of [['ca', true], ['other-ca', true], ['leaf', false]]) {
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
      '-subj', `/CN=Camofox ${name} fixture`,
      '-addext', `basicConstraints=critical,CA:${isCa ? 'TRUE' : 'FALSE'}`,
      '-keyout', join(fixtures, `${name}.key`), '-out', join(fixtures, `${name}.pem`),
    ], { stdio: 'pipe' });
  }
  caPem = readFileSync(join(fixtures, 'ca.pem'), 'utf8');
  otherCaPem = readFileSync(join(fixtures, 'other-ca.pem'), 'utf8');
  leafPem = readFileSync(join(fixtures, 'leaf.pem'), 'utf8');
});

beforeEach(() => {
  workspace = mkdtempSync(join(tmpdir(), 'camofox-ca-trust-test-'));
  const bundle = join(workspace, 'browser');
  mkdirSync(join(bundle, 'distribution'), { recursive: true });
  executablePath = join(bundle, 'camoufox');
  writeFileSync(executablePath, Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
  chmodSync(executablePath, 0o755);
  writeFileSync(join(bundle, 'properties.json'), '{"version":"fixture"}\n');
  writeFileSync(join(bundle, 'untouched.txt'), 'original content\n');
  policyPath = join(bundle, 'distribution', 'policies.json');
  tempDir = join(workspace, 'private');
  mkdirSync(tempDir);
});

afterEach(() => {
  for (const cleanup of cleanups.splice(0)) cleanup();
  rmSync(workspace, { recursive: true, force: true });
});
afterAll(() => { rmSync(fixtures, { recursive: true, force: true }); });

function prepare(config, overrides = {}) {
  const result = prepareCaTrust(config, { executablePath, tempDir, platform: 'linux', ...overrides });
  cleanups.push(result.cleanup);
  return result;
}

function installPaths(result) {
  return JSON.parse(readFileSync(result.policyPath, 'utf8')).policies.Certificates.Install;
}

function fingerprints(paths) {
  return paths.map(path => new X509Certificate(readFileSync(path)).fingerprint256).sort();
}

describe('prepareCaTrust', () => {
  test('default configuration has no filesystem or system store effects', () => {
    const systemCertificates = jest.fn(() => { throw new Error('must not read system store'); });
    const result = prepare({ trustSystemCa: false, extraCaPem: null }, {
      executablePath: '/missing/browser', tempDir: '/missing/temp', systemCertificates,
    });
    expect(result.executablePath).toBeNull();
    expect(result.firefoxUserPrefs).toEqual({});
    expect(systemCertificates).not.toHaveBeenCalled();
    expect(readdirSync(tempDir)).toEqual([]);
    result.cleanup();
    result.cleanup();
  });

  test.each(['darwin', 'win32'])('%s system-only trust sets preference without copying', platform => {
    const systemCertificates = jest.fn(() => { throw new Error('must not read system store'); });
    const result = prepare({ trustSystemCa: true, extraCaPem: null }, {
      platform, systemCertificates,
    });
    expect(result.executablePath).toBeNull();
    expect(result.firefoxUserPrefs).toEqual({ 'security.enterprise_roots.enabled': true });
    expect(systemCertificates).not.toHaveBeenCalled();
    expect(readdirSync(tempDir)).toEqual([]);
  });

  test.each(['darwin', 'win32'])('%s system-only rejects an operator policy disabling enterprise roots', platform => {
    writeFileSync(policyPath, JSON.stringify({ policies: { Certificates: { ImportEnterpriseRoots: false } } }));
    expect(() => prepare({ trustSystemCa: true, extraCaPem: null }, { platform }))
      .toThrow('CAMOFOX_TRUST_SYSTEM_CA');
    expect(readdirSync(tempDir)).toEqual([]);
  });

  test('rejects a wrapper even with sibling resources instead of silently using the original bundle', () => {
    writeFileSync(executablePath, '#!/bin/sh\nexec /original/bundle/camoufox-bin "$@"\n');
    expect(() => prepare({ trustSystemCa: false, extraCaPem: caPem })).toThrow('CAMOFOX_EXTRA_CA_CERT');
    expect(() => prepare({ trustSystemCa: false, extraCaPem: caPem })).toThrow('not a wrapper script');
    expect(readdirSync(tempDir)).toEqual([]);
  });

  test('Linux imports only system CAs, filters leaf certificates, and deduplicates', () => {
    const systemCertificates = jest.fn(() => [caPem, leafPem, caPem, otherCaPem]);
    const result = prepare({ trustSystemCa: true, extraCaPem: null }, { systemCertificates });
    const paths = installPaths(result);
    expect(systemCertificates).toHaveBeenCalledTimes(1);
    expect(systemCertificates).toHaveBeenCalledWith();
    expect(paths).toHaveLength(2);
    expect(fingerprints(paths)).toEqual([
      new X509Certificate(caPem).fingerprint256, new X509Certificate(otherCaPem).fingerprint256,
    ].sort());
    expect(result.firefoxUserPrefs).toEqual({ 'security.enterprise_roots.enabled': true });
  });

  test('extra CA does not enable or read the system store', () => {
    const systemCertificates = jest.fn(() => { throw new Error('must not read system store'); });
    const result = prepare({ trustSystemCa: false, extraCaPem: caPem }, { systemCertificates });
    expect(systemCertificates).not.toHaveBeenCalled();
    expect(result.firefoxUserPrefs).toEqual({});
    expect(fingerprints(installPaths(result))).toEqual([new X509Certificate(caPem).fingerprint256]);
  });

  test('system and extra certificates are additive and deduplicated together', () => {
    const result = prepare({ trustSystemCa: true, extraCaPem: caPem }, {
      systemCertificates: () => [caPem, otherCaPem],
    });
    expect(installPaths(result)).toHaveLength(2);
  });

  test('copies the bundle and preserves original bytes, existing certificates, and other policies', () => {
    const existingPath = join(dirname(executablePath), 'existing.pem');
    writeFileSync(existingPath, otherCaPem);
    const policy = {
      policies: {
        DisableAppUpdate: true,
        Certificates: { Install: [existingPath], ImportEnterpriseRoots: true },
      },
      custom: { value: 'preserve' },
    };
    const originalPolicy = ` ${JSON.stringify(policy)}\n`;
    writeFileSync(policyPath, originalPolicy);
    const executableBytes = readFileSync(executablePath);
    const result = prepare({ trustSystemCa: false, extraCaPem: caPem });
    expect(result.executablePath).not.toBe(executablePath);
    expect(readFileSync(result.executablePath)).toEqual(executableBytes);
    expect(statSync(result.executablePath).mode & 0o111).toBe(0o111);
    expect(readFileSync(policyPath, 'utf8')).toBe(originalPolicy);
    expect(readFileSync(existingPath, 'utf8')).toBe(otherCaPem);
    const copied = JSON.parse(readFileSync(result.policyPath, 'utf8'));
    expect(copied.custom).toEqual(policy.custom);
    expect(copied.policies.DisableAppUpdate).toBe(true);
    expect(copied.policies.Certificates.ImportEnterpriseRoots).toBe(true);
    const paths = installPaths(result);
    expect(paths[0]).toBe(existingPath);
    expect(paths).toHaveLength(2);
    expect(isAbsolute(paths[1])).toBe(true);
    expect(new X509Certificate(readFileSync(paths[1])).ca).toBe(true);
    expect(statSync(paths[1]).mode & 0o777).toBe(0o600);
    expect(statSync(dirname(paths[1])).mode & 0o777).toBe(0o700);
    writeFileSync(join(dirname(result.executablePath), 'untouched.txt'), 'private edit');
    expect(readFileSync(join(dirname(executablePath), 'untouched.txt'), 'utf8')).toBe('original content\n');
    writeFileSync(result.executablePath, 'private executable edit');
    expect(readFileSync(executablePath)).toEqual(executableBytes);
  });

  test('imports the startup PEM snapshot even when its source path changes', () => {
    const extraCaCert = join(workspace, 'extra.pem');
    writeFileSync(extraCaCert, caPem);
    const config = { trustSystemCa: false, extraCaCert, extraCaPem: readFileSync(extraCaCert, 'utf8') };
    writeFileSync(extraCaCert, otherCaPem);
    const result = prepare(config);
    expect(fingerprints(installPaths(result))).toEqual([new X509Certificate(caPem).fingerprint256]);
    expect(readFileSync(extraCaCert, 'utf8')).toBe(otherCaPem);
  });

  test('cleanup is idempotent and removes only the private bundle and certificates', () => {
    const result = prepare({ trustSystemCa: false, extraCaPem: caPem });
    const paths = installPaths(result);
    result.cleanup();
    result.cleanup();
    expect(existsSync(result.executablePath)).toBe(false);
    expect(existsSync(result.policyPath)).toBe(false);
    expect(paths.every(path => !existsSync(path))).toBe(true);
    expect(existsSync(executablePath)).toBe(true);
    expect(readFileSync(join(dirname(executablePath), 'untouched.txt'), 'utf8')).toBe('original content\n');
    expect(readdirSync(tempDir)).toEqual([]);
  });

  test.each([
    ['invalid JSON', '{'],
    ['null document', 'null'],
    ['array document', '[]'],
    ['missing policies', '{}'],
    ['null policies', '{"policies":null}'],
    ['array policies', '{"policies":[]}'],
    ['invalid Certificates', '{"policies":{"Certificates":true}}'],
    ['array Certificates', '{"policies":{"Certificates":[]}}'],
    ['string Install', '{"policies":{"Certificates":{"Install":"cert.pem"}}}'],
    ['null Install', '{"policies":{"Certificates":{"Install":null}}}'],
    ['nonstrings in Install', '{"policies":{"Certificates":{"Install":[42]}}}'],
  ])('rejects malformed policy: %s without modifying source or leaving temp files', (_name, bytes) => {
    writeFileSync(policyPath, bytes);
    expect(() => prepare({ trustSystemCa: false, extraCaPem: caPem })).toThrow(/CAMOFOX_EXTRA_CA_CERT/);
    expect(readFileSync(policyPath, 'utf8')).toBe(bytes);
    expect(readdirSync(tempDir)).toEqual([]);
  });

  test('rejects conflicting ImportEnterpriseRoots without changing source', () => {
    const bytes = '{"policies":{"Certificates":{"ImportEnterpriseRoots":false}}}\n';
    writeFileSync(policyPath, bytes);
    expect(() => prepare({ trustSystemCa: true, extraCaPem: null }, {
      systemCertificates: () => [caPem],
    })).toThrow(/CAMOFOX_TRUST_SYSTEM_CA.*ImportEnterpriseRoots/);
    expect(readFileSync(policyPath, 'utf8')).toBe(bytes);
    expect(readdirSync(tempDir)).toEqual([]);
  });

  test.each([['empty', () => []], ['leaf only', () => [leafPem]]])('rejects a Linux store without any CA certificates: %s', (_name, certificates) => {
    expect(() => prepare({ trustSystemCa: true, extraCaPem: null }, {
      systemCertificates: certificates,
    })).toThrow(/CAMOFOX_TRUST_SYSTEM_CA.*no CA certificates/);
    expect(readdirSync(tempDir)).toEqual([]);
  });

  test('fails on an incomplete browser bundle without copying it', () => {
    rmSync(join(dirname(executablePath), 'properties.json'));
    expect(() => prepare({ trustSystemCa: false, extraCaPem: caPem })).toThrow(/CAMOFOX_EXTRA_CA_CERT.*properties.json/);
    expect(readdirSync(tempDir)).toEqual([]);
  });

  test('two preparations coexist in distinct private directories without mutating the source', async () => {
    const bytes = '{"policies":{"DisableAppUpdate":true}}\n';
    writeFileSync(policyPath, bytes);
    const [first, second] = await Promise.all([
      Promise.resolve().then(() => prepare({ trustSystemCa: false, extraCaPem: caPem })),
      Promise.resolve().then(() => prepare({ trustSystemCa: false, extraCaPem: otherCaPem })),
    ]);
    expect(first.executablePath).not.toBe(second.executablePath);
    expect(dirname(installPaths(first)[0])).not.toBe(dirname(installPaths(second)[0]));
    expect(readFileSync(policyPath, 'utf8')).toBe(bytes);
    expect(readFileSync(executablePath)).toEqual(Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
    first.cleanup();
    expect(existsSync(second.executablePath)).toBe(true);
    expect(fingerprints(installPaths(second))).toEqual([new X509Certificate(otherCaPem).fingerprint256]);
  });
});
