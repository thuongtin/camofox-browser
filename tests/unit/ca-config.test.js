import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from '@jest/globals';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig } from '../../lib/config.js';

const originalEnv = { ...process.env };
let directory;
let caPath;
let caPem;
let leafPem;

beforeAll(() => {
  directory = mkdtempSync(join(tmpdir(), 'camofox-ca-config-'));
  caPath = join(directory, 'ca.pem');
  for (const [name, isCa] of [['ca', true], ['leaf', false]]) {
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
      '-subj', `/CN=Camofox ${name} fixture`,
      '-addext', `basicConstraints=critical,CA:${isCa ? 'TRUE' : 'FALSE'}`,
      '-keyout', join(directory, `${name}.key`), '-out', join(directory, `${name}.pem`),
    ], { stdio: 'pipe' });
  }
  caPem = readFileSync(caPath, 'utf8');
  leafPem = readFileSync(join(directory, 'leaf.pem'), 'utf8');
});

beforeEach(() => {
  process.env = { ...originalEnv };
  for (const key of [
    'CAMOFOX_TRUST_SYSTEM_CA', 'CAMOFOX_EXTRA_CA_CERT', 'CAMOFOX_LOCALE',
    'CAMOFOX_TIMEZONE', 'CAMOFOX_OS', 'PROXY_PROTOCOL',
  ]) delete process.env[key];
});

afterEach(() => { process.env = { ...originalEnv }; });
afterAll(() => { if (directory) rmSync(directory, { recursive: true, force: true }); });

describe('certificate authority configuration', () => {
  test('defaults to no additional trust and forwards absent values unchanged', () => {
    const config = loadConfig();
    expect(config).toMatchObject({ trustSystemCa: false, extraCaCert: null, extraCaPem: null });
    expect(config.serverEnv.CAMOFOX_TRUST_SYSTEM_CA).toBeUndefined();
    expect(config.serverEnv.CAMOFOX_EXTRA_CA_CERT).toBeUndefined();
  });

  test.each([['true', true], ['false', false]])('accepts exact trust flag %s', (flag, enabled) => {
    process.env.CAMOFOX_TRUST_SYSTEM_CA = flag;
    const config = loadConfig();
    expect(config.trustSystemCa).toBe(enabled);
    expect(config.extraCaCert).toBeNull();
    expect(config.extraCaPem).toBeNull();
    expect(config.serverEnv.CAMOFOX_TRUST_SYSTEM_CA).toBe(flag);
  });

  test.each(['', '1', '0', 'TRUE', 'False', ' true', 'true ', 'yes'])('rejects invalid trust flag %j', flag => {
    process.env.CAMOFOX_TRUST_SYSTEM_CA = flag;
    expect(() => loadConfig()).toThrow(/CAMOFOX_TRUST_SYSTEM_CA/);
  });

  test.each([undefined, 'false', 'true'])('extra CA is independent of system trust %s', flag => {
    if (flag !== undefined) process.env.CAMOFOX_TRUST_SYSTEM_CA = flag;
    process.env.CAMOFOX_EXTRA_CA_CERT = caPath;
    const config = loadConfig();
    expect(config).toMatchObject({ trustSystemCa: flag === 'true', extraCaCert: caPath, extraCaPem: caPem });
    expect(config.serverEnv.CAMOFOX_EXTRA_CA_CERT).toBe(caPath);
  });

  test('captures immutable PEM contents rather than rereading the configured path', () => {
    const snapshotPath = join(directory, 'snapshot.pem');
    writeFileSync(snapshotPath, caPem);
    process.env.CAMOFOX_EXTRA_CA_CERT = snapshotPath;
    const config = loadConfig();
    writeFileSync(snapshotPath, leafPem);
    expect(config.extraCaPem).toBe(caPem);
    expect(() => loadConfig()).toThrow(/CAMOFOX_EXTRA_CA_CERT/);
  });

  test.each(['', 'ca.pem', './ca.pem', '../ca.pem', '~/ca.pem'])('rejects nonabsolute path %j', value => {
    process.env.CAMOFOX_EXTRA_CA_CERT = value;
    expect(() => loadConfig()).toThrow(/CAMOFOX_EXTRA_CA_CERT.*absolute/);
  });

  test('rejects a missing file', () => {
    process.env.CAMOFOX_EXTRA_CA_CERT = join(directory, 'missing.pem');
    expect(() => loadConfig()).toThrow(/CAMOFOX_EXTRA_CA_CERT.*readable regular file/);
  });

  test('rejects a directory', () => {
    process.env.CAMOFOX_EXTRA_CA_CERT = directory;
    expect(() => loadConfig()).toThrow(/CAMOFOX_EXTRA_CA_CERT.*readable regular file/);
  });

  test.each([
    ['empty file', () => ''],
    ['arbitrary text', () => 'not a certificate'],
    ['invalid DER', () => '-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n'],
    ['invalid base64', () => '-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n'],
    ['leaf certificate', () => leafPem],
    ['multiple certificates', () => caPem + caPem],
    ['prefixed text', () => 'prefix\n' + caPem],
    ['suffixed text', () => caPem + 'suffix'],
    ['another PEM block', () => caPem + '-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n'],
    ['truncated certificate', () => caPem.replace('-----END CERTIFICATE-----', '')],
  ])('rejects %s', (_name, content) => {
    const invalidPath = join(directory, 'invalid.pem');
    writeFileSync(invalidPath, content());
    process.env.CAMOFOX_EXTRA_CA_CERT = invalidPath;
    expect(() => loadConfig()).toThrow(/CAMOFOX_EXTRA_CA_CERT.*exactly one valid PEM X\.509 CA certificate/);
  });

  test('accepts CRLF PEM without changing the snapshot', () => {
    const crlfPath = join(directory, 'crlf.pem');
    const crlfPem = caPem.replace(/\n/g, '\r\n');
    writeFileSync(crlfPath, crlfPem);
    process.env.CAMOFOX_EXTRA_CA_CERT = crlfPath;
    expect(loadConfig().extraCaPem).toBe(crlfPem);
  });
});
