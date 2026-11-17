/** Real TLS/REST acceptance test. Requires OpenSSL and the installed browser. */
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import https from 'node:https';
import net from 'node:net';
import { once } from 'node:events';

const dir = mkdtempSync(join(tmpdir(), 'camofox-ca-test-'));
const servers = [];
const results = [];
const openssl = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
function certificate(name, issuer, hostname = 'localhost') {
  if (!issuer) {
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', `/CN=${name}`,
      '-keyout', `${name}.key`, '-out', `${name}.pem`, '-addext', 'basicConstraints=critical,CA:TRUE',
      '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
  } else {
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', `/CN=${hostname}`,
      '-keyout', `${name}.key`, '-out', `${name}.csr`);
    writeFileSync(join(dir, `${name}.ext`), `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:${hostname}${hostname === 'localhost' ? ',IP:127.0.0.1' : ''}\n`);
    openssl('x509', '-req', '-in', `${name}.csr`, '-CA', `${issuer}.pem`, '-CAkey', `${issuer}.key`,
      '-CAcreateserial', '-days', '2', '-extfile', `${name}.ext`, '-out', `${name}.pem`);
  }
}
async function serve(name) {
  const server = https.createServer({ key: readFileSync(join(dir, `${name}.key`)), cert: readFileSync(join(dir, `${name}.pem`)) },
    (_req, res) => { res.setHeader('Content-Type', 'text/html'); res.end(`<h1>CA acceptance ${name}</h1>`); });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  servers.push(server);
  return `https://127.0.0.1:${server.address().port}/`;
}
async function port() {
  const server = net.createServer().listen(0, '127.0.0.1');
  await once(server, 'listening');
  const value = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return value;
}
async function run(mode, trusted, unknown, wrongHost) {
  const apiPort = await port();
  const childTemp = join(dir, `tmp-${mode}`);
  mkdirSync(childTemp);
  const env = { ...process.env, TMPDIR: childTemp, TMP: childTemp, TEMP: childTemp, CAMOFOX_PORT: String(apiPort), CAMOFOX_CRASH_REPORT_ENABLED: 'false', CAMOFOX_DISABLE_DEFAULT_ADDONS: 'true' };
  // No ambient trust configuration may contaminate a negative control.
  delete env.CAMOFOX_TRUST_SYSTEM_CA;
  delete env.CAMOFOX_EXTRA_CA_CERT;
  if (mode === 'custom' || mode === 'both') env.CAMOFOX_EXTRA_CA_CERT = join(dir, 'root-a.pem');
  if (mode === 'system' || mode === 'both') env.CAMOFOX_TRUST_SYSTEM_CA = 'true';
  if (process.platform === 'linux') {
    // Scoped OpenSSL system-store equivalent; never modify the host's trust.
    env.SSL_CERT_FILE = join(dir, 'system.pem');
    env.SSL_CERT_DIR = join(dir, 'empty-store');
  }
  const child = spawn(process.execPath, ['server.js'], { cwd: resolve('.'), env, stdio: ['ignore', 'pipe', 'pipe'] });
  let log = '';
  child.stdout.on('data', data => { log += data; });
  child.stderr.on('data', data => { log += data; });
  const exited = once(child, 'exit');
  const api = `http://127.0.0.1:${apiPort}`;
  const userId = `ca-test-${mode}-${Date.now()}`;
  async function request(path, body) {
    const response = await fetch(api + path, { method: body ? 'POST' : 'GET', headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(90000) });
    return { status: response.status, body: await response.json() };
  }
  async function page(url, expectedText, rejected = false) {
    const response = await request('/tabs', { userId, sessionKey: 'ca-test', url });
    if (rejected) {
      assert.ok(response.status >= 400, `${mode} unexpectedly accepted ${url}`);
      const errorCode = expectedText === 'wrong hostname'
        ? /SSL_ERROR_BAD_CERT_DOMAIN/ : /SEC_ERROR_UNKNOWN_ISSUER|SEC_ERROR_UNTRUSTED_ISSUER/;
      assert.match(JSON.stringify(response.body), errorCode);
      results.push({ mode, case: expectedText, result: response.body.error });
    } else {
      assert.equal(response.status, 200, JSON.stringify(response.body));
      const snapshot = await request(`/tabs/${response.body.tabId}/snapshot?userId=${userId}`);
      assert.equal(snapshot.status, 200);
      assert.ok(JSON.stringify(snapshot.body).includes(expectedText), JSON.stringify(snapshot.body));
      results.push({ mode, case: expectedText, result: 'snapshot matched' });
    }
  }
  try {
    let ready = false;
    for (let attempt = 0; attempt < 600; attempt++) {
      if (child.exitCode !== null) throw new Error(`server exited ${child.exitCode}: ${log}`);
      try { if ((await fetch(api + '/health')).ok) { ready = true; break; } } catch {}
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.ok(ready, `startup timeout: ${log}`);
    await page(trusted, 'CA acceptance leaf-a', mode === 'off' || mode === 'off-again');
    await page(unknown, 'unconfigured CA', true);
    if (mode !== 'off' && mode !== 'off-again') await page(wrongHost, 'wrong hostname', true);
    await page('https://example.com', 'documentation');
  } catch (error) {
    writeFileSync(join(dir, `${mode}.log`), log);
    throw new Error(`${error.message}\nServer log: ${dir}/${mode}.log`, { cause: error });
  } finally {
    child.kill('SIGTERM');
    const timeout = setTimeout(() => child.kill('SIGKILL'), 15000);
    const [code] = await exited;
    clearTimeout(timeout);
    assert.equal(code, 0, `server shutdown failed: ${log}`);
    assert.deepEqual(readdirSync(childTemp).filter(name => name.startsWith('camofox-ca-')), [], 'private trust bundle must be removed on shutdown');
  }
}
let success = false;
try {
  certificate('root-a'); certificate('root-b');
  certificate('leaf-a', 'root-a'); certificate('leaf-b', 'root-b'); certificate('wrong-host', 'root-a', 'not-localhost.invalid');
  mkdirSync(join(dir, 'empty-store'));
  writeFileSync(join(dir, 'system.pem'), readFileSync(join(dir, 'root-a.pem')));
  const trusted = await serve('leaf-a'), unknown = await serve('leaf-b'), wrongHost = await serve('wrong-host');
  const modes = process.argv.includes('--baseline') ? ['off'] : process.platform === 'linux' ? ['off', 'custom', 'system', 'both', 'off-again'] : ['off', 'custom', 'off-again'];
  for (const mode of modes) await run(mode, trusted, unknown, wrongHost);
  console.log(JSON.stringify({ platform: process.platform, node: process.version, checks: results.length, privateBundleCleanup: 'passed', results }, null, 2));
  success = true;
} finally {
  await Promise.all(servers.map(server => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); })));
  if (success) rmSync(dir, { recursive: true, force: true });
}
