/** Additive CA trust. Never edit the shared browser bundle or reuse a profile. */
import { constants, openSync, readSync, closeSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, relative } from 'node:path';
import { tmpdir } from 'node:os';
import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';

/** Prepare once at startup; reuse the private bundle across browser restarts. */
export function prepareCaTrust(config, {
  executablePath,
  platform = process.platform,
  systemCertificates = () => {
    if (typeof tls.getCACertificates !== 'function') throw new Error('CAMOFOX_TRUST_SYSTEM_CA requires Node.js 22.15 or newer on Linux');
    return tls.getCACertificates('system');
  },
  tempDir = tmpdir(),
} = {}) {
  const prefs = config.trustSystemCa ? { 'security.enterprise_roots.enabled': true } : {};
  const unchanged = { firefoxUserPrefs: prefs, executablePath: null, cleanup() {} };
  if (!config.trustSystemCa && !config.extraCaPem) return unchanged;
  const variable = config.extraCaPem ? 'CAMOFOX_EXTRA_CA_CERT' : 'CAMOFOX_TRUST_SYSTEM_CA';
  let root;
  try {
    const certificates = new Map();
    // Firefox's enterprise roots pref does not import the Linux OpenSSL store.
    // Only request system roots, never Node's bundled/extra/default CA sets.
    if (config.trustSystemCa && platform === 'linux') {
      for (const pem of systemCertificates()) {
        const cert = new X509Certificate(pem);
        if (cert.ca) certificates.set(cert.fingerprint256, cert.toString());
      }
      if (!certificates.size) throw new Error('CAMOFOX_TRUST_SYSTEM_CA system store contains no CA certificates');
    }
    if (config.extraCaPem) {
      const cert = new X509Certificate(config.extraCaPem);
      certificates.set(cert.fingerprint256, cert.toString());
    }
    const executable = realpathSync(executablePath);
    if (certificates.size) {
      const fd = openSync(executable, 'r');
      const magic = Buffer.alloc(2);
      try { readSync(fd, magic, 0, magic.length, 0); } finally { closeSync(fd); }
      if (magic.toString() === '#!' || /\.(cmd|bat)$/i.test(executable)) {
        throw new Error('requires a native executable in a self-contained bundle, not a wrapper script');
      }
    }
    const mac = platform === 'darwin' && /\.app[\\/]Contents[\\/]MacOS[\\/]/.test(executable);
    const source = mac ? dirname(dirname(dirname(executable))) : dirname(executable);
    const resourceDir = mac ? join(source, 'Contents', 'Resources') : source;
    if (certificates.size && !existsSync(join(resourceDir, 'properties.json'))) {
      throw new Error('requires a complete Camoufox bundle with properties.json');
    }
    const sourcePolicy = join(resourceDir, 'distribution', 'policies.json');
    const policy = existsSync(sourcePolicy) ? JSON.parse(readFileSync(sourcePolicy, 'utf8')) : { policies: {} };
    const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
    if (!isObject(policy) || !isObject(policy.policies)) throw new Error('existing policies.json must contain a policies object');
    const existing = policy.policies.Certificates === undefined ? {} : policy.policies.Certificates;
    if (!isObject(existing) || (existing.Install !== undefined &&
        (!Array.isArray(existing.Install) || existing.Install.some(path => typeof path !== 'string')))) {
      throw new Error('existing policies.json Certificates.Install must be an array of paths');
    }
    if (config.trustSystemCa && existing.ImportEnterpriseRoots === false) {
      throw new Error('existing policies.json explicitly disables ImportEnterpriseRoots');
    }

    if (!certificates.size) return unchanged;

    root = mkdtempSync(join(tempDir, 'camofox-ca-'));
    // Copy-on-write where available, ordinary copy elsewhere. Never hardlink:
    // policy writes through a hardlink would alter the operator's shared bundle.
    const bundle = join(root, basename(source));
    cpSync(source, bundle, { recursive: true, dereference: true, mode: constants.COPYFILE_FICLONE });
    const distribution = mac ? join(bundle, 'Contents', 'Resources', 'distribution') : join(bundle, 'distribution');
    mkdirSync(distribution, { recursive: true });
    const caDir = join(root, 'certificates');
    mkdirSync(caDir, { mode: 0o700 });
    const paths = [];
    for (const [fingerprint, pem] of certificates) {
      const path = join(caDir, `${fingerprint.replaceAll(':', '')}.pem`);
      writeFileSync(path, pem, { mode: 0o600 });
      paths.push(path);
    }
    policy.policies.Certificates = { ...existing, Install: [...new Set([...(existing.Install || []), ...paths])] };
    writeFileSync(join(distribution, 'policies.json'), `${JSON.stringify(policy, null, 2)}\n`, { mode: 0o600 });
    return {
      firefoxUserPrefs: prefs,
      executablePath: join(bundle, relative(source, executable)),
      policyPath: join(distribution, 'policies.json'),
      cleanup() { rmSync(root, { recursive: true, force: true }); },
    };
  } catch (error) {
    if (root) rmSync(root, { recursive: true, force: true });
    throw new Error(`${variable}: CA trust preparation failed: ${error.message}`);
  }
}
