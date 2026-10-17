// Tenant registry: who our customers are, which email domains belong to them,
// and how to reach their identity provider (IdP).
//
// PHASE 1: loaded from config/tenants.json at boot.
// PHASE 2: replace with database queries; the exported functions stay the same.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { SESSION_SECRET } = require('./config');

const ROOT = path.join(__dirname, '..');

// Accept a PEM file or a bare base64 blob (Okta/MockSAML metadata gives you the bare form).
function toPem(raw) {
  const t = raw.trim();
  if (t.includes('BEGIN CERTIFICATE')) return t;
  const body = t.replace(/\s+/g, '').match(/.{1,64}/g).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`;
}

function readCerts(files = []) {
  const certs = [];
  for (const f of files) {
    const p = path.resolve(ROOT, f);
    if (!fs.existsSync(p)) continue;
    const pem = toPem(fs.readFileSync(p, 'utf8'));
    try {
      const x = new crypto.X509Certificate(pem);
      const notAfter = new Date(x.validTo);
      certs.push({
        pem,
        file: f,
        fingerprint256: x.fingerprint256,
        notAfter: notAfter.toISOString(),
        daysLeft: Math.floor((notAfter - Date.now()) / 86_400_000),
      });
    } catch (e) {
      console.warn(`[tenants] ${f} is not a valid certificate: ${e.message}`);
    }
  }
  return certs;
}

function load() {
  const file = process.env.TENANTS_FILE || path.join(ROOT, 'config', 'tenants.json');
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  const bySlug = new Map();
  const byDomain = new Map();

  for (const t of raw.tenants) {
    const certs = readCerts(t.idp?.certFiles);
    const tenant = {
      slug: t.slug,
      name: t.name,
      domains: t.domains.map((d) => ({
        domain: d.domain.toLowerCase(),
        verified: !!d.verified,
        // Stable per-domain token the customer would publish as a DNS TXT record (Phase 2 checks it).
        verificationToken: crypto
          .createHmac('sha256', SESSION_SECRET)
          .update(`${t.slug}:${d.domain.toLowerCase()}`)
          .digest('hex')
          .slice(0, 32),
      })),
      idp: {
        label: t.idp?.label || 'Identity Provider',
        entityId: t.idp?.entityId || '',
        ssoUrl: t.idp?.ssoUrl || '',
        certs,
        requireSignedResponse: !!t.idp?.requireSignedResponse,
        // Only "configured" when we have everything needed to validate a login.
        configured: !!(t.idp?.entityId && t.idp?.ssoUrl && certs.length),
      },
      attributeMap: t.attributeMap || {},
      adminGroup: t.adminGroup || null,
    };
    tenant.verifiedDomains = tenant.domains.filter((d) => d.verified).map((d) => d.domain);
    bySlug.set(tenant.slug, tenant);
    // Only VERIFIED domains are routable (see Home Realm Discovery notes in README).
    for (const d of tenant.domains) if (d.verified) byDomain.set(d.domain, tenant);
  }
  return { bySlug, byDomain };
}

const registry = load();

module.exports = {
  getTenant: (slug) => registry.bySlug.get(String(slug || '').toLowerCase()) || null,
  findByDomain: (domain) => registry.byDomain.get(String(domain || '').toLowerCase()) || null,
  all: () => [...registry.bySlug.values()],
};
