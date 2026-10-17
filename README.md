# Meridian SSO Demo: multi-tenant SAML Service Provider (Phase 1)

A fictional B2B SaaS ("Meridian") that lets each customer company connect its own identity provider
(Okta, MockSAML, later Entra/Ping) and signs their employees in via SAML 2.0.

## Run it

```bash
npm install
cp .env.example .env        # set SESSION_SECRET (see comment inside)
npm start                   # http://localhost:3000
```

Node 20+. Pages: `/login` (email-first), `/app` (post-login home), `/admin` (customer SSO dashboard).

## Connect Okta (tenant `acme`)

1. Okta Admin → Applications → Create App Integration → **SAML 2.0**.
2. In the Admin dashboard of this app (or the values below), use:
   - Single sign-on URL: `http://localhost:3000/saml/acme/acs` (tick "use for Recipient and Destination")
   - Audience URI (SP Entity ID): `http://localhost:3000/saml/acme/metadata`
   - Name ID format: `EmailAddress`, Application username: `Email`
   - Attribute statements: `email`→`user.email`, `firstName`→`user.firstName`, `lastName`→`user.lastName`
   - Group attribute statement: name `groups`, filter `Matches regex` `.*`
   - Response / Assertion signature: **Signed** (Okta default)
3. If Okta rejects an `http://localhost` URL, run a tunnel (ngrok / Cloudflare Tunnel) and set `BASE_URL` to the https URL in `.env`.
4. Assign yourself to the app. Create an Okta group `Meridian Admins` and add yourself.
5. App → **Sign On** → *View SAML setup instructions*. Copy:
   - Identity Provider Single Sign-On URL → `config/tenants.json` → `acme.idp.ssoUrl`
   - Identity Provider Issuer → `acme.idp.entityId`
   - X.509 certificate → save as `certs/acme-okta.pem`
6. Your Okta user's email domain must match a verified domain in `tenants.json` (default `acme.com`). Change the domain or the Okta user's email so they agree.
7. Restart, open `/login`, type your Okta email.

## Connect MockSAML (tenant `globex`)

1. Open https://mocksaml.com. Download its IdP metadata / certificate and save the certificate as `certs/globex-mocksaml.pem`.
2. `globex.idp.entityId` and `ssoUrl` are pre-filled from memory (`https://saml.example.com/entityid`, `https://mocksaml.com/api/saml/sso`). **Confirm them against the metadata XML**; they were not verifiable from the build sandbox.
3. Sign in with any `name@globex.com` and any password. MockSAML sends no groups, so keep `DEMO_ADMIN_ALL=true` to reach `/admin`.

## Where things are

| File | What it does |
|---|---|
| `src/saml.js` | The multi-tenant strategy; read the header comment (Entity ID, ACS, metadata) |
| `src/routes/saml.js` | `/saml/:tenant/{metadata,login,acs}` |
| `src/routes/api.js` | Home Realm Discovery (`/auth/discover`), logout, admin data |
| `src/tenants.js` | Tenant + domain registry, cert fingerprint/expiry |
| `config/tenants.json` | Tenant config (Phase 2: database) |
| `views/`, `public/` | Login, App Home, Admin SSO dashboard (vanilla JS, no innerHTML) |

## Security controls in Phase 1

Pinned per-tenant IdP certificate (array, for rollover) · signed assertion required · Issuer, Audience,
Recipient, time window with 60s skew · InResponseTo required (unsolicited responses rejected) ·
single-use assertion IDs (replay) · verified-domain guard (a tenant's IdP cannot assert another
company's emails) · HRD only routes verified domains and answers identically for unknown/unverified ·
session regenerated on login · HttpOnly, SameSite=Lax cookie (`__Host-` + Secure on https) ·
strict CSP · generic errors to the browser, specific reasons + correlation ID in the audit log ·
raw SAMLResponse is never logged.

## Known Phase 1 limits (do not claim these as production-hardened)

- Sessions, request-ID cache and replay cache are **in-memory**: single instance only, lost on restart. Phase 2: Redis.
- Tenants and domain verification flags live in a JSON file. The DNS TXT check is displayed but **not yet performed**.
- No Single Logout (logout is local only). No IdP-initiated SSO (rejected by design). No SCIM / deprovisioning.
- Admin access is by IdP group (`adminGroup`) or the `DEMO_ADMIN_ALL` demo switch. Turn the switch off for anything real.

## Phase 2 roadmap

Postgres tenants · IdP metadata XML upload · real DNS TXT verification · Redis sessions/caches ·
certificate-expiry alerts and rollover UI · attribute-mapping editor · OIDC as a second protocol.
