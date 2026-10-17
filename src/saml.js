// SAML wiring: one Passport strategy that serves EVERY tenant.
//
// ---------------------------------------------------------------------------
// THREE SAML TERMS YOU MUST BE ABLE TO EXPLAIN IN AN INTERVIEW
// ---------------------------------------------------------------------------
//
// 1. ENTITY ID (a.k.a. Issuer / Audience)
//    A globally unique NAME for our app *as seen by one customer's IdP*. It is just a string
//    (by convention a URL, but nothing is fetched from it). The IdP stamps it into every
//    assertion as <Audience> meaning "this login is only valid for THIS app". We reject any
//    assertion whose Audience is not exactly our Entity ID, so a token minted for another app
//    cannot be replayed against us.
//    We use one Entity ID PER TENANT:  {BASE_URL}/saml/{tenant}/metadata
//    so Acme's IdP and Globex's IdP can never be confused with each other.
//
// 2. ACS (Assertion Consumer Service) ENDPOINT
//    The URL on OUR server where the IdP delivers the signed login result. After the user
//    authenticates at the IdP, the IdP returns an auto-submitting HTML form that makes the
//    USER'S BROWSER POST a base64 "SAMLResponse" to this URL. Our job at the ACS:
//      verify the XML signature -> check Issuer, Audience, Recipient, time window,
//      InResponseTo -> reject replays -> build the user -> start a session.
//    Ours is POST {BASE_URL}/saml/{tenant}/acs
//
// 3. SP METADATA ENDPOINT
//    An XML "business card" describing us: our Entity ID, our ACS URL, the NameID format we
//    want, and whether we require signed assertions. The customer's IT admin uploads this to
//    their IdP (Okta: "Upload metadata" or paste fields manually) so the IdP knows where and
//    how to send logins. Ours is GET {BASE_URL}/saml/{tenant}/metadata
//    The IdP has the mirror image: IdP metadata gives us its Entity ID, SSO URL and signing
//    certificate.
//
// SP = Service Provider = us. IdP = Identity Provider = Okta / MockSAML.
// ---------------------------------------------------------------------------

const passport = require('passport');
const { MultiSamlStrategy, ValidateInResponseTo } = require('@node-saml/passport-saml');
const { BASE_URL, DEMO_ADMIN_ALL } = require('./config');
const tenants = require('./tenants');
const { TtlCache, ReplayGuard } = require('./cache');
const { audit } = require('./audit');

const REQUEST_ID_TTL_MS = 5 * 60 * 1000; // user has 5 min to finish authenticating at the IdP
const REPLAY_TTL_MS = 15 * 60 * 1000; // remember used assertion IDs for 15 min (> max validity window)

// One request-ID cache PER TENANT, created once. If this were created inside getSamlOptions
// it would be recreated on every request and InResponseTo validation would always fail.
const requestIdCaches = new Map();
function cacheFor(slug) {
  if (!requestIdCaches.has(slug)) requestIdCaches.set(slug, new TtlCache(REQUEST_ID_TTL_MS));
  return requestIdCaches.get(slug);
}

const replayGuard = new ReplayGuard(REPLAY_TTL_MS);

// Per-tenant identifiers. The tenant slug comes from the URL path, never from user input in the body.
const entityIdFor = (slug) => `${BASE_URL}/saml/${slug}/metadata`;
const acsUrlFor = (slug) => `${BASE_URL}/saml/${slug}/acs`;
const metadataUrlFor = (slug) => `${BASE_URL}/saml/${slug}/metadata`;

/**
 * Called by MultiSamlStrategy on EVERY request: "which SAML settings apply to this request?"
 * This is what makes the app multi-tenant: same code, different IdP settings per tenant.
 */
function getSamlOptions(req, done) {
  const tenant = tenants.getTenant(req.params.tenant);
  if (!tenant) return done(new Error('UNKNOWN_TENANT'));
  req.tenant = tenant; // make it available to the verify callback and routes

  const spEntityId = entityIdFor(tenant.slug);
  const { idp } = tenant;

  done(null, {
    // ---- identity of THIS SP, for THIS tenant ----
    issuer: spEntityId, // our Entity ID, sent in the AuthnRequest
    audience: spEntityId, // assertion must be addressed to exactly this
    callbackUrl: acsUrlFor(tenant.slug), // our ACS URL

    // ---- trust anchors for THIS tenant's IdP ----
    entryPoint: idp.ssoUrl || 'https://idp.not-configured.invalid/sso', // where we redirect the user
    idpIssuer: idp.entityId || undefined, // assertion <Issuer> must equal this
    // Pinned public certificate(s) from the IdP's metadata. We NEVER trust a cert embedded in the
    // incoming message. An array allows certificate rollover (old + new valid at the same time).
    idpCert: idp.certs.length ? idp.certs.map((c) => c.pem) : 'not-configured',

    // ---- validation strictness ----
    wantAssertionsSigned: true, // the assertion itself must carry a valid XML signature
    wantAuthnResponseSigned: idp.requireSignedResponse,
    validateInResponseTo: ValidateInResponseTo.always, // response must answer a request WE sent
    cacheProvider: cacheFor(tenant.slug),
    acceptedClockSkewMs: 60 * 1000, // tolerate 60s clock drift between IdP and us
    maxAssertionAgeMs: 5 * 60 * 1000, // reject assertions issued more than 5 min ago

    // ---- request shape ----
    identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    // Don't dictate HOW the user authenticates (password/MFA/etc.). The IdP's policy decides.
    disableRequestedAuthnContext: true,
  });
}

function assertionIdOf(profile) {
  const parsed = typeof profile.getAssertion === 'function' ? profile.getAssertion() : null;
  const assertion = parsed && (parsed.Assertion || parsed);
  return (assertion && assertion.$ && assertion.$.ID) || null;
}

/**
 * Called ONLY after node-saml has verified the signature and all protocol checks.
 * `profile` is built from the SIGNED part of the XML; this is the only thing we read attributes from.
 * Everything below is OUR business rules on top of the protocol checks.
 */
function signonVerify(req, profile, done) {
  const tenant = req.tenant;
  const fail = (reason, extra = {}) => {
    audit('saml.login.rejected', { tenant: tenant.slug, reason, reqId: req.id, ...extra });
    return done(null, false);
  };
  if (!profile) return fail('no_profile');

  // 0) ISSUER: the signature proves WHO HOLDS THE KEY; this proves the assertion claims to come
  //    from the IdP we configured for this tenant. (node-saml's idpIssuer option does not enforce
  //    this on login responses, so we check explicitly.)
  if (profile.issuer !== tenant.idp.entityId) {
    return fail('issuer_mismatch', { got: String(profile.issuer).slice(0, 120) });
  }

  // 1) REPLAY: an assertion ID is single-use, even inside its validity window.
  //    (profile.ID is only populated for logout requests; for logins we read the ID off the
  //    already-verified assertion that node-saml hands us.)
  const assertionId = assertionIdOf(profile);
  if (!assertionId) return fail('missing_assertion_id');
  if (!replayGuard.firstUse(`${tenant.slug}:${assertionId}`)) {
    return fail('replay_blocked', { assertionId });
  }

  // 2) ATTRIBUTE MAPPING: each IdP names attributes differently; the tenant's attributeMap
  //    translates them into our internal user shape.
  const pick = (internalName) => {
    const v = profile[tenant.attributeMap[internalName]];
    return Array.isArray(v) ? v[0] : v;
  };
  const rawGroups = profile[tenant.attributeMap.groups];
  const groups = rawGroups == null ? [] : Array.isArray(rawGroups) ? rawGroups : [rawGroups];
  const email = String(pick('email') || profile.nameID || '').trim().toLowerCase();
  if (!email.includes('@')) return fail('no_email');

  // 3) CROSS-TENANT GUARD: Acme controls Acme's IdP, so Acme's IdP could assert "ceo@globex.com".
  //    A user may only sign in to a tenant if their email domain is one that tenant has VERIFIED.
  const domain = email.split('@').pop();
  if (!tenant.verifiedDomains.includes(domain)) {
    return fail('email_domain_not_owned_by_tenant', { domain });
  }

  const isAdmin = DEMO_ADMIN_ALL || (tenant.adminGroup && groups.includes(tenant.adminGroup));
  const user = {
    // Identity key is (tenant, IdP issuer, NameID), NOT email. Emails get reassigned; NameIDs don't.
    id: `${tenant.slug}:${profile.issuer}:${profile.nameID}`,
    tenant: tenant.slug,
    tenantName: tenant.name,
    idpLabel: tenant.idp.label,
    email,
    firstName: pick('firstName') || '',
    lastName: pick('lastName') || '',
    groups,
    role: isAdmin ? 'admin' : 'member',
    // Kept for the "what did the IdP actually send?" panel in the demo UI.
    saml: {
      issuer: profile.issuer,
      nameID: profile.nameID,
      nameIDFormat: profile.nameIDFormat,
      sessionIndex: profile.sessionIndex,
      assertionId,
      signedAt: new Date().toISOString(),
    },
  };
  return done(null, user);
}

// We do not implement Single Logout in Phase 1; logout is local (destroy our own session).
const logoutVerify = (req, profile, done) => done(null, false);

const strategy = new MultiSamlStrategy({ passReqToCallback: true, getSamlOptions }, signonVerify, logoutVerify);
passport.use('saml', strategy);

// Passport stores the user in the session between requests. Phase 1 stores the small user object itself.
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

/** Generate SP metadata XML for a tenant (works even before the tenant's IdP is configured). */
function spMetadata(req) {
  return new Promise((resolve, reject) => {
    strategy.generateServiceProviderMetadata(req, null, null, (err, xml) => (err ? reject(err) : resolve(xml)));
  });
}

module.exports = { passport, spMetadata, entityIdFor, acsUrlFor, metadataUrlFor };
