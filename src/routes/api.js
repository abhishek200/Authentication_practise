// JSON endpoints used by the vanilla-JS frontend.
const express = require('express');
const rateLimit = require('express-rate-limit');
const tenants = require('../tenants');
const { audit, recentForTenant } = require('../audit');
const { requireAuth, requireAdmin, sameOriginOnly } = require('../middleware');
const { entityIdFor, acsUrlFor, metadataUrlFor } = require('../saml');

const router = express.Router();

/**
 * HOME REALM DISCOVERY (HRD): "which company's IdP should this person be sent to?"
 * Input: an email. Output: a tenant login URL, or a neutral miss.
 * The miss response is identical for "unknown domain" and "unverified domain" so the endpoint
 * cannot be used to enumerate which companies are our customers.
 */
router.post(
  '/auth/discover',
  rateLimit({ windowMs: 60_000, limit: 20, standardHeaders: true, legacyHeaders: false }),
  sameOriginOnly,
  (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const at = email.lastIndexOf('@');
    const valid = at > 0 && at < email.length - 1 && email.length <= 254;
    const tenant = valid ? tenants.findByDomain(email.slice(at + 1)) : null;

    audit('hrd.lookup', { matched: !!tenant, tenant: tenant?.slug, reqId: req.id });

    if (!tenant) {
      return res.status(200).json({ found: false, message: 'We could not find a single sign-on connection for that email.' });
    }
    return res.json({ found: true, tenantName: tenant.name, idpLabel: tenant.idp.label, loginUrl: `/saml/${tenant.slug}/login` });
  }
);

router.post('/auth/logout', sameOriginOnly, (req, res, next) => {
  const who = req.user;
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => {
      res.clearCookie(req.app.get('cookieName'));
      if (who) audit('session.logout', { tenant: who.tenant, user: who.email });
      res.json({ ok: true });
    });
  });
});

router.get('/api/me', requireAuth, (req, res) => res.json(req.user));

// Customer Admin dashboard data: scoped to the signed-in user's OWN tenant only.
router.get('/api/admin/tenant', requireAuth, requireAdmin, (req, res) => {
  const t = tenants.getTenant(req.user.tenant);
  res.json({
    slug: t.slug,
    name: t.name,
    sp: {
      entityId: entityIdFor(t.slug),
      acsUrl: acsUrlFor(t.slug),
      metadataUrl: metadataUrlFor(t.slug),
      nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      binding: 'HTTP-POST',
      requiresSignedAssertions: true,
    },
    idp: {
      label: t.idp.label,
      configured: t.idp.configured,
      entityId: t.idp.entityId,
      ssoUrl: t.idp.ssoUrl,
      requireSignedResponse: t.idp.requireSignedResponse,
      certs: t.idp.certs.map(({ pem, ...rest }) => rest), // never ship the raw PEM to the browser
    },
    domains: t.domains.map((d) => ({
      domain: d.domain,
      verified: d.verified,
      txtHost: `_meridian-verify.${d.domain}`,
      txtValue: `meridian-verify=${d.verificationToken}`,
    })),
    attributeMap: t.attributeMap,
    adminGroup: t.adminGroup,
    events: recentForTenant(t.slug, 15),
  });
});

module.exports = router;
