// The three SAML endpoints, all scoped by tenant slug in the URL path.
const express = require('express');
const rateLimit = require('express-rate-limit');
const { passport, spMetadata } = require('../saml');
const tenants = require('../tenants');
const { audit } = require('../audit');

const router = express.Router();

// Resolve :tenant once for every route below; 404 for unknown tenants.
router.param('tenant', (req, res, next, slug) => {
  const tenant = tenants.getTenant(slug);
  if (!tenant) return res.status(404).type('text/plain').send('Unknown tenant');
  req.tenant = tenant;
  next();
});

// SP METADATA: the customer's IdP admin imports this.
router.get('/:tenant/metadata', async (req, res, next) => {
  try {
    const xml = await spMetadata(req);
    res.type('application/xml');
    if (req.query.download !== undefined) {
      res.set('Content-Disposition', `attachment; filename="${req.tenant.slug}-sp-metadata.xml"`);
    }
    res.send(xml);
  } catch (e) {
    next(e);
  }
});

// SP-INITIATED LOGIN: build a signed-in-spirit "AuthnRequest" and 302 the browser to the IdP.
router.get('/:tenant/login', (req, res, next) => {
  if (!req.tenant.idp.configured) {
    audit('saml.login.blocked', { tenant: req.tenant.slug, reason: 'idp_not_configured', reqId: req.id });
    return res.redirect(303, '/login?error=not_configured');
  }
  audit('saml.login.start', { tenant: req.tenant.slug, reqId: req.id });
  passport.authenticate('saml', { session: false })(req, res, next);
});

// ACS: the IdP's browser POST lands here. This is the security-critical endpoint.
router.post(
  '/:tenant/acs',
  rateLimit({ windowMs: 60_000, limit: 30, standardHeaders: true, legacyHeaders: false }),
  (req, res, next) => {
    if (!req.tenant.idp.configured) return res.redirect(303, '/login?error=not_configured');

    // Custom callback so we control both outcomes and never leak validation details to the browser.
    passport.authenticate('saml', { session: false }, (err, user) => {
      if (err || !user) {
        // The precise reason goes to the audit log; the user only sees a generic message + a reference ID.
        audit('saml.login.failure', {
          tenant: req.tenant.slug,
          reason: err ? err.message : 'rejected_by_policy',
          reqId: req.id,
        });
        return res.redirect(303, `/login?error=sso_failed&ref=${req.id}`);
      }
      // req.login() regenerates the session ID (prevents session fixation) and stores the user.
      req.login(user, (loginErr) => {
        if (loginErr) return next(loginErr);
        audit('saml.login.success', { tenant: user.tenant, user: user.email, role: user.role, reqId: req.id });
        // 303 turns the POST into a GET so the browser lands on /app and never re-POSTs the assertion.
        res.redirect(303, '/app');
      });
    })(req, res, next);
  }
);

module.exports = router;
