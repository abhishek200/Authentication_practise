const { BASE_URL } = require('./config');

/** Page/API guard: must be signed in. Pages redirect to /login, API calls get 401 JSON. */
function requireAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'unauthenticated' });
  return res.redirect('/login');
}

/** Guard for the Customer Admin dashboard. */
function requireAdmin(req, res, next) {
  if (req.user?.role === 'admin') return next();
  if (req.path.startsWith('/api/')) return res.status(403).json({ error: 'forbidden' });
  return res.status(403).type('text/plain').send('403: tenant admin role required');
}

/**
 * Lightweight CSRF defence for state-changing JSON routes: the browser always sends an Origin
 * header on cross-site POSTs, so if it is present and is not us, refuse.
 * (The SAML ACS route is exempt: it is protected by the XML signature + InResponseTo instead.)
 */
function sameOriginOnly(req, res, next) {
  const origin = req.get('origin');
  if (origin && origin !== new URL(BASE_URL).origin) {
    return res.status(403).json({ error: 'cross_origin_blocked' });
  }
  next();
}

module.exports = { requireAuth, requireAdmin, sameOriginOnly };
