const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const config = require('./config');
const { passport } = require('./saml');
const { requireAuth, requireAdmin } = require('./middleware');
const samlRoutes = require('./routes/saml');
const apiRoutes = require('./routes/api');

const app = express();
app.disable('x-powered-by');
if (config.IS_HTTPS) app.set('trust proxy', 1); // behind a TLS-terminating proxy (Render, Fly, ngrok...)

// Correlation ID: shown to the user on errors, written to every audit line.
app.use((req, res, next) => {
  req.id = crypto.randomUUID().slice(0, 8);
  res.set('X-Request-Id', req.id);
  next();
});

// Security headers. Strict CSP: our own scripts/styles only, no inline code.
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: { 'script-src': ["'self'"], 'style-src': ["'self'"], 'form-action': ["'self'"] },
    },
  })
);

// The IdP POSTs form-encoded data to the ACS. SAML responses are a few KB; cap the body size.
app.use(express.urlencoded({ extended: false, limit: '256kb' }));
app.use(express.json({ limit: '16kb' }));

// Session cookie: HttpOnly (JS can't read it), Secure on https, __Host- prefix on https
// (locks the cookie to this exact host), SameSite=Lax (not sent on cross-site POSTs).
const cookieName = config.IS_HTTPS ? '__Host-sid' : 'sid';
app.set('cookieName', cookieName);
app.use(
  session({
    name: cookieName,
    secret: config.SESSION_SECRET,
    resave: false,
    saveUninitialized: false, // no cookie until someone actually signs in
    // PHASE 2: replace the default MemoryStore with connect-redis. MemoryStore leaks memory and
    // loses all sessions on restart; fine for a demo, not for production.
    cookie: { httpOnly: true, secure: config.IS_HTTPS, sameSite: 'lax', path: '/', maxAge: config.SESSION_MAX_AGE_MS },
  })
);
app.use(passport.initialize());
app.use(passport.session());

// Static assets (css/js only). HTML pages are served explicitly below so we can guard them.
app.use('/static', express.static(path.join(__dirname, '..', 'public'), { maxAge: '5m' }));

const view = (name) => (req, res) => res.sendFile(path.join(__dirname, '..', 'views', `${name}.html`));

app.get('/', (req, res) => res.redirect(req.isAuthenticated() ? '/app' : '/login'));
app.get('/login', view('login'));
app.get('/app', requireAuth, view('app'));
app.get('/admin', requireAuth, requireAdmin, view('admin'));
app.get('/healthz', (req, res) => res.json({ ok: true }));

app.use('/saml', samlRoutes);
app.use('/', apiRoutes);

// Last-resort error handler: generic message out, detail to the log.
app.use((err, req, res, next) => {
  console.error(JSON.stringify({ level: 'error', reqId: req.id, message: err.message }));
  if (res.headersSent) return next(err);
  res.status(500).type('text/plain').send(`Something went wrong. Reference: ${req.id}`);
});

app.listen(config.PORT, () => {
  console.log(`Meridian SSO demo running at ${config.BASE_URL}`);
});
