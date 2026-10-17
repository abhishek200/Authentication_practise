// Central place for environment-driven settings.
require('dotenv').config({ quiet: true });
const crypto = require('crypto');

const BASE_URL = (process.env.BASE_URL || 'http://localhost:3000').replace(/\/+$/, '');

let sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
  sessionSecret = crypto.randomBytes(32).toString('hex');
  console.warn('[config] SESSION_SECRET not set: generated a random one. Sessions will not survive a restart.');
}

module.exports = {
  PORT: Number(process.env.PORT) || 3000,
  BASE_URL,
  // https base URL => Secure cookies, __Host- prefix, trust proxy.
  IS_HTTPS: BASE_URL.startsWith('https://'),
  SESSION_SECRET: sessionSecret,
  DEMO_ADMIN_ALL: process.env.DEMO_ADMIN_ALL === 'true',
  SESSION_MAX_AGE_MS: 8 * 60 * 60 * 1000, // absolute session lifetime: 8h
};
