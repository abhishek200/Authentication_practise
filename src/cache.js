// Two tiny in-memory stores. Both are single-process only.
// PHASE 2: swap these for Redis (same interface) so multiple app instances share state.

/**
 * TtlCache implements the CacheProvider interface that node-saml expects.
 *
 * Why it exists: when we send a user to the IdP we put a unique request ID in the AuthnRequest
 * and remember it here. When the SAMLResponse comes back it must carry InResponseTo=<that ID>.
 * If the ID is unknown (or already used), the response is rejected. That kills unsolicited and
 * replayed responses. node-saml removes the ID after first use.
 *
 * It is deliberately NOT stored in the express-session: the ACS request is a cross-site POST
 * coming from the IdP's domain, and SameSite=Lax cookies are not sent on it.
 */
class TtlCache {
  constructor(ttlMs) {
    this.ttlMs = ttlMs;
    this.items = new Map();
  }
  prune() {
    const now = Date.now();
    for (const [k, v] of this.items) if (now - v.createdAt > this.ttlMs) this.items.delete(k);
  }
  async saveAsync(key, value) {
    this.prune();
    const item = { value, createdAt: Date.now() };
    this.items.set(key, item);
    return item;
  }
  async getAsync(key) {
    const item = this.items.get(key);
    if (!item) return null;
    if (Date.now() - item.createdAt > this.ttlMs) {
      this.items.delete(key);
      return null;
    }
    return item.value;
  }
  async removeAsync(key) {
    if (key == null) return null;
    const item = this.items.get(key);
    this.items.delete(key);
    return item ? item.value : null;
  }
}

/**
 * ReplayGuard: an assertion ID may be accepted exactly once.
 * Timestamps alone do not stop replay inside the validity window; this does.
 */
class ReplayGuard {
  constructor(ttlMs) {
    this.ttlMs = ttlMs;
    this.seen = new Map();
  }
  /** @returns {boolean} true the first time a key is seen, false on any repeat */
  firstUse(key) {
    const now = Date.now();
    for (const [k, exp] of this.seen) if (exp < now) this.seen.delete(k);
    if (this.seen.has(key)) return false;
    this.seen.set(key, now + this.ttlMs);
    return true;
  }
}

module.exports = { TtlCache, ReplayGuard };
