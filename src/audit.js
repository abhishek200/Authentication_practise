// Minimal audit log: structured JSON to stdout + a ring buffer the admin dashboard reads.
// PHASE 2: persist to a database table.
const events = [];
const MAX = 200;

function audit(event, fields = {}) {
  const entry = { ts: new Date().toISOString(), event, ...fields };
  events.unshift(entry);
  if (events.length > MAX) events.pop();
  console.log(JSON.stringify(entry));
  return entry;
}

function recentForTenant(slug, limit = 20) {
  return events.filter((e) => e.tenant === slug).slice(0, limit);
}

module.exports = { audit, recentForTenant };
