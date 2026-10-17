(async function main() {
  const user = await api('/api/me');
  renderTopbar(user, 'admin');
  const t = await api('/api/admin/tenant');

  document.getElementById('test-sso').href = `/saml/${t.slug}/login`;

  const badge = (cls, text) => h('span', { class: `badge ${cls}` }, text);
  const copyRow = (label, value) => {
    const btn = h('button', { class: 'btn btn-sm', type: 'button' }, 'Copy');
    btn.addEventListener('click', () => copyText(value, btn));
    return h('div', { class: 'kv' }, h('div', { class: 'k' }, label), h('div', { class: 'mono' }, value), btn);
  };
  const row = (label, ...value) => h('div', { class: 'kv two' }, h('div', { class: 'k' }, label), h('div', { class: 'mono' }, ...value));
  const fill = (id, ...nodes) => document.getElementById(id).append(...nodes);

  // 1) Service Provider details: what the customer's IdP admin pastes into Okta / Entra / etc.
  fill(
    'sp-card',
    h('div', { class: 'card-head' }, h('h2', {}, '1. Service provider details (give these to your IdP)'),
      h('a', { class: 'btn btn-sm', href: `${t.sp.metadataUrl}?download` }, 'Download SP metadata XML')),
    copyRow('Entity ID (Audience)', t.sp.entityId),
    copyRow('ACS URL (Reply URL)', t.sp.acsUrl),
    copyRow('Metadata URL', t.sp.metadataUrl),
    row('NameID format', t.sp.nameIdFormat),
    row('Binding', t.sp.binding),
    row('Signed assertions', badge('ok', 'Required'))
  );

  // 2) Identity Provider: what the customer sent back to us.
  const certRows = t.idp.certs.length
    ? t.idp.certs.map((c, i) => {
        const cls = c.daysLeft < 30 ? 'bad' : c.daysLeft < 60 ? 'warn' : 'ok';
        const label = c.daysLeft < 0 ? 'Expired' : `${c.daysLeft} days left`;
        return h('div', { class: 'kv two' },
          h('div', { class: 'k' }, `Signing cert ${i + 1}`),
          h('div', {},
            h('div', { class: 'mono' }, `SHA-256 ${c.fingerprint256}`),
            h('div', { class: 'hint' }, `Expires ${new Date(c.notAfter).toLocaleDateString()} `, badge(cls, label))));
      })
    : [row('Signing certificate', badge('bad', 'Missing'))];
  fill(
    'idp-card',
    h('div', { class: 'card-head' }, h('h2', {}, `2. Identity provider: ${t.idp.label}`),
      t.idp.configured ? badge('ok', 'Configured') : badge('warn', 'Not configured')),
    row('IdP Entity ID (Issuer)', t.idp.entityId || '(not set)'),
    row('IdP SSO URL', t.idp.ssoUrl || '(not set)'),
    ...certRows,
    row('Response signature', t.idp.requireSignedResponse ? badge('ok', 'Required') : badge('muted', 'Assertion signature only'))
  );

  // 3) Domains: HRD only routes VERIFIED domains.
  const domainRows = t.domains.map((d) =>
    h('div', { class: 'kv two' },
      h('div', { class: 'k' }, d.domain),
      h('div', {},
        d.verified ? badge('ok', 'Verified') : badge('warn', 'Pending verification'),
        d.verified ? null : h('div', { class: 'txt-record' },
          h('div', { class: 'hint' }, 'Add this DNS TXT record, then click verify (verification check ships in Phase 2):'),
          h('div', { class: 'mono' }, `${d.txtHost}  TXT  "${d.txtValue}"`))))
  );
  fill('domains-card',
    h('div', { class: 'card-head' }, h('h2', {}, '3. Email domains')),
    h('p', { class: 'hint' }, 'Users with an email on a verified domain are routed to your identity provider automatically.'),
    ...domainRows);

  // 4) Attribute mapping.
  fill('attrs-card',
    h('div', { class: 'card-head' }, h('h2', {}, '4. Attribute mapping')),
    h('p', { class: 'hint' }, `Meridian field ← attribute name in your IdP's assertion. Members of group "${t.adminGroup || '(none)'}" become admins.`),
    ...Object.entries(t.attributeMap).map(([ours, theirs]) => row(ours, theirs)));

  // 5) Audit trail.
  const events = t.events.length
    ? h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Time'), h('th', {}, 'Event'), h('th', {}, 'Details'))),
        h('tbody', {}, ...t.events.map((e) =>
          h('tr', {},
            h('td', { class: 'mono' }, new Date(e.ts).toLocaleTimeString()),
            h('td', {}, e.event),
            h('td', { class: 'mono' }, [e.user, e.reason, e.reqId].filter(Boolean).join(' · '))))))
    : h('p', { class: 'hint' }, 'No sign-in activity yet.');
  fill('events-card', h('div', { class: 'card-head' }, h('h2', {}, '5. Recent sign-in activity')), events);
})();
