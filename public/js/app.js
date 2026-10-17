(async function main() {
  const user = await api('/api/me');
  renderTopbar(user, 'app');

  document.getElementById('welcome').textContent = `Welcome, ${user.firstName || user.email}`;
  document.getElementById('subtitle').textContent = `${user.tenantName} workspace · role: ${user.role}`;

  // "What did the IdP actually send us?" panel. Great for demos: it makes the SAML assertion tangible.
  const rows = [
    ['Email', user.email],
    ['Name', `${user.firstName} ${user.lastName}`.trim() || '(not sent)'],
    ['Groups', user.groups.length ? user.groups.join(', ') : '(none sent)'],
    ['Identity provider', user.idpLabel],
    ['Issuer (IdP Entity ID)', user.saml.issuer],
    ['NameID', user.saml.nameID],
    ['NameID format', (user.saml.nameIDFormat || '').split(':').pop()],
    ['Assertion ID', user.saml.assertionId],
    ['Signed in', new Date(user.saml.signedAt).toLocaleString()],
  ];
  const box = document.getElementById('session-details');
  for (const [k, v] of rows) {
    box.append(h('div', { class: 'kv stack' }, h('div', { class: 'k' }, k), h('div', { class: 'mono' }, v || '')));
  }
})();
