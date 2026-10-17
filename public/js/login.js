const form = document.getElementById('hrd-form');
const emailInput = document.getElementById('email');
const button = document.getElementById('continue');
const notice = document.getElementById('notice');

function showNotice(kind, text) {
  notice.className = `notice ${kind}`;
  notice.textContent = text;
}

// Error banners driven by the redirect from the server. Messages are generic on purpose;
// the precise rejection reason is only in the server audit log, keyed by the reference ID.
const params = new URLSearchParams(location.search);
if (params.get('error') === 'sso_failed') {
  showNotice('error', `Sign-in failed. Contact your administrator and quote reference ${(params.get('ref') || '').slice(0, 8)}.`);
} else if (params.get('error') === 'not_configured') {
  showNotice('error', "Single sign-on isn't set up for your company yet.");
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = emailInput.value.trim();
  if (!email.includes('@')) return showNotice('error', 'Enter a valid work email.');

  button.disabled = true;
  try {
    // HOME REALM DISCOVERY: the server maps the email domain to the right company + IdP.
    const result = await api('/auth/discover', { method: 'POST', body: JSON.stringify({ email }) });
    if (!result.found) {
      showNotice('error', result.message);
      button.disabled = false;
      return;
    }
    showNotice('info', `Redirecting to ${result.tenantName} (${result.idpLabel})…`);
    setTimeout(() => (location.href = result.loginUrl), 700); // short pause so the audience sees the routing decision
  } catch (err) {
    showNotice('error', 'Something went wrong. Please try again.');
    button.disabled = false;
  }
});
