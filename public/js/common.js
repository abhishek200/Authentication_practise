// Tiny helpers shared by all pages. No framework, no innerHTML: every value that came from a SAML
// assertion is attacker-influenced text, so we only ever set textContent.

/** h('div', {class:'card'}, 'text', childNode) -> HTMLElement */
function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === false || v == null) continue;
    if (k === 'class') node.className = v;
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    node.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return node;
}

async function api(url, options = {}) {
  const res = await fetch(url, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (res.status === 401) {
    location.href = '/login';
    throw new Error('unauthenticated');
  }
  if (!res.ok) throw new Error(`Request failed (${res.status})`);
  return res.json();
}

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const old = button.textContent;
    button.textContent = 'Copied';
    setTimeout(() => (button.textContent = old), 1200);
  } catch {
    window.prompt('Copy:', text);
  }
}

async function logout() {
  await api('/auth/logout', { method: 'POST' }).catch(() => {});
  location.href = '/login';
}

/** Shared top bar. `active` is 'app' or 'admin'. */
function renderTopbar(user, active) {
  const bar = document.getElementById('topbar');
  bar.append(
    h('span', { class: 'brand' }, h('span', { class: 'brand-mark' }), 'Meridian'),
    h('span', { class: 'pill' }, user.tenantName),
    h(
      'nav',
      { class: 'nav' },
      h('a', { href: '/app', class: active === 'app' ? 'active' : '' }, 'Home'),
      user.role === 'admin' ? h('a', { href: '/admin', class: active === 'admin' ? 'active' : '' }, 'Admin: Single sign-on') : null
    ),
    h('span', { class: 'spacer' }),
    h('span', { class: 'muted' }, `${user.firstName || user.email}`),
    h('button', { class: 'btn btn-sm', onclick: logout }, 'Sign out')
  );
}
