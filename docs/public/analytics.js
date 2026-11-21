/*
 * Google Analytics 4 and its consent banner, shared by the Astro site
 * (src/layouts/Layout.astro) and the YARD API docs
 * (yard-template/default/layout/html/layout.erb). Both load it from <head>.
 *
 * Analytics loads by default. A visitor who rejects it gets
 * `analytics-consent` = `denied` in localStorage, and from then on nothing
 * from Google loads. The banner shows until the visitor picks either button.
 *
 * The banner follows the site theme: `dark` / `glass` classes on <html> in
 * the Astro site, `hx-dark` / `hx-glass` in the YARD docs.
 */
(function () {
  var ID = 'G-D17785XK3V';
  var KEY = 'analytics-consent';

  function readChoice() {
    try {
      return localStorage.getItem(KEY);
    } catch (e) {
      return null;
    }
  }

  function storeChoice(value) {
    try {
      localStorage.setItem(KEY, value);
    } catch (e) {}
  }

  var choice = readChoice();
  if (choice === 'denied') return;

  window.dataLayer = window.dataLayer || [];
  function gtag() {
    window.dataLayer.push(arguments);
  }
  window.gtag = gtag;
  gtag('consent', 'default', {
    analytics_storage: 'granted',
    ad_storage: 'granted',
    ad_user_data: 'granted',
    ad_personalization: 'granted',
  });
  gtag('js', new Date());
  gtag('config', ID);

  var tag = document.createElement('script');
  tag.async = true;
  tag.src = 'https://www.googletagmanager.com/gtag/js?id=' + ID;
  document.head.appendChild(tag);

  if (choice === 'granted') return;

  // Removes _ga and _ga_* for this host and every parent domain
  // (.danimar.dev on the live site), which is where gtag sets them.
  function deleteGaCookies() {
    var labels = location.hostname.split('.');
    var domains = [''];
    for (var i = 0; i < labels.length - 1; i++) {
      domains.push('; domain=.' + labels.slice(i).join('.'));
    }
    document.cookie.split(';').forEach(function (pair) {
      var name = pair.split('=')[0].trim();
      if (name !== '_ga' && name.indexOf('_ga_') !== 0) return;
      domains.forEach(function (domain) {
        document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/' + domain;
      });
    });
  }

  var CSS =
    '.hx-consent{position:fixed;z-index:60;right:16px;bottom:16px;max-width:24rem;' +
    'display:flex;flex-wrap:wrap;align-items:center;gap:12px;padding:14px 16px;' +
    'font:14px/1.45 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;' +
    'color:#1e293b;background:#fff;border:1px solid #e5e7eb;border-radius:12px;' +
    'box-shadow:0 10px 25px -5px rgba(15,23,42,.15)}' +
    '.hx-consent p{margin:0;flex:1 1 14rem}' +
    '.hx-consent-actions{display:flex;gap:8px;margin-left:auto}' +
    '.hx-consent button{font:inherit;font-weight:600;padding:6px 14px;border-radius:8px;cursor:pointer;' +
    'border:1px solid #e5e7eb;background:transparent;color:#1f2937}' +
    '.hx-consent button:hover{background:#f3f4f6}' +
    '.hx-consent button.hx-consent-ok{border-color:transparent;background:#2563eb;color:#fff}' +
    '.hx-consent button.hx-consent-ok:hover{background:#1d4ed8}' +
    '.hx-consent button:focus-visible{outline:2px solid #2563eb;outline-offset:2px}' +
    ':is(.dark,.hx-dark) .hx-consent{color:#e2e8f0;background:#1e293b;border-color:#374151;' +
    'box-shadow:0 10px 25px -5px rgba(0,0,0,.5)}' +
    ':is(.dark,.hx-dark) .hx-consent button{border-color:#374151;color:#fff}' +
    ':is(.dark,.hx-dark) .hx-consent button:hover{background:rgba(255,255,255,.1)}' +
    ':is(.glass,.hx-glass) .hx-consent{color:#e5e7eb;background:rgba(17,24,39,.96);' +
    'border-color:rgba(255,255,255,.12);-webkit-backdrop-filter:blur(40px);backdrop-filter:blur(40px);' +
    'box-shadow:inset 0 1px 1px rgba(255,255,255,.1)}' +
    ':is(.glass,.hx-glass) .hx-consent button{border-color:rgba(255,255,255,.15);background:rgba(255,255,255,.08)}' +
    ':is(.glass,.hx-glass) .hx-consent button:hover{background:rgba(255,255,255,.12)}' +
    ':is(.dark,.hx-dark,.glass,.hx-glass) .hx-consent button.hx-consent-ok{border-color:transparent;background:#2563eb;color:#fff}' +
    ':is(.dark,.hx-dark,.glass,.hx-glass) .hx-consent button.hx-consent-ok:hover{background:#1d4ed8}' +
    '@media (max-width:639px){.hx-consent{left:16px;max-width:none}}';

  function showBanner() {
    var style = document.createElement('style');
    style.textContent = CSS;
    document.head.appendChild(style);

    var banner = document.createElement('div');
    banner.className = 'hx-consent';
    banner.setAttribute('role', 'region');
    banner.setAttribute('aria-label', 'Cookie notice');
    banner.innerHTML =
      '<p>This site uses Google Analytics cookies to count visits.</p>' +
      '<div class="hx-consent-actions">' +
      '<button type="button" class="hx-consent-reject">Reject</button>' +
      '<button type="button" class="hx-consent-ok">OK</button>' +
      '</div>';
    document.body.appendChild(banner);

    banner.querySelector('.hx-consent-ok').addEventListener('click', function () {
      storeChoice('granted');
      banner.remove();
    });

    banner.querySelector('.hx-consent-reject').addEventListener('click', function () {
      storeChoice('denied');
      gtag('consent', 'update', {
        analytics_storage: 'denied',
        ad_storage: 'denied',
        ad_user_data: 'denied',
        ad_personalization: 'denied',
      });
      window['ga-disable-' + ID] = true;
      deleteGaCookies();
      banner.remove();
    });
  }

  if (document.body) {
    showBanner();
  } else {
    document.addEventListener('DOMContentLoaded', showBanner);
  }
})();
