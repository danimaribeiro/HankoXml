/*
 * Theme bridge between the Astro docs site and the YARD-generated API docs.
 *
 * Reads the same `hankoxml_theme` localStorage key the site's ThemeSwitcher
 * writes and mirrors it onto <html> as `hx-dark` / `hx-glass`. Prefixed class
 * names avoid colliding with YARD's own markup. Loaded from <head> so the
 * classes land before first paint.
 *
 * Runs in both the main document and the sidebar <iframe> (same origin), and
 * `storage` events keep the two in sync when the theme changes in either one.
 */
(function () {
  var STORAGE_KEY = 'hankoxml_theme';
  var DEFAULT_THEME = 'glass';

  function currentTheme() {
    try {
      return localStorage.getItem(STORAGE_KEY) || DEFAULT_THEME;
    } catch (e) {
      return DEFAULT_THEME;
    }
  }

  function prefersDark() {
    return (
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-color-scheme: dark)').matches
    );
  }

  function applyTheme(theme) {
    var isGlass = theme === 'glass';
    var isDark = isGlass || theme === 'dark' || (theme === 'system' && prefersDark());
    var root = document.documentElement;

    root.classList.toggle('hx-dark', isDark);
    root.classList.toggle('hx-glass', isGlass);
    root.style.colorScheme = isDark ? 'dark' : 'light';

    var select = document.getElementById('hx-theme-select');
    if (select && select.value !== theme) select.value = theme;
  }

  applyTheme(currentTheme());

  // Fires in every *other* same-origin document, which is how the main page
  // and the sidebar iframe stay in sync with each other and with the site.
  window.addEventListener('storage', function (event) {
    if (event.key === null || event.key === STORAGE_KEY) applyTheme(currentTheme());
  });

  if (typeof window.matchMedia === 'function') {
    var mql = window.matchMedia('(prefers-color-scheme: dark)');
    var onChange = function () {
      if (currentTheme() === 'system') applyTheme('system');
    };
    if (mql.addEventListener) mql.addEventListener('change', onChange);
    else if (mql.addListener) mql.addListener(onChange);
  }

  document.addEventListener('DOMContentLoaded', function () {
    applyTheme(currentTheme());

    var select = document.getElementById('hx-theme-select');
    if (!select) return;

    select.addEventListener('change', function () {
      try {
        localStorage.setItem(STORAGE_KEY, select.value);
      } catch (e) {}
      applyTheme(select.value);

      // `storage` does not fire in the document that wrote the value, so the
      // sidebar iframe is nudged directly.
      var nav = document.getElementById('nav');
      if (nav && nav.contentWindow) {
        try {
          nav.contentWindow.postMessage({ type: 'hankoxml:theme', theme: select.value }, '*');
        } catch (e) {}
      }
    });
  });

  window.addEventListener('message', function (event) {
    if (event.data && event.data.type === 'hankoxml:theme') applyTheme(event.data.theme);
  });
})();
