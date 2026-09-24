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
  var DEFAULT_THEME = 'light';

  function currentTheme() {
    try {
      var theme = localStorage.getItem(STORAGE_KEY);
      // Unknown values (including the retired `system`) fall back to light.
      return theme === 'dark' || theme === 'glass' ? theme : DEFAULT_THEME;
    } catch (e) {
      return DEFAULT_THEME;
    }
  }

  var LABELS = {
    light: { label: 'Light', emoji: '\u2600\uFE0F' },
    dark: { label: 'Dark', emoji: '\uD83C\uDF19' },
    glass: { label: 'Glass', emoji: '\u2726' },
  };

  function applyTheme(theme) {
    var isGlass = theme === 'glass';
    var isDark = isGlass || theme === 'dark';
    var root = document.documentElement;

    root.classList.toggle('hx-dark', isDark);
    root.classList.toggle('hx-glass', isGlass);
    root.style.colorScheme = isDark ? 'dark' : 'light';

    var info = LABELS[theme] || LABELS[DEFAULT_THEME];
    var emoji = document.getElementById('hx-theme-emoji');
    var label = document.getElementById('hx-theme-label');
    if (emoji) emoji.textContent = info.emoji;
    if (label) label.textContent = info.label;
  }

  function setTheme(theme) {
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch (e) {}
    applyTheme(theme);

    // `storage` does not fire in the document that wrote the value, so the
    // sidebar iframe is nudged directly.
    var nav = document.getElementById('nav');
    if (nav && nav.contentWindow) {
      try {
        nav.contentWindow.postMessage({ type: 'hankoxml:theme', theme: theme }, '*');
      } catch (e) {}
    }
  }

  applyTheme(currentTheme());

  // Fires in every *other* same-origin document, which is how the main page
  // and the sidebar iframe stay in sync with each other and with the site.
  window.addEventListener('storage', function (event) {
    if (event.key === null || event.key === STORAGE_KEY) applyTheme(currentTheme());
  });

  function initTopbar() {
    var topbar = document.querySelector('.hx-topbar');
    if (!topbar) return; // the sidebar iframe has no top bar

    // YARD navigates client-side: it fetches the next page, swaps #main and
    // pushState()s the new URL, but this header stays from the first page
    // loaded. Its links are relative to *that* page, so resolve them to
    // absolute URLs now, before the URL can change under them.
    topbar.querySelectorAll('a[href]').forEach(function (a) {
      a.setAttribute('href', a.href);
    });

    var navToggle = topbar.querySelector('.hx-nav-toggle');
    if (navToggle) {
      navToggle.addEventListener('click', function () {
        var open = topbar.classList.toggle('hx-nav-open');
        navToggle.setAttribute('aria-expanded', String(open));
      });
    }

    var dropdown = topbar.querySelector('.hx-theme-dropdown');
    if (!dropdown) return;
    var toggle = dropdown.querySelector('.hx-theme-toggle');
    var menu = dropdown.querySelector('.hx-theme-menu');

    function setMenuOpen(open) {
      menu.hidden = !open;
      dropdown.classList.toggle('hx-open', open);
      toggle.setAttribute('aria-expanded', String(open));
    }

    toggle.addEventListener('click', function (event) {
      event.stopPropagation();
      setMenuOpen(menu.hidden);
    });

    menu.querySelectorAll('[data-theme-option]').forEach(function (option) {
      option.addEventListener('click', function () {
        setTheme(option.getAttribute('data-theme-option'));
        setMenuOpen(false);
      });
    });

    document.addEventListener('click', function (event) {
      if (!dropdown.contains(event.target)) setMenuOpen(false);
    });

    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape') setMenuOpen(false);
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    applyTheme(currentTheme());
    initTopbar();
  });

  window.addEventListener('message', function (event) {
    if (event.data && event.data.type === 'hankoxml:theme') applyTheme(event.data.theme);
  });
})();
