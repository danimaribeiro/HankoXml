# frozen_string_literal: true

require "json"

# Appends the HankoXml skin to YARD's default HTML layout. The extra assets
# live in ../../fulldoc/html/{css,js} so YARD's `generate_assets` copies them
# into the output directory automatically.

def stylesheets
  super + %w[css/hankoxml.css]
end

def javascripts
  # Loaded in <head>, before <body> renders, so the theme classes are on
  # <html> before first paint (no flash of unstyled content).
  %w[js/hankoxml-theme.js] + super
end

# Relative URL of the docs site root (the directory containing `api/`), so
# the top bar links work from any nesting depth and under any GitHub Pages
# base path.
def site_root_url
  "#{File.join(File.dirname(url_for_main), "..")}/"
end

# Top bar links, shared with the Astro site header (src/layouts/Layout.astro)
# so both always match. Hrefs are site-root-relative; absolute URLs are
# external.
def top_nav
  @top_nav ||= JSON.parse(File.read(File.expand_path("../../../../src/topnav.json", __dir__)))
end

def top_nav_href(item)
  external_nav_link?(item) ? item["href"] : "#{site_root_url}#{item["href"]}"
end

def external_nav_link?(item)
  item["href"].match?(%r{\Ahttps?://})
end
