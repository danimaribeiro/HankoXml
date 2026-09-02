# frozen_string_literal: true

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
