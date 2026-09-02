# frozen_string_literal: true

# The class/method/file lists rendered inside the sidebar <iframe> are built
# from a separate document (full_list.erb) with its own asset list, so they
# need the skin wired up independently from the main layout.

def stylesheets_full_list
  super + %w[css/hankoxml-list.css]
end

def javascripts_full_list
  %w[js/hankoxml-theme.js] + super
end
