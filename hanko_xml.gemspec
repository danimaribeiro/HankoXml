# frozen_string_literal: true

require_relative "lib/hanko_xml/version"

Gem::Specification.new do |spec|
  spec.name = "hanko_xml"
  spec.version = HankoXml::VERSION
  spec.authors = ["Danimar Ribeiro"]
  spec.email = ["danimaribeiro@gmail.com"]

  spec.summary = "XML digital signature signing and verification for Ruby via a Rust extension calling libxmlsec1."
  spec.description = "hanko_xml signs and verifies XML-DSig signatures by binding to libxmlsec1 through " \
                      "a Rust extension built with Magnus and rb-sys, integrating directly with Nokogiri."
  spec.homepage = "https://github.com/danimaribeiro/HankoXml"
  spec.license = "MIT"
  # 3.1 rather than 3.0: 3.0 is end-of-life and, more to the point, is not in
  # the CI matrix. A signing library should not claim a Ruby it never builds on.
  spec.required_ruby_version = ">= 3.1.0"
  # 3.3.11 is the first RubyGems that can build a Cargo.toml extension.
  spec.required_rubygems_version = ">= 3.3.11"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["documentation_uri"] = "#{spec.homepage}#readme"
  spec.metadata["rubygems_mfa_required"] = "true"
  # The libxmlsec1 range this extension's bindgen output is known to be ABI
  # compatible with. Informational for humans and tooling -- the binding check
  # that actually runs is HankoXml::NativeVersion, at require time.
  spec.metadata["xmlsec1_version_requirement"] = ">= 1.2.30, < 1.4"

  # An allowlist, deliberately, rather than a reject list. The repo also
  # carries a full Astro docs site, a 90KB API contract, design assets, and a
  # Rust target dir -- none of which belong in an installed gem. A reject list
  # would silently start shipping the next directory someone adds; this will
  # instead silently omit it, which is the failure that shows up in CI rather
  # than in a user's bundle.
  #
  # Sourced from `git ls-files` so nothing untracked can ride along.
  gem_dirs = %w[lib/ ext/ sig/]
  gem_files = %w[
    Cargo.toml
    Cargo.lock
    dependencies.yml
    README.md
    CHANGELOG.md
    LICENSE.txt
    THIRD_PARTY_LICENSES.md
  ]
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).select do |f|
      gem_files.include?(f) || f.start_with?(*gem_dirs)
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  # The root Cargo.toml/Cargo.lock ship alongside it: ext/hanko_xml is a
  # workspace member, so cargo needs the workspace root to resolve and build it.
  spec.extensions = ["ext/hanko_xml/Cargo.toml"]

  # Nokogiri is deliberately not a runtime dependency. HankoXml::Dom probes for
  # it and degrades by removing capabilities rather than weakening them, so the
  # gem is usable without it. See API_CONTRACT.md §6.1.
end
