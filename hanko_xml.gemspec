# frozen_string_literal: true

require_relative "lib/hanko_xml/version"

Gem::Specification.new do |spec|
  spec.name = "hanko_xml"
  spec.version = HankoXml::VERSION
  spec.authors = ["Danimar Ribeiro"]
  spec.email = ["danimaribeiro@gmail.com"]

  spec.summary = "XML digital signature signing and verification for Ruby via a Rust extension calling libxmlsec1."
  spec.description = "hanko_xml signs and verifies XML-DSig signatures by binding to libxmlsec1 " \
                      "through a Rust extension built with Magnus and rb-sys. It integrates directly " \
                      "with Nokogiri and defends against XML Signature Wrapping attacks."
  spec.homepage = "https://github.com/danimaribeiro/HankoXml"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0.0"
  spec.required_rubygems_version = ">= 3.3.11"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/hanko_xml/Cargo.toml"]

  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
