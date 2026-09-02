# frozen_string_literal: true

require "pathname"
require "yaml"

# The gemspec builds spec.files from an allowlist over `git ls-files`, which
# trades one failure mode for another: it can no longer ship the docs site by
# accident, but it can now silently *omit* a newly added source file (or one
# that is still untracked). That failure only shows up as a LoadError in
# someone else's bundle, so it gets caught here instead.
RSpec.describe "gem packaging" do
  let(:root) { Pathname.new(__dir__).join("..").expand_path }
  let(:gemspec) { Gem::Specification.load(root.join("hanko_xml.gemspec").to_s) }
  let(:files) { gemspec.files }

  def tracked(glob)
    Dir.chdir(root) { Dir.glob(glob) }
  end

  it "ships every Ruby source file under lib/" do
    expect(files).to include(*tracked("lib/**/*.rb"))
  end

  it "ships the XML-DSig schema the Verifier validates against" do
    expect(files).to include("lib/hanko_xml/xmldsig-core-schema.xsd")
  end

  it "ships every Rust source file the extension is built from" do
    expect(files).to include(*tracked("ext/**/*.rs"), "ext/hanko_xml/extconf.rb")
  end

  it "ships the pinned upstream manifest the vendored build reads" do
    # HANKO_XML_VENDOR=1 is opt-in on a source install, so build.rs has to be
    # able to find the pinned versions and checksums from inside the gem.
    expect(files).to include("dependencies.yml")
  end

  it "pins a version and a SHA256 for every vendored library" do
    deps = YAML.load_file(root.join("dependencies.yml"))

    expect(deps.keys).to contain_exactly("libxml2", "xmlsec1")
    deps.each_value do |dep|
      expect(dep["version"]).to match(/\A\d+\.\d+\.\d+\z/)
      expect(dep["sha256"]).to match(/\A[0-9a-f]{64}\z/)
      expect(dep["url"]).to start_with("https://")
      # Optional, but if a fallback host is named it has to be https too: the
      # checksum is what establishes trust, not the transport, but there is no
      # reason to fetch over plaintext.
      expect(dep["mirror"]).to start_with("https://") if dep["mirror"]
    end
  end

  it "ships the workspace manifests cargo needs to resolve the extension" do
    # ext/hanko_xml is a workspace member, so building it from an unpacked gem
    # needs the root Cargo.toml and the lockfile that pins magnus/bindgen.
    expect(files).to include("Cargo.toml", "Cargo.lock", "ext/hanko_xml/Cargo.toml")
  end

  it "ships the RBS signatures" do
    expect(files).to include(*tracked("sig/**/*.rbs"))
  end

  it "declares the extension RubyGems has to build at install time" do
    expect(gemspec.extensions).to eq(["ext/hanko_xml/Cargo.toml"])
  end

  it "excludes the docs site, specs, and design assets" do
    expect(files.grep(%r{\A(docs|spec|assets|bin)/})).to be_empty
  end

  it "excludes the long-form design documents" do
    expect(files).not_to include("API_CONTRACT.md", "RUST_COMPARISON.md")
  end

  it "excludes compiled artifacts, so the source gem is built on the target machine" do
    expect(files.grep(/\.(bundle|so|dylib|o|a)\z/)).to be_empty
  end

  it "carries the metadata rubygems.org links from" do
    expect(gemspec.metadata).to include(
      "homepage_uri", "source_code_uri", "changelog_uri", "bug_tracker_uri"
    )
  end

  it "requires MFA to push, since this gem produces signatures" do
    expect(gemspec.metadata["rubygems_mfa_required"]).to eq("true")
  end

  it "records the libxmlsec1 range the bindings are known to work against" do
    expect(gemspec.metadata["xmlsec1_version_requirement"]).to match(/\A>= \d+\.\d+\.\d+, < \d+\.\d+\z/)
  end

  it "keeps the version constant and the CHANGELOG in agreement" do
    changelog = root.join("CHANGELOG.md").read

    expect(changelog).to include("## [#{HankoXml::VERSION}]")
  end
end
