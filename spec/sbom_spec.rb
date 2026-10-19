# frozen_string_literal: true

require "json"
require "yaml"
require_relative "../.github/scripts/sbom"

# The SBOM release.yml attaches to every release (#180). It is the only way a
# platform gem user's scanner learns which OpenSSL, libxml2 and xmlsec1 are
# linked into hanko_xml.so, so it must agree with what vendor.rs builds.
RSpec.describe Sbom do
  let(:root) { File.expand_path("..", __dir__) }
  let(:sbom) { described_class.build(root: root, version: HankoXml::VERSION, cargo_metadata: metadata) }
  let(:metadata) { described_class.cargo_metadata(root) }
  let(:components) { sbom.fetch("components").to_h { |c| [c.fetch("name"), c] } }

  it "is a CycloneDX 1.6 document for this gem version" do
    expect(sbom).to include("bomFormat" => "CycloneDX", "specVersion" => "1.6")
    expect(sbom.dig("metadata", "component")).to include("name" => "hanko_xml", "version" => HankoXml::VERSION,
                                                         "purl" => "pkg:gem/hanko_xml@#{HankoXml::VERSION}")
    expect(JSON.parse(JSON.generate(sbom))).to eq(sbom)
  end

  it "lists every vendored library at the version and checksum dependencies.yml pins" do
    YAML.safe_load_file(File.join(root, "dependencies.yml")).each do |name, dep|
      component = components.fetch(name)

      expect(component["version"]).to eq(dep["version"])
      expect(component["hashes"]).to eq([{ "alg" => "SHA-256", "content" => dep["sha256"] }])
      expect(component["licenses"]).to eq([{ "license" => { "id" => dep["license"] } }])
      expect(component["purl"]).to start_with("pkg:generic/#{name}@#{dep["version"]}")
    end
  end

  it "names OpenSSL and libxml2 by the CPE their advisories are filed under" do
    { "openssl" => "openssl:openssl", "libxml2" => "xmlsoft:libxml2" }.each do |name, vendor_product|
      component = components.fetch(name)

      expect(component["cpe"]).to start_with("cpe:2.3:a:#{vendor_product}:#{component["version"]}:")
    end
  end

  it "lists the crates linked into the extension, without build-time-only ones" do
    expect(components).to include("magnus", "rb-sys")
    expect(components.dig("magnus", "purl")).to start_with("pkg:cargo/magnus@")
    expect(components.dig("magnus", "hashes", 0, "content")).to match(/\A\h{64}\z/)
    # bindgen and sha2 are build dependencies; syn and quote only serve the
    # magnus-macros proc macro.
    expect(components.keys).not_to include("bindgen", "sha2", "magnus-macros", "syn", "quote")
  end

  it "reads Cargo.lock checksums by name and version" do
    lock = <<~TOML
      [[package]]
      name = "magnus"
      version = "0.8.2"
      source = "registry+https://github.com/rust-lang/crates.io-index"
      checksum = "#{"a" * 64}"

      [[package]]
      name = "hanko_xml"
      version = "0.2.0"
    TOML

    expect(described_class.cargo_checksums(lock)).to eq(%w[magnus 0.8.2] => "a" * 64)
  end
end
