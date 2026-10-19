#!/usr/bin/env ruby
# frozen_string_literal: true

# A CycloneDX 1.6 SBOM of what the precompiled platform gems link statically
# (#180): libxml2, xmlsec1 and OpenSSL at the versions pinned in
# dependencies.yml, plus the Rust crates compiled into the extension.
#
# Dependency scanners can't see a static copy of OpenSSL inside
# hanko_xml.so, so without this a user can't tell whether an OpenSSL or
# libxml2 advisory applies to the gem they installed. The source gem links
# the system libraries instead; its users check their OS packages.
#
# release.yml attaches the output to every GitHub release.
#
# Usage: sbom.rb VERSION > hanko_xml-VERSION.cdx.json
#   (run from the repository root; needs cargo for the crate list)

require "json"
require "open3"
require "securerandom"
require "time"
require "yaml"

# Builds the SBOM document from dependencies.yml, Cargo.lock and cargo metadata.
module Sbom
  # CPE names the NVD files advisories under, so scanners that match on CPE
  # (Grype, Trivy) find them. xmlsec1 has no stable CPE, so it relies on its
  # purl and name.
  CPE_VENDOR_PRODUCT = {
    "libxml2" => "xmlsoft:libxml2",
    "openssl" => "openssl:openssl"
  }.freeze

  module_function

  def build(root:, version:, cargo_metadata:, timestamp: Time.now.utc)
    crates = linked_crates(cargo_metadata, cargo_checksums(File.read(File.join(root, "Cargo.lock"))))
    {
      "bomFormat" => "CycloneDX",
      "specVersion" => "1.6",
      "serialNumber" => "urn:uuid:#{SecureRandom.uuid}",
      "version" => 1,
      "metadata" => {
        "timestamp" => timestamp.iso8601,
        "component" => {
          "type" => "library",
          "bom-ref" => "pkg:gem/hanko_xml@#{version}",
          "name" => "hanko_xml",
          "version" => version,
          "purl" => "pkg:gem/hanko_xml@#{version}",
          "licenses" => [{ "license" => { "id" => "MIT" } }],
          "description" => "Precompiled platform gems. The source gem links the system libxml2, " \
                           "libxmlsec1 and OpenSSL instead of the copies listed here."
        }
      },
      "components" => vendored_libraries(root) + crates
    }
  end

  def vendored_libraries(root)
    YAML.safe_load_file(File.join(root, "dependencies.yml")).map do |name, dep|
      purl = "pkg:generic/#{name}@#{dep.fetch("version")}?download_url=#{dep.fetch("url")}"
      component = {
        "type" => "library",
        "bom-ref" => purl,
        "name" => name,
        "version" => dep.fetch("version"),
        "purl" => purl,
        "hashes" => [{ "alg" => "SHA-256", "content" => dep.fetch("sha256") }],
        "licenses" => [{ "license" => { "id" => dep.fetch("license") } }],
        "externalReferences" => [{ "type" => "distribution", "url" => dep.fetch("url") }]
      }
      if (vendor_product = CPE_VENDOR_PRODUCT[name])
        component["cpe"] = "cpe:2.3:a:#{vendor_product}:#{dep.fetch("version")}:*:*:*:*:*:*:*"
      end
      component
    end
  end

  # The crates hanko_xml depends on through normal (not build or dev) edges:
  # what ends up in the compiled extension. Build-script tools (bindgen) and
  # proc-macro crates (magnus-macros and its syn/quote) run at compile time
  # and are left out, along with everything only they depend on.
  def linked_crates(metadata, checksums)
    nodes = metadata.fetch("resolve").fetch("nodes").to_h { |node| [node.fetch("id"), node] }
    packages = metadata.fetch("packages").to_h { |pkg| [pkg.fetch("id"), pkg] }
    root_ids = metadata.fetch("workspace_members")

    seen = {}
    queue = root_ids.dup
    until queue.empty?
      nodes.fetch(queue.shift).fetch("deps").each do |dep|
        next unless dep.fetch("dep_kinds").any? { |kind| kind["kind"].nil? }
        next if seen[dep.fetch("pkg")] || proc_macro?(packages.fetch(dep.fetch("pkg")))

        seen[dep.fetch("pkg")] = true
        queue << dep.fetch("pkg")
      end
    end

    seen.keys.map { |id| crate_component(packages.fetch(id), checksums) }.sort_by { |c| c["name"] }
  end

  def proc_macro?(pkg)
    pkg.fetch("targets").any? { |target| target.fetch("kind").include?("proc-macro") }
  end

  def crate_component(pkg, checksums)
    name = pkg.fetch("name")
    version = pkg.fetch("version")
    purl = "pkg:cargo/#{name}@#{version}"
    component = { "type" => "library", "bom-ref" => purl, "name" => name, "version" => version, "purl" => purl }
    if (sha = checksums[[name, version]])
      component["hashes"] = [{ "alg" => "SHA-256", "content" => sha }]
    end
    component["licenses"] = [{ "expression" => pkg["license"] }] if pkg["license"]
    component
  end

  # Cargo.lock's [[package]] checksums, keyed by [name, version]. Only the
  # three keys needed, so no TOML parser.
  def cargo_checksums(lockfile)
    lockfile.split("[[package]]").drop(1).each_with_object({}) do |entry, out|
      fields = entry.scan(/^(name|version|checksum) = "([^"]*)"$/).to_h
      out[[fields["name"], fields["version"]]] = fields["checksum"] if fields["checksum"]
    end
  end

  def cargo_metadata(root)
    out, status = Open3.capture2("cargo", "metadata", "--format-version", "1", "--locked", chdir: root)
    raise "cargo metadata failed" unless status.success?

    JSON.parse(out)
  end
end

if $PROGRAM_NAME == __FILE__
  version = ARGV.fetch(0) { abort "usage: sbom.rb VERSION" }
  root = File.expand_path("../..", __dir__)
  puts JSON.pretty_generate(Sbom.build(root: root, version: version, cargo_metadata: Sbom.cargo_metadata(root)))
end
