#!/usr/bin/env ruby
# frozen_string_literal: true

# Watches the C libraries pinned in dependencies.yml, which Dependabot cannot
# see: it understands bundler/cargo/github-actions manifests, not a hand-rolled
# list of tarball URLs and checksums.
#
# Vendoring makes us the distributor of libxml2 and xmlsec1, so responding to
# their security fixes is our obligation rather than the OS vendor's. This
# reports two different things, and the difference matters:
#
#   * a newer PATCH within the pinned minor series -- almost always the shape a
#     security fix arrives in, and directly actionable
#   * a newer minor/major -- a deliberate decision (we pin libxml2 2.14.x while
#     2.15.x exists), so it is reported but not treated as urgent
#   * known advisories against the pinned version, via OSV
#
# Exits 1 when anything actionable is found, so the workflow can open an issue.

require "fileutils"
require "yaml"
require "json"
require "net/http"
require "uri"

ROOT = File.expand_path("../..", __dir__)
DEPS = YAML.load_file(File.join(ROOT, "dependencies.yml"))

def get_json(url)
  uri = URI(url)
  req = Net::HTTP::Get.new(uri)
  req["User-Agent"] = "hanko_xml-vendored-deps-check"
  req["Accept"] = "application/json"
  # GITHUB_TOKEN only raises the api.github.com rate limit; the script works
  # without it, which is why this is conditional rather than required.
  token = ENV.fetch("GITHUB_TOKEN", nil)
  req["Authorization"] = "Bearer #{token}" if token && uri.host == "api.github.com"

  res = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 15, read_timeout: 30) do |http|
    http.request(req)
  end
  return nil unless res.is_a?(Net::HTTPSuccess)

  JSON.parse(res.body)
rescue StandardError => e
  warn "  ! #{uri.host}: #{e.class}: #{e.message}"
  nil
end

def post_json(url, payload)
  uri = URI(url)
  req = Net::HTTP::Post.new(uri)
  req["Content-Type"] = "application/json"
  req["User-Agent"] = "hanko_xml-vendored-deps-check"
  req.body = JSON.dump(payload)

  res = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 15, read_timeout: 30) do |http|
    http.request(req)
  end
  return nil unless res.is_a?(Net::HTTPSuccess)

  JSON.parse(res.body)
rescue StandardError => e
  warn "  ! #{uri.host}: #{e.class}: #{e.message}"
  nil
end

def version_tuple(str)
  str.to_s.sub(/\Av/, "").split(".").map(&:to_i)
end

# Upstream releases: xmlsec publishes GitHub releases, libxml2 tags on GNOME
# GitLab (project 1665).
def upstream_versions(name)
  case name
  when "xmlsec1"
    data = get_json("https://api.github.com/repos/lsh123/xmlsec/releases")
    Array(data).reject { |r| r["prerelease"] || r["draft"] }.map { |r| r["tag_name"].sub(/\Axmlsec_/, "").tr("_", ".") }
  when "libxml2"
    data = get_json("https://gitlab.gnome.org/api/v4/projects/1665/repository/tags?per_page=100")
    Array(data).map { |t| t["name"] }
  when "openssl"
    data = get_json("https://api.github.com/repos/openssl/openssl/releases?per_page=100")
    Array(data).reject { |r| r["prerelease"] || r["draft"] }
               .map { |r| r["tag_name"].to_s.sub(/\Aopenssl-/, "") }
  else
    []
  end.map { |v| v.sub(/\Av/, "") }.select { |v| v.match?(/\A\d+\.\d+\.\d+\z/) }
end

# OSV has no generic ecosystem for C tarballs, so we query through a distro that
# tracks these packages. That proxy is lossy, and naively trusting it produces
# pure noise: querying libxml2 2.14.6, 2.15.0 and 2.15.3 all return the *same*
# two advisories, because upstream tarball versions ("2.14.6") do not carry the
# Debian revision ("2.14.5+dfsg-0.1") its range comparison expects.
#
# So we redo the comparison ourselves against each advisory's recorded fix
# version, with the distro suffix stripped, and drop anything already fixed at
# or below our pin. What survives is split in two, because the two cases
# deserve different urgency:
#
#   :affected  -- a fix exists and is newer than our pin. Actionable.
#   :unknown   -- no fix version recorded. Cannot be judged automatically;
#                 reported as context, never as a reason to fire an alert.
def advisories(name, version)
  body = { "package" => { "name" => name, "ecosystem" => "Debian:12" }, "version" => version }
  data = post_json("https://api.osv.dev/v1/query", body)
  pin = version_tuple(version)

  Array(data && data["vulns"]).filter_map do |vuln|
    fixes = vuln.fetch("affected", []).flat_map do |aff|
      aff.fetch("ranges", []).flat_map { |r| r.fetch("events", []) }
    end.filter_map { |e| e["fixed"] }
      .map { |v| v.sub(/[+~-].*\z/, "") }
      .select { |v| v.match?(/\A\d+(\.\d+)*\z/) }

    summary = (vuln["summary"] || vuln["details"] || "").split("\n").first.to_s[0, 100]

    if fixes.empty?
      [:unknown, vuln["id"], summary]
    else
      # Affected only if every recorded fix is newer than what we ship.
      [:affected, vuln["id"], summary] if fixes.all? { |f| (version_tuple(f) <=> pin) == 1 }
    end
  end
end

findings = []

DEPS.each do |name, dep|
  pinned = dep["version"]
  puts "== #{name} #{pinned}"

  available = upstream_versions(name)
  if available.empty?
    puts "  ? could not read upstream releases (network or API change) -- not treating as clean"
    findings << "- **#{name}**: could not reach upstream to check for new releases."
    next
  end

  pin = version_tuple(pinned)
  newer = available.select { |v| (version_tuple(v) <=> pin) == 1 }
  same_series = newer.select { |v| version_tuple(v).first(2) == pin.first(2) }

  if same_series.any?
    latest = same_series.max_by { |v| version_tuple(v) }
    puts "  ! patch update available in the pinned series: #{pinned} -> #{latest}"
    findings << "- **#{name}**: patch update `#{pinned}` → `#{latest}` in the pinned " \
                "#{pin.first(2).join(".")}.x series. Security fixes usually arrive this way."
  end

  out_of_series = (newer - same_series).max_by { |v| version_tuple(v) }
  puts "  · newer series available: #{out_of_series} (pinned deliberately, not urgent)" if out_of_series

  vulns = advisories(name, pinned)
  affected = vulns.select { |kind, _, _| kind == :affected }
  unknown  = vulns.select { |kind, _, _| kind == :unknown }

  unknown.each { |_, id, summary| puts "  · #{id} (no fix version recorded) #{summary}" }

  next if affected.empty?

  puts "  ! #{affected.size} advisory/advisories fixed in a release newer than #{pinned}"
  affected.each { |_, id, summary| puts "      #{id} #{summary}" }
  findings << "- **#{name} #{pinned}**: #{affected.size} advisory/advisories fixed upstream after " \
              "our pin — #{affected.map { |_, id, _| id }.join(", ")}. (OSV via the Debian " \
              "ecosystem as a proxy, so confirm against upstream before acting.)"
end

if findings.empty?
  puts "\nNothing actionable."
  exit 0
end

puts "\n#{findings.size} finding(s)."
# Defaults under tmp/ rather than the repo root: running this locally should
# not drop an untracked report into the working tree.
findings_file = ENV.fetch("FINDINGS_FILE") do
  FileUtils.mkdir_p(File.join(ROOT, "tmp"))
  File.join(ROOT, "tmp", "vendored-deps-findings.md")
end

File.write(findings_file, <<~MD)
  The pinned C libraries in `dependencies.yml` need a look.

  #{findings.join("\n")}

  Bumping one means changing `version` **and** `sha256` together, then running
  `HANKO_XML_VENDOR=1 bundle exec rake` and confirming `rake` still reports no
  leaked `xml*`/`xmlSec*` exports. See `VENDORING.md`.
MD
exit 1
