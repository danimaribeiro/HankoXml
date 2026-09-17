# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec)

require "rubocop/rake_task"

RuboCop::RakeTask.new

require "rb_sys/extensiontask"

task build: :compile

GEMSPEC = Gem::Specification.load("hanko_xml.gemspec")

# Cross-compiling is driven entirely by RUBY_TARGET: RbSys::ExtensionTask turns
# it on when that variable is present and builds exactly the one platform it
# names. That is how rb-sys-dock and oxidize-rb/actions/cross-gem invoke this,
# one platform per CI job, so the platform list lives in
# .github/workflows/cross-gem.yml rather than here -- setting cross_platform to
# a fixed list would fight that and try to build every target in every job.
#
# The vendored libxml2/xmlsec1 build reads the same TARGET triple to pick its
# autotools --host and cross toolchain; see ext/hanko_xml/build/vendor.rs.
RbSys::ExtensionTask.new("hanko_xml", GEMSPEC) do |ext|
  ext.lib_dir = "lib/hanko_xml"
end

task default: %i[compile spec rubocop]

namespace :interop do
  desc "Fetch the EU DSS XAdES vectors not vendored in spec/interop/xades/dss (see its MANIFEST.tsv)"
  task :dss do
    require "digest"
    require "fileutils"
    require "net/http"

    root = File.expand_path("spec/interop/xades/dss", __dir__)
    manifest = File.readlines(File.join(root, "MANIFEST.tsv"), chomp: true)
    commit = manifest.first[/commit (\h{40})/, 1]
    rows = manifest.reject { |line| line.start_with?("#") }.map { |line| line.split("\t") }

    rows.each do |blob, size, vendored, path|
      next if vendored == "yes"

      target = File.join(root, "corpus", path)
      git_blob = ->(bytes) { Digest::SHA1.hexdigest("blob #{bytes.bytesize}\0#{bytes}") }
      next if File.exist?(target) && git_blob.call(File.binread(target)) == blob

      uri = URI("https://raw.githubusercontent.com/esig/dss/#{commit}/dss-xades/src/test/resources/#{path}")
      bytes = Net::HTTP.get_response(uri).tap(&:value).body.b
      unless bytes.bytesize == Integer(size) && git_blob.call(bytes) == blob
        abort "#{path}: does not match MANIFEST.tsv (expected git blob #{blob})"
      end

      FileUtils.mkdir_p(File.dirname(target))
      File.binwrite(target, bytes)
      puts "fetched #{path}"
    end
  end
end
