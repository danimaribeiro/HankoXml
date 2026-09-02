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
