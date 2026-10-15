#!/usr/bin/env ruby
# frozen_string_literal: true

# The Windows leg of the symbol-leak check (#20). spec/symbols_spec.rb and
# smoke_test.sh use nm/otool, which do not read PE files, so the x64-mingw-ucrt
# platform gem went unchecked.
#
# Two things would let our statically linked libxml2/xmlsec1/OpenSSL meet
# another copy in the same Ruby process (Nokogiri's, most likely):
#
#   * the DLL exports their symbols. Windows binds imports per DLL, so this is
#     not the process-wide interposition ELF has, but any export besides the
#     Ruby entry points means the static archives leaked through
#     -Wl,--exclude-libs,ALL and should be fixed the same way.
#   * the DLL imports one of them from another DLL, i.e. it was not linked
#     statically at all and would pick up whatever copy is on PATH.
#
# Runs on Linux in cross-gem.yml: Ubuntu's binutils objdump reads pei-x86-64,
# while the windows-latest runner has no objdump by default.
#
# Usage: check_pe_exports.rb pkg/hanko_xml-*-x64-mingw-ucrt.gem

require "open3"
require "rubygems/package"
require "tmpdir"

# Parses `objdump -p` for a PE DLL and checks hanko_xml's isolation rules.
module PeExports
  # What a Ruby extension built by rb-sys exports, and nothing else.
  ALLOWED_EXPORTS = %w[Init_hanko_xml ruby_abi_version].freeze

  # DLLs that would mean a vendored library is linked dynamically.
  VENDORED_DLL = /\A(lib)?(xml2|xmlsec|crypto|ssl|iconv)\b/i

  module_function

  # Parses `objdump -p` output into the exported names and imported DLLs.
  def parse(objdump_output)
    exports = []
    dlls = []
    in_exports = false

    objdump_output.each_line do |line|
      if (dll = line[/^\s*DLL Name:\s*(\S+)/, 1])
        dlls << dll
      elsif line.start_with?("[Ordinal/Name Pointer] Table")
        in_exports = true
      elsif in_exports && line.strip.empty?
        in_exports = false
      elsif in_exports && (name = line[/^\s*\[\s*\d+\]\s+\+base\[\s*\d+\]\s+\h+\s+(\S+)/, 1])
        exports << name
      end
    end

    { exports: exports, dlls: dlls }
  end

  # Human-readable problems with one parsed DLL; empty when it is clean.
  def problems(parsed)
    found = []
    extra = parsed[:exports] - ALLOWED_EXPORTS
    found << "exports #{extra.size} symbol(s) besides the Ruby entry point: #{extra.first(10).join(", ")}" if extra.any?
    unless parsed[:exports].include?("Init_hanko_xml")
      found << "never exports Init_hanko_xml, so this is not the extension (or the table did not parse)"
    end
    linked = parsed[:dlls].grep(VENDORED_DLL)
    found << "imports a vendored library dynamically: #{linked.join(", ")}" if linked.any?
    found
  end

  def objdump(path)
    out, status = Open3.capture2e("objdump", "-p", path)
    raise "objdump -p #{path} failed:\n#{out}" unless status.success?

    out
  end

  # Unpacks each gem and checks every hanko_xml.so (one per Ruby ABI) in it.
  # Returns the number of failing DLLs.
  def check_gems(gem_paths)
    failures = 0
    gem_paths.each do |gem_path|
      Dir.mktmpdir do |dir|
        Gem::Package.new(gem_path).extract_files(dir)
        dlls = Dir.glob(File.join(dir, "lib", "**", "hanko_xml.so"))
        raise "no hanko_xml.so in #{gem_path}" if dlls.empty?

        dlls.each do |dll|
          relative = dll.delete_prefix("#{dir}/")
          found = problems(parse(objdump(dll)))
          puts "#{File.basename(gem_path)} #{relative}: #{found.empty? ? "OK" : "FAIL"}"
          found.each { |problem| puts "  #{problem}" }
          failures += 1 if found.any?
        end
      end
    end
    failures
  end
end

if $PROGRAM_NAME == __FILE__
  abort "usage: #{$PROGRAM_NAME} GEM..." if ARGV.empty?
  exit(PeExports.check_gems(ARGV).zero? ? 0 : 1)
end
