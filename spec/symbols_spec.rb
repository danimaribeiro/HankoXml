# frozen_string_literal: true

require "pathname"

# Guards the failure that vendoring introduces and that nothing else would
# catch: two statically-linked copies of libxml2 in one Ruby process (ours and
# Nokogiri's).
#
# On Linux the dynamic linker resolves a duplicated symbol to whichever
# definition was loaded first, process-wide. If this extension exported its
# vendored `xmlReadMemory`, our calls could bind to Nokogiri's libxml2 instead
# -- handing an xmlDocPtr allocated under one struct layout to code compiled
# against another. That is the exact bug documented at length in
# ext/hanko_xml/build.rs, one layer lower down where pkg-config cannot help.
#
# macOS two-level namespaces make this mostly not happen, so a leak here would
# pass local testing on a Mac and fail on production Linux. Hence a test.
#
# On a system (non-vendored) build there is nothing statically linked in to
# leak, so this passes trivially. It has teeth only for HANKO_XML_VENDOR=1
# builds -- which is exactly when it matters.
RSpec.describe "exported symbols" do
  let(:artifact) do
    root = Pathname.new(__dir__).join("..").expand_path
    # Two layouts: a source build puts the extension at
    # lib/hanko_xml/hanko_xml.<so|bundle>, while a precompiled platform gem
    # ships one per ABI under lib/hanko_xml/<major.minor>/. Check both, or this
    # spec silently skips on exactly the artifact it exists to police.
    abi = RUBY_VERSION[/\d+\.\d+/]
    %W[
      lib/hanko_xml/hanko_xml.bundle
      lib/hanko_xml/hanko_xml.so
      lib/hanko_xml/#{abi}/hanko_xml.bundle
      lib/hanko_xml/#{abi}/hanko_xml.so
    ].map { |f| root.join(f) }.find(&:exist?)
  end

  # Linux: only the dynamic symbol table can interpose. macOS: -U hides
  # undefined symbols so we see just what this object actually defines.
  def exported_symbols(path)
    command = if RbConfig::CONFIG["host_os"].match?(/darwin/)
                ["nm", "-gU", path.to_s]
              else
                ["nm", "-D", "--defined-only", path.to_s]
              end
    out = IO.popen(command, err: IO::NULL, &:read)
    return nil unless $CHILD_STATUS&.success?

    out.lines.filter_map { |line| line.split[2] }
  end

  it "exports no libxml2 or xmlsec symbols that could interpose with Nokogiri's copy" do
    skip "extension not built" unless artifact

    symbols = exported_symbols(artifact)
    skip "nm unavailable on this platform" if symbols.nil?

    leaked = symbols.grep(/\A_?(xml|xmlSec)/)

    expect(leaked).to be_empty,
                      "#{leaked.size} vendored symbol(s) are exported and can be interposed " \
                      "at load time: #{leaked.first(10).join(", ")}. Build the vendored " \
                      "libraries with -fvisibility=hidden and, on Linux, link with " \
                      "-Wl,--exclude-libs,ALL."
  end

  it "exports only the Ruby entry point" do
    skip "extension not built" unless artifact

    symbols = exported_symbols(artifact)
    skip "nm unavailable on this platform" if symbols.nil?

    # rb-sys defines ruby_abi_version, but whether the linker keeps it in the
    # dynamic table varies by toolchain (the 0.1.0 platform gems and a local
    # rustc 1.97 build drop it). Ruby checks it only on development builds of
    # Ruby, so it is allowed but not required.
    expect(symbols.map { |s| s.delete_prefix("_") } - ["ruby_abi_version"])
      .to contain_exactly("Init_hanko_xml")
  end
end
