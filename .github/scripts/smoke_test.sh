#!/usr/bin/env bash
#
# Verifies a precompiled platform gem on a bare image: no Rust, no
# libxmlsec1-dev, no pkg-config, no libclang. That is the entire promise of
# shipping one, so this is the real acceptance test -- and it has caught two
# bugs no local testing would have (a gem that installed but could not be
# required, and one linked against a libcrypto soname no current distro has).
#
# Runs on Linux inside a bare container and on macOS directly on the runner
# (there is no macOS container to use). PKG_DIR and FIXTURES_DIR default to the
# container mount points.
set -euo pipefail

# Exported, not just assigned: the Ruby subprocesses below read FIXTURES_DIR
# from their own environment.
export PKG_DIR="${PKG_DIR:-/pkg}"
export FIXTURES_DIR="${FIXTURES_DIR:-/fixtures}"

case "$(uname -s)" in
  Darwin) EXT=bundle ;;
  # Yes, .so -- RbConfig::CONFIG['DLEXT'] is "so" even on a mingw Ruby build,
  # despite the underlying file being a PE DLL. Windows falls through here.
  *)      EXT=so ;;
esac

echo "== architecture"
uname -m

echo "== install"
# Resolved explicitly rather than passing /pkg/*.gem straight to `gem install`:
# an unmatched glob is handed through literally, and the error that follows
# ("Could not find a valid gem '/pkg/*.gem'") reads like a corrupt package
# rather than an empty mount.
gems=()
while IFS= read -r line; do gems+=("$line"); done < <(find "$PKG_DIR" -maxdepth 1 -name '*.gem' -print | sort)
if [ "${#gems[@]}" -eq 0 ]; then
  echo "no .gem found in $PKG_DIR -- is the artifact present?" >&2
  ls -la "$PKG_DIR" >&2
  exit 1
fi
printf 'found: %s\n' "${gems[@]}"
gem install --no-document --local "${gems[@]}"

echo "== load, and confirm the vendored libraries are the pinned ones"
ruby -e '
  require "hanko_xml"
  versions = HankoXml::NativeVersion.build_versions
  puts "loaded hanko_xml #{HankoXml::VERSION} on #{RUBY_PLATFORM}"
  puts "vendored: #{versions.inspect}"
  raise "libxml2 is #{versions[:libxml2]}, expected the pinned 2.15.4" unless versions[:libxml2] == "2.15.4"
  raise "xmlsec1 is #{versions[:xmlsec]}, expected the pinned 1.3.12"  unless versions[:xmlsec]  == "1.3.12"
  raise "version guard did not pass" unless HankoXml::NativeVersion.check! == :ok
'

# Loading proves linkage; this proves the crypto actually works on this
# architecture.
echo "== verify a real signature, and reject a wrong certificate"
# Through the public API, not HankoXml::Native: the native signature is private
# and changes with features (#147 added an argument), and a smoke test that
# calls it breaks without anything a user would notice. This also proves
# verification works without Nokogiri, which this bare install does not have.
ruby -e '
  require "hanko_xml"
  xml   = File.read("#{ENV.fetch("FIXTURES_DIR")}/signed.xml")
  good  = File.read("#{ENV.fetch("FIXTURES_DIR")}/signer.crt")
  other = File.read("#{ENV.fetch("FIXTURES_DIR")}/other.crt")

  ok = HankoXml::Verifier.new(certificate: good).verify(xml)
  no = HankoXml::Verifier.new(certificate: other).verify(xml)
  puts "signer cert -> #{ok.valid?} / other cert -> #{no.valid?}"
  raise "expected the signing certificate to verify: #{ok.errors.inspect}" unless ok.valid?
  raise "a non-signing certificate must not verify" if no.valid?
'

echo "== no vendored symbols exported"
if [ "$(uname -s)" = "Linux" ]; then
  apt-get update -qq && apt-get install -y -qq --no-install-recommends binutils >/dev/null
fi

# Resolved from the installed gem rather than Gem.find_files: a platform gem
# keeps its extension under lib/hanko_xml/<ruby abi>/, which that helper does
# not match. It previously returned nothing, and the check passed on an empty
# path without ever inspecting a binary.
gem_dir=$(ruby -e 'require "hanko_xml"; print Gem.loaded_specs.fetch("hanko_xml").gem_dir')
sos=()
while IFS= read -r line; do sos+=("$line"); done < <(find "$gem_dir/lib" -name "hanko_xml.$EXT" | sort)
if [ "${#sos[@]}" -eq 0 ]; then
  echo "could not locate the installed extension under $gem_dir/lib" >&2
  exit 1
fi

# Every ABI, not just the one this Ruby loads: all four ship in the gem, and a
# leak in any of them is a leak a user can hit.
for so in "${sos[@]}"; do
  echo "artifact: $so"

  # PE export/import tables need objdump, which windows-latest does not
  # carry by default. cross-gem.yml checks them on Linux instead, right after
  # building the gem (.github/scripts/check_pe_exports.rb, #20).
  case "$(uname -s)" in
    MINGW*|MSYS*)
      echo "  symbol-leak check: done on Linux in the build job (check_pe_exports.rb)"
      continue
      ;;
  esac

  # Linux exports through the dynamic symbol table; macOS through -gU. The
  # leading underscore is a Mach-O convention, hence the optional _ below.
  if [ "$(uname -s)" = "Darwin" ]; then
    symbols=$(nm -gU "$so" | awk '{print $3}')
    # Skip both the "path:" header and the object's own install name, which
    # Mach-O records first and which rake-compiler leaves pointing at the build
    # directory. Neither is a dependency, and reporting the install name as one
    # makes the output read like a leak that is not there.
    needs=$(otool -L "$so" | tail -n +2 | grep -v 'libhanko_xml' | awk '{printf " %s", $1}')
  else
    symbols=$(nm -D --defined-only "$so" | awk '{print $3}')
    needs=$(objdump -p "$so" | awk '/NEEDED/ {printf " %s", $2}')
  fi
  leaked=$(printf '%s\n' "$symbols" | grep -cE '^_?(xml|xmlSec|EVP_|OPENSSL_|CRYPTO_)' || true)
  echo "  leaked xml*/xmlSec*/openssl exports: $leaked"
  if [ "$leaked" -ne 0 ]; then
    echo "vendored symbols are exported and can be interposed at load time" >&2
    printf '%s\n' "$symbols" | grep -E '^_?(xml|xmlSec|EVP_|OPENSSL_|CRYPTO_)' | head -20 >&2
    exit 1
  fi
  echo "  needs:$needs"

  # The gem must carry its own libxml2, xmlsec1 and OpenSSL. If any of them
  # shows up here it was linked dynamically against the build machine, which
  # works on a CI runner that happens to have it and fails for a user who does
  # not -- the exact bug that shipped an unloadable libcrypto.so.1.1 gem.
  if printf '%s' "$needs" | grep -qE 'libxml2|libxmlsec|libcrypto|libssl'; then
    echo "a vendored library is linked dynamically instead of statically:$needs" >&2
    exit 1
  fi
done

echo "OK"
