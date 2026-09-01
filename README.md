# HankoXml

XML digital signature (XML-DSig) verification for Ruby, implemented as a
Rust native extension that calls [libxmlsec1](https://www.aleksey.com/xmlsec/)
directly through hand-written [bindgen](https://github.com/rust-lang/rust-bindgen)
FFI bindings — not by shelling out to the `xmlsec1` CLI. The Ruby-facing API
is built with [Magnus](https://github.com/matsadler/magnus) and
[rb-sys](https://github.com/oxidize-rb/rb-sys).

The Rust side is deliberately split in two: `ext/hanko_xml/src/lib.rs`'s
`sys` module is thin, unsafe, one-to-one bindgen output; `verify_signature`
and its two entry points are the only place that coordinates those raw calls
into something safe, mirroring xmlsec's own `verify2.c` example (find the
`<Signature>` node, build a keys manager trusting one certificate, verify,
check status). Signing is not implemented yet.

## Requirements

- Rust toolchain (stable)
- libxmlsec1 development headers, discoverable via `pkg-config`:
  - macOS: `brew install xmlsec1` (also pulls in `libxml2`, which is linked
    explicitly — see the note below)
  - Debian/Ubuntu: `apt install libxmlsec1-dev pkg-config`

### A macOS-specific gotcha this build works around

Homebrew's `libxml2` is keg-only, and `xmlsec1-openssl.pc`'s own `Libs:`
line references it with a bare `-lxml2` (no `-L`). Left alone, that makes
the linker fall back to macOS's own ancient system libxml2
(`/usr/lib/libxml2.2.dylib`) for our own direct `xmlReadMemory`/`xmlFreeDoc`
calls, while `libxmlsec1-openssl.dylib` itself links Homebrew's newer
`libxml2.dylib` for its internal calls (`xmlSecFindNode`, ID-attribute
lookups, etc.) — two different libxml2 ABIs operating on the same
`xmlDocPtr` in one process. `build.rs` works around this by linking libxml2
by its exact absolute path rather than `-lxml2` + `-L` (rustc always emits
`-l` flags before `-L` search paths, so a plain search-based link can't be
fixed by adding `-L` — verified empirically with a linker-trace wrapper).
If you ever see `hanko_xml` crash or misbehave specifically on `#id`/ID
lookups or other structural reads on a parsed doc, this class of bug —
two different libxml2s loaded into the same process — is the first thing to
check (`otool -L` on `hanko_xml.bundle` and on `libxmlsec1-openssl.dylib`
should show the exact same libxml2 path).

## Installation

Not yet released to RubyGems.org. To use from a Gemfile pointed at this
repo:

```ruby
gem "hanko_xml", git: "https://github.com/danimaribeiro/hanko_xml"
```

## Usage

```ruby
require "hanko_xml"

HankoXml.validate(xml, certificate) # => true / false, or raises HankoXml::Error
```

Returns `true` only when libxmlsec1 confirms the `<Signature>` in `xml` is
cryptographically valid and chains to `certificate`; `false` for a
well-formed but invalid/untrusted signature. Raises `HankoXml::Error` when
verification can't run at all (unparseable XML, no `<Signature>` element,
unreadable certificate).

`xml` accepts:
- a `Nokogiri::XML::Document` — passed to Rust by pointer
  (`#pointer_id`), not re-serialized/re-parsed, so a document you just
  built in memory (e.g. about to sign) is handled as-is
- a `String` of XML markup
- a `Pathname`, `File`, or anything responding to `#to_path` (read from disk)

`certificate` accepts:
- an `OpenSSL::X509::Certificate` (converted via `#to_pem`)
- a `String` of PEM-encoded certificate data
- a `Pathname`, `File`, or anything responding to `#to_path` (read from disk)

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then,
run `rake spec` to compile the extension and run the tests. You can also run
`bin/console` for an interactive prompt.

`spec/fixtures/` includes a real signed document (`signed.xml`) and its
signer/unrelated certificates, built by hand via Nokogiri's C14N +
`OpenSSL::PKey::RSA#sign` (see git history) and cross-checked against the
independent `xmlsec1 verify` CLI oracle — the specs exercise genuine
signature verification, not mocks.

## Contributing

Bug reports and pull requests are welcome on GitHub at
https://github.com/danimaribeiro/hanko_xml.

## License

The gem is available as open source under the terms of the
[MIT License](https://opensource.org/licenses/MIT).
