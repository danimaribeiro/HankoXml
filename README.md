<p align="center">
  <img src="assets/hanko-mark.png" alt="HankoXml" width="120" height="120">
</p>

<h1 align="center">HankoXml</h1>

<p align="center">
  A high-performance, strictly secure XML Digital Signature (XML-DSig) library for Ruby.
</p>

---

HankoXml is backed by a native Rust extension that binds directly to [libxmlsec1](https://www.aleksey.com/xmlsec/) using [Magnus](https://github.com/matsadler/magnus). It is designed to be completely byte-faithful, blazingly fast, and natively immune to XML Signature Wrapping (XSW) attacks.

It works nicely with Nokogiri, signing and verifying the documents you already hold without fragile re-serialization, and it works without Nokogiri too: verification runs on plain bytes.

## Features
- **Full XML-DSig Support:** Sign and verify Enveloped, Enveloping, and Detached signatures.
- **Nokogiri Native, Nokogiri Optional:** Directly patches `Nokogiri::XML::Document` for seamless `.sign!` and `.verify!` calls when Nokogiri is loaded, and verifies Strings, files and IOs without it.
- **XSW Defense:** Provides a robust `Policy` engine and structural `signed?(node)` checks to defeat XML Signature Wrapping (XSW) attacks.
- **Rust-Backed:** Memory-safe FFI boundaries, zero shell-outs to CLI binaries, and massive performance gains over pure-Ruby cryptography.

A feature and security comparison with Python [SignXML](https://pypi.org/project/signxml/), including a plan to close the remaining gaps (XAdES first), lives in [`docs/src/content/guide/comparison-signxml.md`](docs/src/content/guide/comparison-signxml.md).

## Requirements

Most users install a precompiled platform gem and do **not** need a local build
toolchain.

- Ruby 3.1+

Precompiled gems are published for:

- `x86_64-linux`
- `aarch64-linux`
- `arm64-darwin`
- `x64-mingw-ucrt`

### Building from source (fallback)

If RubyGems falls back to the source gem for your platform, HankoXml compiles
its Rust extension against the local `libxmlsec1`, so the build toolchain has
to be present:

- Rust toolchain (stable)
- `libxmlsec1` and `libxml2` development headers, `pkg-config`, and libclang
  (bindgen generates the FFI bindings during the build):
  - **macOS:** `brew install libxmlsec1 libxml2 pkg-config`
  - **Debian/Ubuntu:** `apt install libxmlsec1-dev libxml2-dev pkg-config libclang-dev`

Supported libxmlsec1: `>= 1.2.30, < 1.4`.

*(Note for macOS: Homebrew's `libxml2` is keg-only. HankoXml's `build.rs` automatically works around this by resolving absolute library paths during compilation.)*

### Version safety

bindgen bakes xmlsec's and libxml2's struct layouts into the compiled
extension, and a later mismatch is invisible to the dynamic linker — every
symbol still resolves, and a field is then read at the wrong offset. HankoXml
checks for this when it loads and raises `HankoXml::NativeVersionMismatch`
rather than returning a wrong answer from `verify!`:

```ruby
HankoXml::NativeVersion.build_versions
# => { xmlsec: "1.3.12", libxml2: "2.15.3", crypto: "openssl" }
```

If you installed from source and later upgrade libxmlsec1 through your OS
package manager, rebuild the extension with `gem pristine hanko_xml`.

## Installation

Add this line to your application's Gemfile:

```ruby
gem "hanko_xml"
```

Nokogiri is optional, and `hanko_xml` does not depend on it or load it. Pick
the setup that fits:

- **With Nokogiri** (most projects already have it): add `gem "nokogiri"` and
  `require "nokogiri"`. Everything is available, including signing, the
  Nokogiri API below, and node-level `signed?` checks.
- **Bytes only**: leave Nokogiri out. Verification works on a String, a path
  or an IO, with the same policy, schema and structural checks. Signing and the
  DOM features raise `HankoXml::NokogiriRequired`, naming what needs Nokogiri.

| Capability | With Nokogiri | Bytes only |
|---|---|---|
| `valid?`, `verify!`, `Verifier`, `signature_present?` | yes | yes |
| `sign`, `sign!`, `Signer` | yes | raises `NokogiriRequired` |
| `Verification#signed?`, `#at_signed`, `#signed_nodes` | yes | raises; `#covers_root?` still answers |
| Custom `Nokogiri::XML::Schema`, `signature:` XPath, `resolver:`, XAdES | yes | raises `NokogiriRequired` |

`HankoXml.capabilities` reports the same thing at runtime. On Linux with
system libraries, whichever of hanko_xml and Nokogiri loads first decides which
libxml2 the other runs on, so HankoXml leaves the load order to you.

## Usage

### 1. The Nokogiri API (Recommended)

HankoXml extends Nokogiri directly, making signing and verifying incredibly ergonomic.

```ruby
require "nokogiri"
require "hanko_xml"

doc = Nokogiri::XML(File.read("document.xml"))
private_key = File.read("private.pem")
certificate = File.read("public.crt")

# Sign the document in place
doc.sign!(key: private_key, certificate: certificate)

# Safely serialize without destroying the signature bytes
File.write("signed.xml", doc.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML))

# Verify it later
signed_doc = Nokogiri::XML(File.read("signed.xml"))
if signed_doc.signature_valid?(certificate: certificate)
  puts "Signature is valid!"
end
```

### 2. The Module API

If you prefer not to use the Nokogiri monkey-patches, you can use the top-level module:

#### Verification

This works with or without Nokogiri:

```ruby
require "hanko_xml"
require "pathname"

xml = File.read("signed.xml")

# Raises HankoXml::VerificationError if the signature is invalid or tampered with
result = HankoXml.verify!(xml, certificate: Pathname("public.crt"))

puts result.valid? # => true
```

#### Signing (Immutable)
```ruby
# Returns a safe `SignedDocument` wrapper without mutating the original
# A String is PEM content, not a filename: pass files as Pathname (or File.read them).
signed_doc = HankoXml.sign(xml, key: Pathname("private.pem"), certificate: Pathname("public.crt"))

puts signed_doc.to_s
```

### Defending against XML Signature Wrapping (XSW)

A signature is only secure if it actually signed the data you are looking at. Attackers often wrap or move the `<Signature>` block to trick naive verifiers. HankoXml provides a structural `signed?` check on the verification result to prove a specific node was cryptographically covered by the digest.

```ruby
result = HankoXml.verify!(doc, certificate: cert)

# Find the critical data in your document
payload = doc.at_xpath("//Invoice")

# Ensure the attacker didn't move it outside the signed block
unless result.signed?(payload)
  raise "XSW Attack Detected: The invoice was tampered with!"
end
```

### Trust Anchors & Verification Options

You can verify signatures against multiple certificates, strict schemas, or specific validation times.

```ruby
HankoXml.verify!(
  doc,
  # Pass a single cert, an array of certs, an OpenSSL::X509::Store, or a mapping of <KeyName>s
  store: my_trusted_ca_store,
  
  # Ensure the certificate was valid at a specific time
  verification_time: Time.parse("2023-01-01"),
  
  # Pre-validate the <Signature> structure against the W3C XSD to prevent parser exploits
  schema: :default,
  
  # Enforce strict security policies (no SHA-1, no external references)
  policy: HankoXml::Policy.strict
)
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/danimaribeiro/HankoXml.

`bundle exec rake compile spec` by default builds the Rust extension against
your system's `libxmlsec1` (see "Building from source" above), which is fine
for day-to-day development. But the system library's build configuration can
differ from the pinned, vendored `libxmlsec1` that CI and the released gem
actually use — on macOS with Homebrew's `libxmlsec1`, this has been observed
to make some native URI-restriction and `KeyValue` specs fail or hang. Before
relying on a full local `bundle exec rspec` run (e.g. to validate a security
fix), rebuild against the vendored library instead:

```sh
HANKO_XML_VENDOR=1 bundle exec rake compile spec
```

See [VENDORING.md](VENDORING.md) for details on what gets vendored and why.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
