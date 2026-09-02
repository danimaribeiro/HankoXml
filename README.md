<p align="center">
  <img src="https://raw.githubusercontent.com/danimaribeiro/HankoXml/main/assets/hanko-mark.png"
       alt="HankoXml" width="120" height="120">
</p>

<h1 align="center">HankoXml</h1>

<p align="center">
  A high-performance, strictly secure XML Digital Signature (XML-DSig) library for Ruby.
</p>

---

HankoXml is backed by a native Rust extension that binds directly to [libxmlsec1](https://www.aleksey.com/xmlsec/) using [Magnus](https://github.com/matsadler/magnus). It is designed to be completely byte-faithful, blazingly fast, and natively immune to XML Signature Wrapping (XSW) attacks.

It tightly integrates with Nokogiri, allowing you to sign and verify documents directly in memory without fragile re-serialization.

## Features
- **Full XML-DSig Support:** Sign and verify Enveloped, Enveloping, and Detached signatures.
- **Nokogiri Native:** Directly patches `Nokogiri::XML::Document` for seamless `.sign!` and `.verify!` calls.
- **XSW Defense:** Provides a robust `Policy` engine and structural `signed?(node)` checks to defeat XML Signature Wrapping (XSW) attacks.
- **Rust-Backed:** Memory-safe FFI boundaries, zero shell-outs to CLI binaries, and massive performance gains over pure-Ruby cryptography.

## Requirements

- Ruby 3.0+
- Rust toolchain (stable)
- `libxmlsec1` development headers:
  - **macOS:** `brew install xmlsec1`
  - **Debian/Ubuntu:** `apt install libxmlsec1-dev pkg-config`

*(Note for macOS: Homebrew's `libxml2` is keg-only. HankoXml's `build.rs` automatically works around this by resolving absolute library paths during compilation.)*

## Installation

Add this line to your application's Gemfile:

```ruby
gem "hanko_xml", git: "https://github.com/danimaribeiro/HankoXml"
```

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
```ruby
require "hanko_xml"

xml = File.read("signed.xml")

# Raises HankoXml::VerificationError if the signature is invalid or tampered with
result = HankoXml.verify!(xml, certificate: "public.crt")

puts result.valid? # => true
```

#### Signing (Immutable)
```ruby
# Returns a safe `SignedDocument` wrapper without mutating the original
signed_doc = HankoXml.sign(xml, key: "private.pem", certificate: "public.crt")

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

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
