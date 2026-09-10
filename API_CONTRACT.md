# hanko_xml — API Contract

Status: **design contract, not yet implemented.** This document is the reference
we implement against. Where it disagrees with the code in `lib/` or
`ext/hanko_xml/`, this document wins and the code is behind.

Companion documents: [`README.md`](README.md) (current, pre-contract
behaviour), [`VENDORING.md`](VENDORING.md) (how the native extension is built
and why its dependencies are vendored).

---

## 1. Goals, in priority order

1. **MUST — memory safety.** The unsafe surface is small, fixed, and auditable.
   Adding a feature must not add `unsafe`. Everything that varies per use case
   (algorithm choice, reference layout, placement, trust policy) lives in Ruby.
2. **MUST — plays well with Nokogiri, without requiring it.** When Nokogiri is
   present it is first-class: we accept and return `Nokogiri::XML::Document` /
   `::Node`, never force a `to_xml` round trip, never silently reformat, never
   corrupt a document Nokogiri owns. When it is absent the gem still installs
   and still verifies — see §6.1, which draws the line at what needs a DOM.
3. **SHOULD — the Ruby way.** Keyword arguments with real defaults, predicates
   ending in `?`, bang methods that mutate, blocks for configuration, value
   objects that are frozen and comparable, exceptions for exceptional things.
4. **SHOULD — the C# `SignedXml` ergonomics** — declare the parts, get a
   signature — **without xmlsec's template ceremony**, and with the extension
   points C# gets right (pluggable algorithms, custom ID resolution, custom
   placement).

Explicit non-goal: being a thin binding to libxmlsec1. If a concept only exists
because xmlsec needs it (templates, keys managers, key data formats), it does
not appear in the public API.

---

## 2. What we take from C#, and what we fix

`System.Security.Cryptography.Xml.SignedXml` is the best of the three the author
has used (C#, Python, Ruby). What makes it good:

| C# behaviour | We keep it as |
| --- | --- |
| You describe `Reference`s, `Transform`s and `KeyInfo` clauses as objects; the library emits the `<Signature>` XML | `Signer#reference`, `Transform`, `KeyInfo` clauses — §5.2 |
| `CryptoConfig.AddAlgorithm` — register your own algorithm URI | `HankoXml::Algorithms.register` — §5.7 |
| `SafeCanonicalizationMethods` — an allowlist that verification enforces | `HankoXml::Policy` generalised to *every* algorithm slot — §5.8 |
| `GetIdElement` override — custom ID resolution | `id_attributes:` + `resolver:` — §5.9 |
| You choose where the `<Signature>` element goes | `HankoXml::Placement` — §5.5 |

What C# gets **wrong**, that we must not copy:

1. **`CheckSignature` returns a bare `bool`.** It answers "some signature in this
   document is valid" — not "the data you are about to trust is what was
   signed". This is the root of every XML Signature Wrapping (XSW) bug in the
   SAML ecosystem. Our verification returns an object whose central question is
   **`#signed?(node)`** (§5.4).
2. **`LoadXml(nodeList[0])`** — the caller picks a `<Signature>` by index and
   nothing checks that it is the one covering the data. We make the signature
   node an explicit part of the result, and support `verify_all`.
3. **Insecure defaults with opt-out.** We default-deny: SHA-1, XSLT/XPath
   transforms, external references, and HMAC are all off unless a `Policy`
   turns them on (§5.8).
4. **`ComputeSignature` mutates the document you handed it.** We give
   `sign` (returns a new document) and `sign!` (mutates, and says so).

---

## 3. Architecture: three layers, and where the safety lives

```
┌──────────────────────────────────────────────────────────────┐
│ Layer 2  HankoXml.sign / .valid? / .verify!                   │  convenience
├──────────────────────────────────────────────────────────────┤
│ Layer 1  Signer, Verifier, Verification, Reference,           │  100% Ruby
│          Transform, KeyInfo, Placement, Policy, Algorithms    │  Nokogiri
│          — template building, policy enforcement, trust       │  optional
│            chain validation, ID resolution, write-back        │  no unsafe
├──────────────────────────────────────────────────────────────┤
│ Layer 0  HankoXml::Native — 5 functions, bytes in/bytes out   │  Rust
│          parse + inspect + canonicalize + digest + sign/verify│  all unsafe
└──────────────────────────────────────────────────────────────┘
```

**The governing rule: policy in Ruby, crypto in Rust.**

Everything that varies — which algorithms, which references, where the signature
goes, which certificates are trusted, whether SHA-1 is acceptable — is plain
XML manipulation and plain OpenSSL, both of which Ruby already does well and
memory-safely. Most of it is string comparison against an allowlist, which is
why the policy layer works even with no DOM available (§6.1). The only thing Ruby cannot do is canonicalize-digest-and-sign.
That, and only that, crosses into Rust.

Consequences worth stating plainly:

- The Rust crate never grows a new `unsafe` block when we add support for a new
  algorithm, a new document shape, or a new trust mode. It grows one only if we
  need a genuinely new libxmlsec1 *operation* (e.g. XML Encryption).
- Policy violations are caught **before** any bytes reach libxmlsec1. A document
  signed with XSLT transforms is rejected by Ruby; xmlsec never sees it.
- Certificate chain validation happens in Ruby via `OpenSSL::X509::Store`
  (§5.6), because `OpenSSL::X509::Store` is a better-tested chain validator
  than xmlsec's keys manager and because it keeps the trust decision inspectable
  from Ruby.

### 3.1 The finding that forces this design: two libxml2s

Measured on this machine, 2026-08-31:

```
nokogiri libxml2: source=packaged  loaded=2.13.9  memory_management=ruby
our extension links: /opt/homebrew/opt/libxml2/lib/libxml2.16.dylib  (2.15.3)
```

The default precompiled `nokogiri` gem (`arm64-darwin`, and every other
precompiled platform) **statically links its own patched libxml2**, does not
export its symbols, and — critically — routes libxml2's allocator through
Ruby's (`memory_management: "ruby"`, i.e. `xmlMemSetup(ruby_xfree, ruby_xmalloc, …)`).
Our extension dynamically links a *different, newer* libxml2 with the default
`malloc`.

So the current `validate_doc_pointer(doc.pointer_id, …)` path:

- reads `xmlDoc`/`xmlNode` struct fields laid out by 2.13.9 using 2.15.3's
  headers — layout compatibility here is luck, not contract, and libxml2 2.14/2.15
  reworked struct internals and globals;
- calls `xmlSecAddIDs`, which **allocates ID-table entries with our `malloc`**
  and stores them in a document that Nokogiri will later `xmlFreeDoc` **with
  `ruby_xfree`**. That is a cross-allocator free: heap corruption, at an
  arbitrary later GC, far from this call.

The specs pass today. They pass the way use-after-free specs pass.

**Therefore: XML crosses the Ruby/Rust boundary as bytes, always, by default.**
"Plays well with Nokogiri" is delivered at the *API* level (we accept and return
Nokogiri documents, and we write results back into the caller's own nodes — §6.4)
rather than at the pointer level. Pointer sharing becomes an opt-in mode gated
on a runtime check (§7.4) that is false for every precompiled Nokogiri.

This costs one serialize + one parse per operation. That is the correct trade
for a signing library.

---

## 4. Naming, module layout, files

```
lib/hanko_xml.rb                     # requires everything, Layer 2 module methods
lib/hanko_xml/version.rb
lib/hanko_xml/errors.rb
lib/hanko_xml/algorithms.rb          # registry
lib/hanko_xml/policy.rb
lib/hanko_xml/key.rb                 # key + certificate coercion
lib/hanko_xml/reference.rb
lib/hanko_xml/transform.rb
lib/hanko_xml/key_info.rb
lib/hanko_xml/placement.rb
lib/hanko_xml/data_object.rb
lib/hanko_xml/template.rb            # builds the <Signature> Nokogiri tree
lib/hanko_xml/signer.rb
lib/hanko_xml/verifier.rb
lib/hanko_xml/verification.rb
lib/hanko_xml/signed_document.rb     # safe-serialization wrapper returned by #sign
lib/hanko_xml/signed_info.rb         # parsed, authenticated view of <SignedInfo>
lib/hanko_xml/dom.rb                 # the ONLY place that probes for Nokogiri (§6.1)
lib/hanko_xml/signature_info.rb      # DOM-free <SignedInfo> value object
lib/hanko_xml/xml.rb                 # HankoXml.parse / .serialize, Nokogiri helpers
lib/hanko_xml/xmldsig-core-schema.xsd # bundled, for Verifier(schema: :default)
lib/hanko_xml/profiles/nfe.rb        # optional, require-on-demand
lib/hanko_xml/nokogiri_ext.rb        # optional, require-on-demand core extension
```

Top-level module stays `HankoXml` (matches the gem name and the compiled
extension's `magnus::init`). `Xmlsec = HankoXml` is defined as an alias only if
the constant is not already taken — see Decision §13.1.

**Naming rule we enforce:** no exception or class in `HankoXml` may shadow a
core Ruby constant. Specifically **not** `HankoXml::KeyError`,
`HankoXml::ArgumentError`, `HankoXml::TypeError`, `HankoXml::IOError` — inside
`module HankoXml`, a bare `rescue KeyError` would then silently resolve to ours
instead of Ruby's. See §5.10 for the names we use instead.

---

## 5. Public API

### 5.1 Layer 2 — the 90% case

```ruby
require "hanko_xml"

# Sign. Returns a NEW HankoXml::SignedDocument (§6.8); `doc` is untouched.
signed = HankoXml.sign(doc, key: key, certificate: cert)
signed.to_xml   # signature-safe serialization; #to_s and #write_to too

# Sign in place. Returns the same object you passed, now containing <Signature>.
HankoXml.sign!(doc, key: key, certificate: cert)

# Verify — predicate. Safe to use directly in a conditional.
HankoXml.valid?(xml, certificate: cert)        # => true / false

# Verify — raising. Returns a Verification; raises on anything but success.
HankoXml.verify!(xml, certificate: cert)       # => Verification, or raises

# Is there a signature at all? (structural, no crypto)
HankoXml.signed?(xml)                          # => true / false
```

Every keyword accepted by `Signer.new` / `Verifier.new` is accepted here and
forwarded; these are constructor + single call, nothing more.

`valid?`, `verify!` and `signed?` run with or without Nokogiri. `sign` and
`sign!` need Nokogiri unless the document already carries a `<Signature>`
template (§5.2, §6.1).

**There is deliberately no `HankoXml.verify` returning a rich object.** A
`Verification` instance is always truthy, so `if HankoXml.verify(doc, ...)` would
be a security bug that reads like correct code. The rich object is reachable
only through `verify!` (which raises on failure) or `Verifier#verify` (§5.4,
where the object's role is explicit). This asymmetry is intentional.

### 5.2 `HankoXml::Signer`

```ruby
signer = HankoXml::Signer.new(
  key:                     key,                # §5.6
  certificate:             cert,               # §5.6, optional
  certificates:            [cert, intermediate], # chain for <X509Data>, optional
  signature_method:        :rsa_sha256,        # default
  canonicalization_method: :exc_c14n,          # default, applies to <SignedInfo>
  digest_method:           :sha256,            # default for every reference
  references:              [],                 # see below; default = [whole document]
  key_info:                [:x509_certificate], # default
  placement:               :append_to_root,    # default, §5.5
  id_attributes:           %w[Id ID id],       # §5.9
  namespaces:              {},                 # prefix => href, for XPath args
  signature_id:            nil,                # sets <Signature Id="...">
  policy:                  HankoXml::Policy.strict, # §5.8
  template:                :adopt,             # :adopt | :build | :require, below
)
```

Block form, for when the reference list is non-trivial:

```ruby
signer = HankoXml::Signer.new(key: key, certificate: cert) do |s|
  s.signature_method = :rsa_sha1
  s.canonicalization_method = :c14n
  s.reference "#NFe3520...", transforms: %i[enveloped_signature c14n], digest_method: :sha1
  s.key_info :x509_certificate
  s.placement = HankoXml::Placement.append_to("/nfe:NFe", namespaces: { "nfe" => NFE_NS })
end
```

The block runs against a mutable builder; `Signer.new` **freezes the instance
before returning it**. A `Signer` is therefore immutable, reusable, and safe to
share across threads (§9).

#### Methods

```ruby
signer.sign(doc_or_xml)   # => HankoXml::SignedDocument (§6.8), input untouched
signer.sign!(doc)         # => the same Nokogiri::XML::Document, now signed
signer.template(doc)      # => Nokogiri::XML::Element — the unsigned <Signature>
                          #    it would insert. For inspection and testing.
signer.to_h               # => the full effective configuration, resolved URIs
```

`#template` exists because "show me exactly what XML you are about to produce,
before any crypto happens" is the single most useful debugging affordance a
signing library can offer, and because it makes the whole template layer
testable with plain XML assertions and no keys.

#### Signing a document that already has a `<Signature>` template

Many real documents arrive with the `<Signature>` skeleton already in place —
SAML request templates, ERP-generated NFe, anything produced by a tool that
separates "build the envelope" from "sign it". Building a second template
next to the existing one would be wrong. This is the entire model of the
`xmldsig` gem, and we support it as a first-class mode:

```ruby
Signer.new(key: key, template: :adopt)   # default
Signer.new(key: key, template: :build)   # always build; raise if one exists
Signer.new(key: key, template: :require) # only fill in an existing one; raise if absent
```

Under `:adopt` (the default), `sign`/`sign!` look for `ds:Signature` elements
first:

- **none present** → build one from the `Signer` configuration (§5.2), as
  described everywhere else in this document;
- **one or more present** → adopt them. The signer's `signature_method`,
  `digest_method`, `canonicalization_method`, `references` and `placement` are
  **ignored**, because the template already states them; they are read *out* of
  the template and validated against `Policy` exactly as on verification. Only
  `key`, `certificates`, `key_info` and `id_attributes` still apply.

`:require` is also the one signing mode that runs without Nokogiri (§6.1):
nothing has to be constructed, so no DOM is needed.

A `Signer` configured with explicit `references:` that then adopts a template
raises `HankoXml::ConfigurationError` rather than silently discarding them —
"I told it what to sign and it did something else" is not a failure mode we
ship.

Signing order for multiple/nested signatures follows `xmldsig`'s rule and for
the same reason: **innermost first**, sorted by ancestor depth descending. An
outer signature covering an inner one must be computed after the inner
`<SignatureValue>` exists, or the outer digest covers an empty element.

```ruby
signer.sign!(doc)                   # signs every unsigned <Signature>, innermost first
signer.sign!(doc, force: true)      # re-signs even already-signed ones
signer.sign!(doc, signature: 0)     # only the nth, document order
```

`force:` defaults to `false`: an already-signed `<Signature>` (non-empty
`<SignatureValue>`) is left alone, so signing a partially-signed document is
idempotent for the parts already done.

#### External signers — HSM, cloud KMS, smartcards

The private key does not always exist as bytes you can hand to a library. AWS
KMS, Azure Key Vault, PKCS#11 tokens and Brazilian A3 smartcards all sign *on
the device*.

**This is not supported in v1**, and the mechanism is deliberately *not* "let
Ruby do the signing and call out for the key operation". Doing that requires a
Ruby implementation of reference resolution, transforms, canonicalization and
digesting — which is where XML-DSig vulnerabilities actually live (§13.6). The
planned route instead keeps libxmlsec1 doing all of that and gives it a
device-backed key handle through an OpenSSL provider or PKCS#11 engine; see
§7.3.

For reference, the protocol a future version would expose — an object
responding to `#sign(data, algorithm:)` and `#signature_method`, or a
`sign_with` block receiving the canonicalized `<SignedInfo>`, matching what
`xmldsig`'s `sign { |data| … }` block receives — is recorded in §7.3 as a
sketch. It is **not implemented**, and `Signer.new` raises
`HankoXml::ConfigurationError` if `key:` is anything but key material or an
`HankoXml::Key`.

### 5.3 `HankoXml::Verifier`

```ruby
verifier = HankoXml::Verifier.new(
  certificate:   cert,             # pin exactly this certificate
  # or
  certificates:  [cert_a, cert_b], # any one of these
  # or
  store:         OpenSSL::X509::Store.new, # full chain validation, §5.6
  # or
  key:           OpenSSL::PKey::RSA,       # bare public key, no certificate

  # or
  keys:          { "key-name-1" => cert_a, "key-name-2" => key_b },
                 # select by the <ds:KeyName> the document declares

  policy:        HankoXml::Policy.strict,  # default, §5.8
  id_attributes: %w[Id ID id],
  namespaces:    {},
  signature:     :first,   # :first | :only | :all | Integer index | XPath String

  verification_time:    nil,   # Time — evaluate certificate validity as of then
  schema:               nil,   # validate <Signature> against an XSD first
  referenced_documents: {},    # URI => document, for non-fragment references
)
```

Four keywords deserve their own note:

**`keys:`** — a `KeyName => key-or-certificate` map. The document's
`<ds:KeyInfo><ds:KeyName>` selects which one to verify against, and a
`<KeyName>` naming nothing in the map fails as `UntrustedCertificate` rather
than falling back to trying them all. This is `nokogiri-xmlsec`'s
`verify_with({'name' => key})` form, which is how multi-tenant SAML deployments
route to the right IdP key.

**`verification_time:`** — certificate validity (`notBefore`/`notAfter`) is
checked against this `Time` instead of `Time.now`. Without it, every archived
document becomes unverifiable the day its signing certificate expires, which is
wrong: the question is whether the certificate was valid *when the document was
signed*. Brazilian NFe (5-year retention, 1-3 year A1 certificates) and any
long-lived SAML/contract archive need this. Pass the document's own timestamp,
or a timestamp from a trusted source — never one the signed document itself
supplies unless it is inside signed material.

```ruby
HankoXml::Verifier.new(store: store, verification_time: nfe.emission_time)
```

Setting `policy: policy.with(check_certificate_validity: false)` skips the
window entirely — `nokogiri-xmlsec`'s `verify_certificates: false`.

**`schema:`** — an `OpenSSL`-independent structural check: the `<ds:Signature>`
subtree is validated against `xmldsig-core-schema.xsd` (shipped) or a caller-
supplied `Nokogiri::XML::Schema` *before* any cryptography. This is `xmldsig`'s
`validate(cert, schema)`, and it is cheap defence in depth: a structurally
malformed `<SignedInfo>` is rejected without reaching libxmlsec1's parser at
all. `schema: :default` uses the bundled XSD; `nil` (the default) skips it.
`Policy.strict` sets `schema: :default`.

**`referenced_documents:`** — a `URI => document` map for references that point
outside the document. It is the *only* way a non-fragment reference can resolve:
`allow_external_references` stays `false`, nothing is fetched, and a reference
whose URI is not a key in this map raises `ReferenceError`. This gives
`xmldsig`'s `referenced_documents:` feature without its network surface.

Trust sources are mutually exclusive: passing more than one of `certificate:`,
`certificates:`, `store:`, `key:`, `keys:` raises `ConfigurationError` at
construction. Verifying against the operating system's CA bundle is
`store: OpenSSL::X509::Store.new.tap(&:set_default_paths)` —
`nokogiri-xmlsec`'s `verify_signature` / `certs: []`, spelled out rather than
hidden behind an empty array.

`signature:` values:

| Value | Meaning |
| --- | --- |
| `:first` (default) | verify the first `<ds:Signature>` in document order |
| `:only` | as `:first`, but raise `MultipleSignatures` if the document has more than one — the safest choice for protocols that expect exactly one |
| `Integer` | the nth signature, document order, 0-based |
| `String` | an XPath selecting exactly one `<ds:Signature>` |

Methods:

```ruby
verifier.verify(xml)      # => HankoXml::Verification. ALWAYS TRUTHY — check #valid?
verifier.verify!(xml)     # => Verification, or raises (§5.10)
verifier.valid?(xml)      # => true / false. Never raises for signature-level
                          #    failures; still raises ParseError / KeyLoadError.
verifier.verify_all(xml)  # => Array<Verification>, one per <ds:Signature>
```

`#verify` is the only method that hands back a failed `Verification`, and its
documentation and YARD `@return` both carry the "always truthy" warning. Prefer
`#valid?` in conditionals and `#verify!` in flows that should abort.

### 5.4 `HankoXml::Verification` — the anti-XSW object

This is the most important type in the library. It answers "what was actually
signed", not "did something verify".

```ruby
v = verifier.verify(doc)

v.valid?             # => true / false — the single crypto verdict
v.errors             # => Array<HankoXml::Error>  (built, not raised)

# --- What was covered -----------------------------------------------------
v.signed?(node)      # => true / false. THE question you should be asking.
v.signed_nodes       # => Array<Nokogiri::XML::Node> actually covered
v.references         # => Array<Verification::Reference>
v.covers_root?       # => true when the document element is inside signed material
v.partial?           # => true when it does not (a fragment signature, §5.8)

# --- Reading signed data safely -------------------------------------------
v.at_signed(xpath, ns = {})   # => Node, or raises HankoXml::NotSignedError
v.signed(xpath, ns = {})      # => Array<Node>, all of which are covered;
                              #    raises if ANY match is not covered

# --- Authenticated metadata (read from <SignedInfo>, which is signed) -----
v.signature_method        # => :rsa_sha256
v.canonicalization_method # => :exc_c14n
v.digest_methods          # => [:sha256]
v.signed_info             # => HankoXml::SignedInfo (frozen value object)

# --- Who signed -----------------------------------------------------------
v.certificate        # => OpenSSL::X509::Certificate that trust resolved to, or nil
v.certificate_chain  # => Array<OpenSSL::X509::Certificate> as validated
v.key_info           # => HankoXml::KeyInfo::Parsed — what the document *claimed*

# --- Provenance -----------------------------------------------------------
v.signature_node     # => Nokogiri::XML::Element, the <ds:Signature> verified
v.document           # => the Nokogiri document these nodes belong to
```

`Verification::Reference` is frozen:

```ruby
ref.uri            # => "#infNFe01"
ref.node           # => Nokogiri::XML::Node the URI resolved to, or nil for URI=""
ref.digest_method  # => :sha1
ref.transforms     # => [:enveloped_signature, :c14n]
ref.enveloped?     # => true
ref.valid?         # => false — THIS reference's digest did not match
ref.errors         # => [#<HankoXml::DigestMismatch reference_uri="#infNFe01">]
```

Per-reference validity matters because "the digest of reference 2 does not
match" and "the signature over `<SignedInfo>` does not match" are completely
different bugs — the first means the data changed, the second means the key or
the canonicalization is wrong — and a single `false` cannot tell you which.
`xmldsig` gets this right with its `[:digest_value, :signature]` error symbols;
we carry the same distinction as typed errors. Per-reference status is
recovered from the captured xmlsec error log (§7.1);
when it cannot be attributed to a specific reference, `ref.errors` is empty and
the failure appears only at `v.errors`.

#### `#at_signed` — making the safe read shorter than the unsafe one

```ruby
# Unsafe, and the shortest thing to write in every other library:
assertion = doc.at_xpath("//saml:Assertion", ns)

# Safe, and now shorter still:
assertion = v.at_signed("//saml:Assertion", ns)
```

`#at_signed` needs a DOM and raises `HankoXml::NokogiriRequired` without one
(§6.1) — never `false`, and never a node it could not check. It performs the
XPath *and* the `#signed?` check, raising
`HankoXml::NotSignedError` if the node it found is not covered — so forgetting
the check is no longer possible by omission, only by deliberately using
`doc.at_xpath` instead. Ergonomics is a security control: a defence that costs
an extra line gets skipped, and one that saves a line gets adopted.

#### `#signed?` semantics — normative

`v.signed?(node)` returns `true` if and only if **all** of:

1. `v.valid?` is `true`. On an invalid verification `#signed?` is always `false`;
   it never raises. (`#signed_nodes` is likewise `[]`.)
2. `node` belongs to `v.document` — the same object identity, not an equal
   document. A node from a re-parse of the same bytes returns `false`. This is
   deliberate: "is this node, the one I am about to read values out of, covered"
   is the only question that prevents XSW.
3. `node` is the target of some `ref` in `v.references`, or a descendant of one
   (attributes and text nodes count via their owner element).
4. `node` is **not** inside a subtree removed by that reference's transforms —
   concretely, not inside the `<ds:Signature>` element that an
   `enveloped-signature` transform excised.

`URI=""` means "the whole document minus the enveloped signature", so with an
enveloped whole-document reference, `#signed?` is true for every node except
those under `<ds:Signature>`.

Metadata accessors (`signature_method`, `references`, …) are populated on both
valid and invalid verifications, because "what did it claim" is exactly what you
want when debugging a failure. Everything on a `Verification` whose `valid?` is
`false` is **unauthenticated** and the YARD docs say so on each accessor.

### 5.5 `HankoXml::Placement`

Where the `<Signature>` element goes. Frozen value object; symbols coerce.

```ruby
HankoXml::Placement.append_to_root            # :append_to_root  (default)
HankoXml::Placement.prepend_to_root           # :prepend_to_root
HankoXml::Placement.append_to(node_or_xpath, namespaces: {})
HankoXml::Placement.prepend_to(node_or_xpath, namespaces: {})
HankoXml::Placement.after(node_or_xpath, namespaces: {})
HankoXml::Placement.before(node_or_xpath, namespaces: {})
HankoXml::Placement.detached                  # build <Signature> but insert nothing;
                                              # Signer#template returns it, sign raises
HankoXml::Placement.custom { |doc, signature| ... }  # you insert it; return value ignored
```

An XPath that matches zero or more than one node raises
`HankoXml::PlacementError` before any crypto runs. The `custom` block is the
full escape hatch and is what C# effectively makes you write by hand every time
(`doc.DocumentElement.AppendChild(doc.ImportNode(sig, true))`) — here it is the
rare case, not the default.

Signature placement happens **before** digest computation, which is why it is
part of the `Signer` and not a post-processing step: for an enveloped signature,
where the element sits changes what gets canonicalized.

### 5.6 Keys and certificates — `HankoXml::Key`

Coercion is uniform, and applies to `key:`, `certificate:`, `certificates:`.

`key:` accepts:

- `OpenSSL::PKey::PKey` (RSA, EC, DSA) — used directly
- a `String` of PEM (encrypted PEM requires `key_password:`)
- a `Pathname` / `File` / anything responding to `#to_path` — read from disk
- `HankoXml::Key` — the explicit wrapper

`certificate:` / `certificates:` accept the same, plus `OpenSSL::X509::Certificate`.

Convenience constructors, all pure Ruby over `OpenSSL`:

```ruby
HankoXml::Key.from_pem(pem, password: nil)
HankoXml::Key.from_der(der)
HankoXml::Key.from_file(path, password: nil)

# PKCS#12 — the common case for Brazilian NFe A1 certificates and for
# Windows-exported keys. Returns key + leaf certificate + CA chain in one go.
bundle = HankoXml::Key.from_pkcs12("cert.pfx", password: ENV["PFX_PASSWORD"])
bundle.key           # => OpenSSL::PKey::RSA
bundle.certificate   # => OpenSSL::X509::Certificate
bundle.certificates  # => [leaf, *ca_chain]
signer = HankoXml::Signer.new(**bundle.to_h)   # key:, certificate:, certificates:
```

Everything crossing into Rust is **PEM**, always. No `key_format` parameter
exists in the public API or in the native contract: Ruby normalises with
`OpenSSL::PKey#to_pem` / `OpenSSL::X509::Certificate#to_pem`, which is
unambiguous, covers PKCS#1 and PKCS#8, and means decryption and PKCS#12
unwrapping happen in Ruby with OpenSSL rather than in Rust with xmlsec's format
enum.

Trust modes for verification, in decreasing order of strength:

| Keyword | Behaviour |
| --- | --- |
| `store:` | Extract the `<X509Certificate>` from `KeyInfo` (Ruby/Nokogiri), validate the chain with `OpenSSL::X509::Store#verify` (Ruby/OpenSSL), then hand libxmlsec1 **only the validated leaf** as the trusted key. Chain policy — CRLs, purpose, time — is OpenSSL's, and fully configurable by the caller. |
| `certificates:` | The signature must verify against one of these exact certificates. |
| `certificate:` | Pinned to exactly one. |
| `key:` | Bare public key; `KeyInfo` is ignored entirely. |

And the unsafe one, which has no keyword because a keyword is too easy to reach
for:

```ruby
# Verifies self-consistency ONLY: the signature matches the certificate the
# document itself carries. Proves the document was not modified after signing;
# proves NOTHING about who signed it. Never sufficient on its own.
HankoXml::Verifier.without_trust_verification(policy: ...)
```

Its `Verification#certificate` is populated, `#trusted?` is `false`, and
`#valid?` is `true` only for integrity. `verify!` on such a verifier still
raises unless you also passed `allow_untrusted: true` to it — two explicit
steps to get to the dangerous outcome.

#### Key material handling

`HankoXml::Key` holds PEM bytes in a Ruby `String`. Ruby strings are GC-managed
and not zeroized, and we cannot promise otherwise. What we do promise:

- the native layer copies what it needs and retains nothing after the call
  returns;
- `Key#dispose!` overwrites the Ruby-side buffer in place and marks the key
  unusable, for callers who want to bound the window;
- a `Key` never appears in `#inspect`, `#to_s`, or an exception message.
  `Signer#inspect` shows `#<HankoXml::Signer key=[FILTERED] …>`.

### 5.7 `HankoXml::Algorithms` — the registry

Every algorithm slot accepts either a **Symbol** (looked up here) or a **String
URI** (used verbatim, subject to `Policy`). This is C#'s `CryptoConfig` without
the global mutable state and machine.config.

```ruby
HankoXml::Algorithms.signature[:rsa_sha256]
# => #<Entry name=:rsa_sha256 uri="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" secure=true>

HankoXml::Algorithms.uri_for(:signature, :rsa_sha256)  # => "http://..."
HankoXml::Algorithms.name_for(:signature, "http://...") # => :rsa_sha256, or nil
HankoXml::Algorithms.secure?(:digest, :sha1)            # => false

HankoXml::Algorithms.register(
  :signature, :rsa_pss_sha256,
  "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
  secure: true
)
```

Registration is process-global and additive; re-registering a built-in name
raises unless `replace: true`. Registering does **not** grant use — a `Policy`
must also allow it (§5.8). That separation is the fix for `CryptoConfig`, where
registering an algorithm silently made it acceptable to every verifier in the
process.

#### Built-in tables

Canonicalization (`Algorithms.canonicalization`), also usable as transforms:

| Name | URI | `secure?` |
| --- | --- | --- |
| `:c14n` | `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` | ✅ |
| `:c14n_with_comments` | `…-20010315#WithComments` | ✅ |
| `:exc_c14n` | `http://www.w3.org/2001/10/xml-exc-c14n#` | ✅ |
| `:exc_c14n_with_comments` | `http://www.w3.org/2001/10/xml-exc-c14n#WithComments` | ✅ |
| `:c14n11` | `http://www.w3.org/2006/12/xml-c14n11` | ✅ |
| `:c14n11_with_comments` | `http://www.w3.org/2006/12/xml-c14n11#WithComments` | ✅ |

Digest (`Algorithms.digest`):

| Name | URI | `secure?` |
| --- | --- | --- |
| `:sha1` | `http://www.w3.org/2000/09/xmldsig#sha1` | ❌ |
| `:sha224` | `http://www.w3.org/2001/04/xmldsig-more#sha224` | ✅ |
| `:sha256` | `http://www.w3.org/2001/04/xmlenc#sha256` | ✅ |
| `:sha384` | `http://www.w3.org/2001/04/xmldsig-more#sha384` | ✅ |
| `:sha512` | `http://www.w3.org/2001/04/xmlenc#sha512` | ✅ |
| `:ripemd160` | `http://www.w3.org/2001/04/xmlenc#ripemd160` | ❌ |

(The `xmlenc` / `xmldsig-more` split for sha256/384/512 is not a typo — it is
what the specs say.)

Signature (`Algorithms.signature`):

| Name | URI | `secure?` |
| --- | --- | --- |
| `:rsa_sha1` | `http://www.w3.org/2000/09/xmldsig#rsa-sha1` | ❌ |
| `:rsa_sha224` | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha224` | ✅ |
| `:rsa_sha256` | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` | ✅ |
| `:rsa_sha384` | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha384` | ✅ |
| `:rsa_sha512` | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha512` | ✅ |
| `:ecdsa_sha256` | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256` | ✅ |
| `:ecdsa_sha384` | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384` | ✅ |
| `:ecdsa_sha512` | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512` | ✅ |
| `:dsa_sha1` | `http://www.w3.org/2000/09/xmldsig#dsa-sha1` | ❌ |
| `:hmac_sha256` | `http://www.w3.org/2001/04/xmldsig-more#hmac-sha256` | ✅ but see §5.8 |

Transform (`Algorithms.transform`) — the canonicalization table above, plus:

| Name | URI | `secure?` |
| --- | --- | --- |
| `:enveloped_signature` | `http://www.w3.org/2000/09/xmldsig#enveloped-signature` | ✅ |
| `:base64` | `http://www.w3.org/2000/09/xmldsig#base64` | ✅ |
| `:xpath` | `http://www.w3.org/TR/1999/REC-xpath-19991116` | ❌ |
| `:xpath_filter2` | `http://www.w3.org/2002/06/xmldsig-filter2` | ❌ |
| `:xslt` | `http://www.w3.org/TR/1999/REC-xslt-19991116` | ❌ |

`secure?` is a *default recommendation*, not a hard gate — `Policy.strict`
allows exactly the `secure?` set, and any other policy may allow more.

### 5.8 `HankoXml::Policy`

A frozen allowlist, enforced **in Ruby, before anything reaches libxmlsec1**,
on both signing and verification.

```ruby
HankoXml::Policy.strict        # default everywhere
HankoXml::Policy.fragment      # strict, minus require_signed_root — for protocols
                               # that sign a fragment (SAML assertions). §5.8.1
HankoXml::Policy.legacy_sha1   # strict + SHA-1 digest and RSA-SHA1 signature
HankoXml::Policy.permissive    # everything libxmlsec1 supports. Documented as unsafe.

policy = HankoXml::Policy.strict.with(
  digest_methods:    %i[sha1 sha256],
  max_references:    4,
  max_document_size: 8 * 1024 * 1024,
)
```

Full field list, with `strict` defaults:

```ruby
HankoXml::Policy.new(
  # --- algorithm allowlists (Symbols or URI Strings) ---------------------
  signature_methods:        %i[rsa_sha256 rsa_sha384 rsa_sha512
                               ecdsa_sha256 ecdsa_sha384 ecdsa_sha512],
  digest_methods:           %i[sha256 sha384 sha512],
  canonicalization_methods: %i[c14n exc_c14n c14n11
                               c14n_with_comments exc_c14n_with_comments],
  transforms:               %i[enveloped_signature base64
                               c14n exc_c14n c14n11
                               c14n_with_comments exc_c14n_with_comments],

  # --- reference resolution ----------------------------------------------
  allow_external_references: false,  # URI="http://…", "file:…", or any non-#fragment
  allow_retrieval_method:    false,  # <ds:RetrievalMethod> in KeyInfo → network/file fetch
  allow_same_document_xpointer: false, # URI="#xpointer(…)"
  max_references:            8,
  require_references:        true,   # a <SignedInfo> with zero <Reference> is rejected

  # --- structural hardening ----------------------------------------------
  require_signed_root:       true,   # the document element must be inside signed material
  reject_duplicate_ids:      true,   # two elements with the same Id → reject
  max_document_size:         16 * 1024 * 1024,
  max_transforms_per_reference: 4,

  # --- keys ---------------------------------------------------------------
  min_rsa_key_bits:          2048,
  min_ec_key_bits:           256,
  allow_hmac:                false,  # see below
  check_certificate_validity: true,  # notBefore / notAfter against Time.now
  clock_skew:                60,     # seconds of tolerance for the above
)
```

Notes on the non-obvious ones:

- **`allow_hmac: false`.** An HMAC `SignatureMethod` combined with certificate-
  based trust is a classic confusion attack: the attacker replaces an RSA
  signature with an HMAC one keyed on public data. Enabling HMAC requires
  `allow_hmac: true` *and* a `key:` (never `certificate:`/`store:`) on the
  verifier; the combination `allow_hmac: true` + `certificate:` raises
  `PolicyError` at `Verifier.new` time.
- **`require_signed_root: true`** is the structural half of the XSW defence —
  see §5.8.1, which is where the whole decision is argued.
- **`reject_duplicate_ids: true`** is enforced by a Nokogiri scan before we
  serialize. Duplicate IDs make `URI="#x"` resolution ambiguous, and "which `x`
  did xmlsec pick" is the mechanism behind several XSW variants.
- **`allow_external_references: false`** blocks the SSRF/file-read surface of
  XML-DSig outright. Any reference whose URI is not `""` or `#fragment` is
  rejected in Ruby before xmlsec sees it, so libxmlsec1's own I/O callbacks are
  never reached with attacker-controlled URIs.

Violations raise `HankoXml::PolicyError` from `verify!`/`sign`, and appear in
`Verification#errors` with `#valid?` false from `#verify` / `#valid?`. The
message always names the offending value and the field:

```
HankoXml::PolicyError: digest method http://www.w3.org/2000/09/xmldsig#sha1 (:sha1)
is not in this policy's digest_methods. Use HankoXml::Policy.legacy_sha1 or
Policy#with(digest_methods: …) if this document genuinely requires SHA-1.
```

Error messages that name the escape hatch are how a security default stays a
default instead of getting replaced with `permissive` by the first person who
hits it.

#### 5.8.1 `require_signed_root` — why it defaults to `true`

This is the one policy field where the correct default is genuinely arguable,
so the reasoning is recorded rather than asserted.

`true` means: the document element must be inside signed material. It kills
signature-wrapping outright — an attacker cannot wrap signed content in an
unsigned envelope and have the envelope believed. It also **breaks SAML**, where
the signature legitimately covers an `<Assertion>` inside an unsigned
`<Response>`, and breaks any protocol that signs a fragment.

The tempting middle ground — default it to `false` and tell people to call
`#signed?` — is the worse option, because it makes the library safe only for
readers who read this document. The naive four-line integration
(`verify` → `valid?` → `at_xpath` → trust it) must be safe, and with `false` it
is not.

So: **`true` by default**, and the fragment case is served by three things that
together make the opt-out safe rather than merely available:

1. **A named preset, not a boolean.** `policy: HankoXml::Policy.fragment` reads
   as a deliberate protocol decision at the call site. `require_signed_root:
   false` reads as a flag someone flipped to make an error go away. Both work;
   the preset is what the docs and error messages point at.
2. **`Verification#partial?`** is `true` for every such verification, so the
   condition is inspectable, loggable, and assertable in tests.
3. **`Verification#at_signed`** makes the safe read *shorter* than the unsafe
   one (§5.4), so under a fragment policy the path of least resistance is the
   correct one.

And the error you get without the preset names the preset:

```
HankoXml::PolicyError: the signature covers <saml:Assertion> but not the document
element <samlp:Response>; this policy requires the document root to be signed.
If this protocol signs a fragment by design (SAML assertions do), use
policy: HankoXml::Policy.fragment and read signed data via Verification#at_signed.
```

### 5.9 ID attributes and reference resolution

XML-DSig resolves `URI="#foo"` against attributes *declared as type ID*. Without
a DTD or schema, no attribute has that type, which is why detached signatures
fail unless something registers them. libxmlsec1 exposes `xmlSecAddIDs`; the
`xmlsec1` CLI exposes it as `--id-attr`.

We surface it as `id_attributes:`, on both `Signer` and `Verifier`:

```ruby
id_attributes: %w[Id ID id]                      # default
id_attributes: ["ID", ["urn:oasis:names:tc:SAML:2.0:assertion", "AssertionID"]]
id_attributes: []                                # register nothing
```

A bare String is an unqualified attribute name; a `[href, name]` pair is a
namespace-qualified one. The default covers SAML's `ID`, XML-DSig's and NFe's
`Id`, and XHTML's `id` — the same broad default the current implementation
hardcodes, now visible and overridable.

For resolution that is not attribute-based at all (C#'s `GetIdElement`
override), pass a resolver:

```ruby
resolver: ->(doc, uri_fragment) { doc.at_xpath("//*[@wsu:Id=$id]", …) }
```

`Native.verify` returns `reference_element_indexes`: for each SignedInfo
`<Reference>`, the document-order element index of the node libxml2's ID table
resolved (the same table xmlsec used for `URI="#id"`), or `nil` when the URI
is non-fragment / unresolved. Empty URI reports the root. `Verification` maps
those indexes onto the caller's Nokogiri DOM for `#references[].node` and
`#signed?` — Ruby does **not** re-run ID lookup for coverage after a native
verify (issues #28 / #34).

A caller-supplied `resolver:` is a cross-check only: if it disagrees with the
native locator (or, when no native indexes are present, with Ruby
`id_attributes`), `Verification` reports `HankoXml::ResolutionMismatch` in
`#errors` and `#valid?` becomes `false`. Silently letting the two disagree is
exactly how "verified a different node than the one I read" happens. `#signed?`
is also false whenever `#valid?` is false (§5.4).

### 5.10 Errors

```
StandardError
└── HankoXml::Error                  base; rescue this to catch everything
    ├── HankoXml::ConfigurationError invalid Signer/Verifier construction
    │   ├── HankoXml::PolicyError    a Policy allowlist was violated
    │   ├── HankoXml::PlacementError placement XPath matched 0 or >1 nodes
    │   ├── HankoXml::NokogiriRequired  this capability needs a DOM (§6.1)
    │   └── HankoXml::SchemaError    <Signature> failed XSD validation (§5.3)
    ├── HankoXml::ParseError         the XML would not parse
    ├── HankoXml::KeyLoadError       key or certificate unreadable / unsupported
    ├── HankoXml::ReferenceError     a reference target does not exist, is
    │                                ambiguous, or has no ID attribute
    ├── HankoXml::SigningError       libxmlsec1 could not produce a signature
    ├── HankoXml::VerificationError  verification did not succeed  (raised by verify!)
    │   ├── HankoXml::SignatureInvalid       cryptographic mismatch
    │   ├── HankoXml::SignatureMissing       no <ds:Signature> in the document
    │   ├── HankoXml::MultipleSignatures     signature: :only and >1 present
    │   ├── HankoXml::UntrustedCertificate   chain/pinning failed
    │   ├── HankoXml::CertificateExpired     outside notBefore/notAfter, as of
    │   │                                    verification_time (§5.3)
    │   ├── HankoXml::DigestMismatch         one <Reference>'s digest is wrong;
    │   │                                    carries #reference_uri (§5.4)
    │   └── HankoXml::ResolutionMismatch     resolver vs xmlsec disagree (§5.9)
    ├── HankoXml::NotSignedError     Verification#at_signed found a node that
    │                                the signature does not cover (§5.4)
    ├── HankoXml::FrozenSignatureError  a mutator was called on a
    │                                SignedDocument (§6.7)
    └── HankoXml::NativeError        libxmlsec1 failed in an unexpected way
```

`HankoXml::KeyLoadError`, not `KeyError` — see the shadowing rule in §4.

Every error carries structured context, not just a message:

```ruby
e.xmlsec_errors  # => ["func=xmlSecOpenSSLEvpSignatureVerify:file=signatures.c:
                 #      line=444:obj=rsa-sha256:subj=EVP_VerifyFinal:error=18:
                 #      data do not match"]
e.signature_node # => Nokogiri::XML::Element, when one was located
e.reference_uri  # => "#infNFe01", on ReferenceError
```

`#xmlsec_errors` is captured by installing an `xmlSecErrorsSetCallback` handler
that appends into a thread-local buffer, drained on each native call. This is
the difference between `SigningError: failed to sign` and an actual diagnosis,
and it is the single highest-value thing the Rust layer can add beyond the
crypto itself.

**`HankoXml::Error` and subclasses never carry key material.** The error
constructor filters any value that came from a `Key`.



---

## 6. The XML layer: Nokogiri, and life without it

### 6.1 Nokogiri is an optional dependency

**Nokogiri is not required to install or use this gem.** It is declared as an
optional dependency, loaded only if present, and the library degrades to a
documented, narrower API without it — it does not fail to load, and it does not
fall back silently to something less safe.

This preserves what works in the pre-contract code today: `lib/hanko_xml.rb`
never `require`s Nokogiri, probing for it with `defined?(Nokogiri::XML::Document)`
instead, so `HankoXml.validate(xml_string, cert_pem)` already runs with Nokogiri
absent. Making it mandatory would have been an unannounced dependency
regression on existing callers.

The split falls along one line: **what needs a DOM in Ruby, and what does not.**

| Capability | Nokogiri absent | Nokogiri present |
| --- | :---: | :---: |
| Verify — verdict, `#errors`, full `Policy` enforcement | ✅ | ✅ |
| Authenticated metadata — algorithms, reference URIs, transforms, certificate | ✅ | ✅ |
| `#signed?` / `#at_signed` — node-identity coverage | ❌ | ✅ |
| XSD schema validation of `<Signature>` (§5.3) | ❌ | ✅ |
| Sign into a `<Signature>` template already in the document (`template: :require`) | ✅ | ✅ |
| Build a template — choose references, transforms, placement | ❌ | ✅ |
| `HankoXml.parse` / `.serialize`, `SignedDocument`, `nokogiri_ext` | ❌ | ✅ |

Verification survives DOM-free because the native layer must parse the document
anyway: `Native.inspect` (§7) returns the `<SignedInfo>` metadata as plain Ruby
`String`s and `Symbol`s, and `Policy` is very largely a set of string
allowlists. No DOM is needed to decide that
`http://www.w3.org/TR/1999/REC-xslt-19991116` is not an acceptable transform.

Signing survives DOM-free in `template: :require` mode only (§5.2), where the
caller's document already carries the `<Signature>` skeleton and the native
layer only fills in `DigestValue`, `SignatureValue` and `X509Certificate`.
*Building* a template needs a DOM: doing it by string concatenation would put
attacker-influenced values into markup we assemble by hand, and that is an
injection bug waiting for its first unusual reference URI.

#### How it degrades

```ruby
HankoXml.nokogiri?          # => false
HankoXml.capabilities       # => {verify: true, sign: :template_only,
                            #     coverage_checks: false, schema: false, …}
```

Calling a capability that needs the DOM raises `HankoXml::NokogiriRequired`
(a `ConfigurationError`) naming the capability and the fix, never a
`NoMethodError` on a missing constant:

```
HankoXml::NokogiriRequired: Verification#at_signed needs a DOM to resolve
node identity, and Nokogiri is not loaded. Add `gem "nokogiri"` to your
Gemfile, or verify without coverage checks using #valid? and treat the whole
document as untrusted beyond the verdict.
```

The rule for what may degrade: **a missing Nokogiri may remove a capability, it
may never weaken one.** No check that runs with Nokogiri present is skipped in
its absence — `Policy` is enforced identically on both paths. The capabilities
that disappear are the ones that cannot be expressed at all without a DOM, and
each of them raises rather than quietly returning a less careful answer. In
particular `#signed?` never degrades to `true`.

#### Declaring it

```ruby
# hanko_xml.gemspec — NOT a runtime dependency
spec.metadata["optional_dependencies"] = "nokogiri"
spec.add_development_dependency "nokogiri", "~> 1.18"
```

`lib/hanko_xml/dom.rb` is the single place that probes for Nokogiri and holds
every `defined?(Nokogiri…)` check. Nothing else in the library references the
constant directly, so the DOM-free path is one seam rather than a condition
scattered through twelve files, and "does this work without Nokogiri" is
answerable by reading one file.

### 6.2 Accepted inputs

Everywhere a document is taken (`sign`, `sign!`, `verify`, `valid?`, `signed?`):

- `Nokogiri::XML::Document` — used as-is
- `Nokogiri::XML::Node` / `::Element` — its `#document` is used; for signing,
  the node becomes the default reference target
- `String` of XML markup — parsed with `HankoXml.parse` (§6.3)
- `Pathname` / `File` / anything responding to `#to_path` — read binary, parsed
- anything responding to `#read` (`IO`, `StringIO`) — read fully, parsed
  (this was in the POC, dropped in the rewrite, and comes back here)

Anything else raises `::ArgumentError` — core Ruby's, deliberately, because it
is a programmer error and not an XML-signature condition.

### 6.3 Parsing and serialization helpers

```ruby
HankoXml.parse(source)      # => Nokogiri::XML::Document
HankoXml.serialize(doc)     # => String
```

These exist because both operations have a signature-breaking default in
Nokogiri, and everyone learns that the hard way.

`HankoXml.parse` is `Nokogiri::XML(source) { |c| c.strict.nonet }`:

- **`strict`** (no `RECOVER`): a malformed document must raise, not be silently
  repaired into a different document than the one that was signed.
- **`nonet`**: no network fetches for DTDs or entities (Nokogiri's default, made
  explicit and non-negotiable here).
- **never `noblanks`**: `NOBLANKS` strips whitespace text nodes, which changes
  canonical form and breaks every signature over the document. `HankoXml.parse`
  raises `ArgumentError` if handed a `ParseOptions` with `NOBLANKS` set.
- **never `noent`**: entity substitution is left off, so entity-expansion
  attacks and signature-over-expanded-entities confusion are both avoided.
- **never `huge`**: libxml2's built-in limits stay on.

`HankoXml.serialize` is
`doc.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)`:

- Nokogiri's default is `DEFAULT_XML == FORMAT | AS_XML` (`33`). `FORMAT`
  reindents the tree. **Serializing a signed document with `FORMAT` invalidates
  the signature.** `AS_XML` alone (`32`) is byte-faithful.
- `#to_s` and `#to_xml` on a signed document are therefore *not* safe, and this
  is called out in the README, in the YARD docs of `sign`/`sign!`, and in
  `Verification#inspect`.

`Signer#sign` returns a document; getting bytes out of it is
`HankoXml.serialize(signed)`, and that is the only serialization we support for
signed documents.

### 6.4 The write-back guarantee (how `sign!` stays safe)

`sign!` must mutate the caller's Nokogiri document, and §3.1 forbids handing that
document's pointer to our libxml2. The resolution:

1. **Ruby** builds the `<ds:Signature>` template as ordinary Nokogiri nodes and
   inserts them into the caller's document per `Placement`. The caller's
   document is now structurally final — every element that will exist, exists,
   with `<DigestValue>`, `<SignatureValue>` and `<X509Certificate>` empty.
2. **Ruby** serializes that document (`AS_XML`) to bytes.
3. **Rust** parses those bytes into a document *it* owns, registers ID
   attributes, signs, serializes, and returns the signed bytes. It touches
   nothing Ruby owns.
4. **Ruby** parses the returned bytes and copies back exactly three kinds of
   text content into the caller's own nodes:
   - each `ds:Reference/ds:DigestValue`
   - `ds:SignatureValue`
   - `ds:KeyInfo//ds:X509Certificate` (and other `KeyInfo` leaves)

   matched by position within the `<Signature>` subtree, which is unambiguous
   because Ruby built that subtree in step 1.

So the only mutation applied to the caller's document is: the `<Signature>`
element Nokogiri itself created, plus text content in leaves Nokogiri itself
created. No node is ever allocated, freed, moved, or reparented by foreign
code. There is no cross-allocator anything.

`sign` is `sign!` on `doc.dup` (a deep Nokogiri-side copy), returning the copy.

**The correctness precondition**, which we assert in the test suite: the
document Rust signs (step 3) must be canonically identical to the caller's
document (step 4). It is, because step 2 produced it from step 1 with a
byte-faithful serializer and step 3's re-parse is lossless for canonicalization
purposes.

The one documented exception is a **parse-option mismatch on DTD default
attributes**. libxml2 only materialises `<!ATTLIST>` defaults into the tree when
the document was parsed with `DTDATTR` or `DTDVALID` (verified: neither is set
by `Nokogiri::XML` by default, nor by `HankoXml.parse`). If the caller parsed
their document *with* those options, their in-memory tree carries attributes
that step 3's re-parse — which uses `HankoXml.parse`'s options — will not, and
the signature would cover different content than the caller's tree. `sign!`
therefore raises `HankoXml::ConfigurationError` when the document has an
internal subset containing `ATTLIST` declarations *and* was parsed with
`DTDATTR`/`DTDVALID`, rather than producing a signature that verifies for us and
for nobody else. Documents whose DTD declares no attribute defaults, and
documents parsed with our own options, are unaffected.

### 6.5 Side effects of verification

Verification does **not** mutate the caller's document. It serializes to bytes;
ID registration happens on Rust's private copy. (Contrast with the current
implementation, where `xmlSecAddIDs` mutates the caller's document's ID table.)

`Verification#signed_nodes` and `#signed?` map each Reference onto the
*caller's* document using the element indexes `Native.verify` returned from
libxml2's ID table (§5.9) — the same table xmlsec used for crypto — so coverage
cannot disagree with what was digested.

### 6.6 Optional core extension

Off by default. The Ruby way is not to monkeypatch someone else's classes
without being asked.

```ruby
require "hanko_xml/nokogiri_ext"

doc.sign(key: key, certificate: cert)     # => new Nokogiri::XML::Document
doc.sign!(key: key, certificate: cert)    # => doc
doc.signature_valid?(certificate: cert)   # => true / false
doc.signatures                            # => NodeSet of <ds:Signature>
doc.signed?                               # => structural, no crypto
```

Namespaced deliberately as `signature_valid?` rather than `valid?` — Nokogiri
already has `Document#validate`, and a bare `valid?` on a document means schema
validity to most readers.

### 6.7 `HankoXml::SignedDocument` — a document you cannot mis-serialize

`Signer#sign` and `HankoXml.sign` do **not** return a bare
`Nokogiri::XML::Document`. A bare document's `#to_xml` defaults to
`FORMAT | AS_XML`, which reindents the tree and invalidates the signature that
was just computed — a footgun that fires silently, produces valid-looking XML,
and is discovered by the counterparty. Handing the caller an object whose
obvious method breaks the thing we just built is not acceptable ergonomics.

```ruby
signed = HankoXml.sign(doc, key: key, certificate: cert)
# => #<HankoXml::SignedDocument signatures=1 valid=true>

signed.to_xml                       # => String, always AS_XML. Safe.
signed.to_s                         # => same
signed.to_xml(declaration: false)   # => same, minus <?xml …?>  (xmldsig's `instruct`)
signed.write_to(io)                 # => streams the safe serialization
signed.bytes                        # => the String, binary encoding

signed.document                     # => the underlying Nokogiri::XML::Document,
                                    #    for callers who want it. Escape hatch,
                                    #    documented as "you own the consequences".
signed.signatures                   # => NodeSet of <ds:Signature>
signed.valid?(certificate: cert)    # => self-check round trip
```

`SignedDocument` delegates read-only Nokogiri methods (`#at_xpath`, `#xpath`,
`#root`, `#encoding`, `#errors`, …) to the wrapped document, so it is a drop-in
for reading. It deliberately does **not** delegate mutators — `#add_child`,
`#remove`, `#content=` and friends raise `HankoXml::FrozenSignatureError` with
a message pointing at `#document` for callers who genuinely mean it. Any
mutation invalidates the signature; failing loudly at the mutation beats failing
mysteriously at the counterparty.

`sign!` still returns the caller's own `Nokogiri::XML::Document`, unwrapped,
because the caller already holds that object and wrapping it would be a lie
about what they have. The `sign` / `sign!` asymmetry is therefore: `sign` is
safe by construction, `sign!` is in-place and expects you to know that
`HankoXml.serialize` (§6.3) is how you write it out.

### 6.8 Namespace helpers

```ruby
HankoXml::NS = {
  "ds"  => "http://www.w3.org/2000/09/xmldsig#",
  "ds11"=> "http://www.w3.org/2009/xmldsig11#",
  "ec"  => "http://www.w3.org/2001/10/xml-exc-c14n#",
}.freeze
```

Every XPath the library runs internally is `ds:`-qualified against this map —
never `//Signature`, never `local-name()=`. A document that puts a decoy
`<Signature>` in another namespace must not confuse us.

Caller-supplied XPaths (`placement:`, `signature:`, `reference(xpath:)`) get the
caller's `namespaces:` map merged over `HankoXml::NS`.

---

## 7. Layer 0 — the native contract

This is the entire Ruby↔Rust surface. It is `HankoXml::Native`, documented as
**private API**: no semantic versioning guarantees, not for direct use.

```ruby
HankoXml::Native.check_version
# => true when the linked libxmlsec1 matches what bindgen ran against

HankoXml::Native.versions
# => { xmlsec: "1.3.4", libxml2: "2.15.3", crypto: "openssl-3.5.0" }
#    Used by HankoXml.zero_copy_available? (§7.4) and by bug reports.

HankoXml::Native.sign(xml, key_pem, cert_pems, id_attributes, signature_index)
#   xml             : String (binary) — the complete document, template included
#   key_pem         : String (binary) — PEM private key, already decrypted
#   cert_pems       : Array<String>   — PEM certs to attach to the key for KeyInfo
#   id_attributes   : Array<String | [href, name]>
#   signature_index : Integer — which <ds:Signature> in document order to fill
# => String (binary) — the signed document
# raises HankoXml::SigningError / NativeError, with #xmlsec_errors populated

HankoXml::Native.inspect(xml, signature_index)
#   Parses, locates the nth <ds:Signature>, and returns its <SignedInfo> as
#   plain Ruby data. NO cryptography, no transform execution, no key material:
#   this is a libxml2 parse and some attribute reads, safe to run on untrusted
#   input, which is what lets Policy be enforced before any crypto happens.
# => { signature_method:  "http://…#rsa-sha256",
#      canonicalization_method: "http://…#exc-c14n",
#      signature_count:   2,
#      key_names:         ["idp-1"],
#      certificates:      ["-----BEGIN CERTIFICATE-----…"],   # from KeyInfo, untrusted
#      references: [ { uri: "#infNFe01",
#                      digest_method: "http://…#sha256",
#                      transforms: ["http://…#enveloped-signature", "http://…#exc-c14n"],
#                      id: nil, type: nil } ] }

HankoXml::Native.verify(xml, trusted_pems, untrusted_pems, id_attributes, signature_index)
#   trusted_pems    : Array<String> — certs/keys that establish trust
#   untrusted_pems  : Array<String> — intermediates, for chain building
# => { status: :succeeded | :invalid | :unknown,
#      errors: Array<String>,
#      reference_element_indexes: Array<Integer|nil> }  # §5.9
# raises only for conditions that are not a verification verdict
#   (unparseable input, index out of range, unreadable key material)
```

That is five functions. Everything else in this document is Ruby.

### 7.1 Design notes for the native layer

- **`inspect` is the single source of signature metadata**, used on both the
  Nokogiri and the DOM-free path. Ruby could read `<SignedInfo>` with Nokogiri
  when it is available and skip this call, but then two implementations would
  extract the same metadata and could disagree — and "two resolvers disagree"
  is already a hazard class this document has to guard against elsewhere
  (§5.9). One implementation, one answer, at the cost of one extra parse.
- **`inspect` runs before `Policy`, `verify` runs after.** It performs no
  cryptography and executes no transforms, so running it on untrusted input is
  no more dangerous than parsing that input — which any caller does anyway.
  The ordering that matters is preserved: nothing an attacker chose reaches
  libxmlsec1's *crypto* until the allowlists have passed.
- **`signature_index`, not a node pointer.** Ruby locates the signature it means
  with a namespace-qualified XPath and passes its position in document order.
  Rust walks `ds:Signature` elements and takes the nth. This removes
  `xmlSecFindNode` ambiguity ("the first Signature anywhere") and makes
  multi-signature documents a Ruby-side loop rather than a native feature.
- **Everything is PEM.** No format enum crosses the boundary (§5.6).
- **Errors are values.** `verify` returns a status rather than raising for
  `:invalid`, because an invalid signature is an expected outcome and Ruby
  decides whether it becomes an exception.
- **The xmlsec error log is captured**, not printed to stderr. An
  `xmlSecErrorsSetCallback` handler writes into a thread-local `Vec<String>`,
  cleared at the start of each native call and drained into the return value or
  the raised error. This replaces libxmlsec1's default behaviour of writing to
  stderr, which is unacceptable in a library.
- **No GVL release in v1.** These calls only touch Rust-owned memory, so
  releasing the GVL would be sound *if* the input `RString` bytes were copied
  into a Rust `Vec<u8>` first (a `RString` slice is not valid across a GVL
  release: GC compaction can move it). That copy plus
  `rb_thread_call_without_gvl` is a Phase 4 optimisation for large documents,
  not v1 scope.

### 7.2 Rust module layout

Keeping the rewrite's split, with the POC's readability lessons applied:

```
ext/hanko_xml/src/
  sys.rs      bindgen output include, plus thin aliases for the enum constants
              whose generated names are unreadable
              (sys::KEY_FORMAT_PEM = sys::xmlSecKeyDataFormat_xmlSecKeyDataFormatPem)
  errors.rs   the xmlSecErrorsSetCallback handler + thread-local buffer
  dsig.rs     RAII wrappers (OwnedXmlDoc, Key, KeysMngr, DsigCtx) and the two
              operations (sign_document, verify_document)
  lib.rs      magnus glue: 5 functions, argument coercion, error construction
```

Simplifications adopted from the POC:

- **Drop `XmlDoc<'a>` and its `PhantomData` entirely.** With bytes-only I/O
  there is no borrowed document any more — every document is an `OwnedXmlDoc`.
  The `Owned`/`Borrowed` distinction that motivated both the POC's enum and the
  rewrite's lifetime parameter simply stops existing. This is the single
  largest complexity reduction available, and it falls out of §3.1 for free.
- **Keep `XmlSecKey` with `into_raw()`** (POC) for the signing path: signing
  needs a key attached to the context, and the `Option`-nulling ownership
  transfer is the clearest way to express "the context owns it now".
- **Keep `std::sync::Once`, `xmlSecAddIDs`, `Result<_, &'static str>`, the
  custom exception class, and the `// SAFETY:` comments** (rewrite) — all
  strictly better, per the comparison doc.
- **Keep the `build.rs` Homebrew/libxml2-absolute-path work** (rewrite). §3.1
  makes the *cross-library* hazard go away, but our own extension still needs to
  link one consistent libxml2, and that is what `build.rs` guarantees.
- **`DsigCtx<'mngr>` keeps its lifetime parameter.** It costs one type parameter
  and buys compile-time drop ordering; unlike `XmlDoc<'a>` it is not
  load-bearing complexity that can be deleted.

Target: the `unsafe` blocks in `dsig.rs` are the only ones in the crate, they
are counted in a test, and adding a Ruby-level feature must not increase that
count. Suggested guard: a spec that greps the crate and asserts the number of
`unsafe` blocks against a committed number, so growth is a deliberate, reviewed
diff rather than a drift.

### 7.3 External signers and key devices

**There is one backend: libxmlsec1.** No `backend:` keyword exists, and there
is no pure-Ruby implementation of signing or verification. This is a deliberate
reversal of an earlier draft, argued in §13.6.

The problem this section exists to solve: sometimes the private key cannot be
handed to a library as bytes. Brazilian **A3 certificates** live on smartcards
and USB tokens; AWS KMS, Azure Key Vault and HSMs sign on the device. Our
`Native.sign` takes `key_pem`, which those cannot produce.

The answer is **not** to reimplement signing in Ruby so the key operation can be
delegated to a block. It is to give libxmlsec1 a key it can use without holding
the key material:

```
xmlSecOpenSSLAppKeyLoadEx()      # present in the linked xmlsec (1.3.12)
        ↑
OpenSSL 3 provider / PKCS#11 engine
        ↑
smartcard · HSM · cloud KMS
```

The key becomes an `EVP_PKEY` handle whose private operation happens on the
device. **libxmlsec1 still performs every part of the orchestration** —
reference resolution, transforms, canonicalization, digests — exactly as it does
for a key in memory. Nothing about the security-critical path changes; only
where the final signature operation executes.

Sketched, not specified: this would surface as

```ruby
key = HankoXml::Key.from_engine("pkcs11", uri: "pkcs11:object=my-a3;type=private",
                                pin: ENV["PKCS11_PIN"])
HankoXml::Signer.new(key: key, certificate: cert).sign(doc)
```

and would add one native entry point (an engine/provider-aware variant of the
key load) rather than a second implementation of XML-DSig.

It is **not in v1**, and it is not fully designed. A3 support via PKCS#11 is
well-trodden and should work; cloud-KMS OpenSSL 3 providers exist but are
third-party and vary in quality, so this needs proving against a real device
before it is promised. Until then, `key:` takes key material, and the
`sign_with` block protocol sketched in §5.2 is documented as **unimplemented**.

#### Testing without a second implementation

The earlier draft justified a pure-Ruby backend partly as a differential test —
two implementations cross-checking each other. That was backwards: shipping a
second implementation in order to test the first means shipping, maintaining and
security-patching it forever.

The independent oracle already exists and costs nothing: the **`xmlsec1` CLI**,
a separate binary that this repository's fixtures were already cross-checked
against (see `spec/fixtures` and the README). Every fixture we sign must verify
under `xmlsec1 verify`, and every fixture it signs must verify under ours. Same
cross-checking property, zero maintained surface.

### 7.4 Zero-copy: the opt-in escape hatch

For deployments that build Nokogiri against the system libxml2 — the only
configuration in which pointer sharing is defined behaviour:

```ruby
HankoXml.zero_copy_available?
# true only when ALL of:
#   Nokogiri::VERSION_INFO["libxml"]["source"] == "system"
#   Nokogiri::VERSION_INFO["libxml"]["loaded"] == Native.versions[:libxml2]
# i.e. one shared libxml2, one allocator, one struct layout.

HankoXml.sign(doc, key: k, certificate: c, zero_copy: true)
```

`zero_copy: true` raises `HankoXml::ConfigurationError` when
`zero_copy_available?` is false, naming both versions in the message. It is
never a default and never inferred. On the machine this document was written on
it is false (`source=packaged`, 2.13.9 vs 2.15.3).

Honest assessment: this mode exists for the rare deployment that measures the
serialize/parse cost and finds it matters. It is not the interesting part of
the library and should not be built until someone has that measurement.

---

## 8. Worked examples

### 8.1 The simplest thing

```ruby
require "hanko_xml"

key  = OpenSSL::PKey::RSA.new(File.read("signer.key"))
cert = OpenSSL::X509::Certificate.new(File.read("signer.crt"))

signed = HankoXml.sign(HankoXml.parse(File.read("doc.xml")), key: key, certificate: cert)
File.binwrite("signed.xml", HankoXml.serialize(signed))

HankoXml.valid?(signed, certificate: cert)  # => true
```

Enveloped, whole document, RSA-SHA256, exclusive C14N, `<Signature>` appended to
the root. No template, no keys manager, no algorithm URIs.

### 8.2 Brazilian NFe (the driving use case)

```ruby
require "hanko_xml"

bundle = HankoXml::Key.from_pkcs12("certificado_a1.pfx", password: ENV.fetch("PFX_PASSWORD"))

# NFe requires SHA-1 and explicit configuration
signer = HankoXml::Signer.new(
  key:                     bundle.key,
  certificates:            bundle.certificates,
  signature_method:        :rsa_sha1,
  digest_method:           :sha1,
  canonicalization_method: :c14n,
  id_attributes:           %w[Id],
  key_info:                [:x509_certificate],
  placement:               HankoXml::Placement.after("//ds:Signature")
)

signed = signer.sign(nfe_doc)
```

Which is equivalent to writing this manually without the helper wrapper.

```ruby
v = HankoXml::Verifier.new(
  store:         idp_store,
  policy:        HankoXml::Policy.strict.with(require_signed_root: false),
  id_attributes: %w[ID],
  signature:     :only,
).verify(response_doc)

raise "invalid signature" unless v.valid?

assertion = response_doc.at_xpath("//saml:Assertion", "saml" => SAML_NS)

# THE line that C#'s CheckSignature does not make you write, and that every
# SAML XSW CVE is the absence of:
raise "assertion is not covered by the signature" unless v.signed?(assertion)

subject = assertion.at_xpath(".//saml:NameID", "saml" => SAML_NS).text
```

`require_signed_root: false` is necessary here (the signature covers the
Assertion, not the Response) and is precisely the case where `#signed?` becomes
mandatory rather than merely advisable. The documentation for
`require_signed_root` says so at the point of use.

### 8.4 Detached signature, custom placement

```ruby
signer = HankoXml::Signer.new(key: key, certificate: cert) do |s|
  s.reference "#payload-1", transforms: %i[exc_c14n]
  s.placement = HankoXml::Placement.after("//*[@Id='payload-1']")
end
```

### 8.5 Enveloping signature

```ruby
signer = HankoXml::Signer.new(key: key, certificate: cert) do |s|
  s.object payload_element, id: "object-1"
  s.reference "#object-1", transforms: %i[exc_c14n]
end
signer.sign(Nokogiri::XML("<Root/>"))
```

### 8.6 Multiple signatures

```ruby
HankoXml::Verifier.new(store: store).verify_all(doc).each do |v|
  puts "#{v.certificate&.subject} → #{v.valid? ? "ok" : v.errors.map(&:message).join("; ")}"
end
```

### 8.7 Debugging without keys

```ruby
puts signer.template(doc).to_xml   # exactly what will be inserted, unsigned
puts signer.to_h                   # every default resolved to a concrete URI
```

---

## 9. Threading, reentrancy, resource lifetime

- `xmlSecInit` / `xmlSecOpenSSLAppInit` / `xmlSecOpenSSLInit` run once per
  process under `std::sync::Once` (kept from the rewrite). `HankoXml.init!` is
  exposed so applications can force it at boot rather than on first use — the
  recommendation for forking servers is to call it in the parent before fork,
  and for threaded servers to call it during boot.
- `Signer`, `Verifier`, `Policy`, `Transform`, `Placement`, `Reference`,
  `KeyInfo` clauses and `Verification` are **frozen after construction** and
  safe to share across threads.
- `Nokogiri` documents are not thread-safe, and neither is any operation on
  one; a `Signer` shared between threads operating on *different* documents is
  fine.
- Native calls hold the GVL for their whole duration (§7.1), so no Ruby object
  can move or be collected mid-call.
- No native resource outlives a native call. `OwnedXmlDoc`, `KeysMngr`,
  `DsigCtx` and `XmlSecKey` are created and dropped inside one function; there
  is no Ruby-visible object wrapping a C pointer, and therefore no
  `TypedData_Wrap_Struct`, no `dmark`/`dfree`, and no GC interaction beyond
  argument strings.

That last point is worth stating as a rule: **no Ruby object in this gem ever
holds a raw pointer.** It is the reason the safety story is short enough to
audit.

---

## 10. Compatibility with today's API

`HankoXml.validate(xml, certificate)` is kept as a deprecated alias:

```ruby
def self.validate(xml, certificate)
  warn "[DEPRECATION] HankoXml.validate is deprecated; use HankoXml.valid?(xml, certificate:). " \
       "Note that valid? applies Policy.strict, which rejects SHA-1; pass " \
       "policy: HankoXml::Policy.legacy_sha1 for documents that require it.",
       uplevel: 1
  valid?(xml, certificate: certificate, policy: Policy.permissive)
end
```

It forwards with `Policy.permissive` so that behaviour does not change under
existing callers — the deprecation warning is what tells them the new default is
stricter. Removed in 1.0.

Behavioural differences the migration notes must call out:

1. `valid?` applies `Policy.strict`; the current `validate` applies nothing. The
   existing `signed_nfe.xml` spec fixture (SHA-1) will fail under `valid?`
   without `policy: Policy.legacy_sha1`. That is the point.
2. Verification no longer mutates the caller's document's ID table (§6.5).
3. `Nokogiri::XML::Document` inputs are no longer passed by pointer (§3.1).

---

## 11. Coverage vs. the existing Ruby gems

Checked against the two libraries most Ruby XML-DSig work goes through today:
[`benoist/xmldsig`](https://github.com/benoist/xmldsig) (pure Ruby, Nokogiri
C14N + OpenSSL, template-driven) and
[`instructure/nokogiri-xmlsec-instructure`](https://github.com/instructure/nokogiri-xmlsec-instructure)
(C extension over libxmlsec1, monkeypatches `Nokogiri::XML::Document`/`Node`).

Read against the source, not just the READMEs. Everything marked ➕ was **added
to this contract as a direct result of this comparison**.

### 11.1 vs. `benoist/xmldsig`

| Their API | Ours | |
| --- | --- | --- |
| `SignedDocument.new(xml, id_attr:)` | `Signer`/`Verifier` `id_attributes:` (a list, incl. ns-qualified) | ✅ superset |
| `#sign(private_key)` fills an **existing** `<Signature>` template | `template: :adopt` (default) — §5.2 | ➕ **added** |
| `#sign { \|data\| ... }` custom signing block | not in v1; device keys via OpenSSL engine — §7.3, §13.6 | ⚠️ **deferred** |
| `#validate(cert)` | `valid?` / `verify!` | ✅ |
| `#validate(cert, schema)` — XSD validation of `<Signature>` | `schema:`, on by default in `Policy.strict` — §5.3 | ➕ **added** |
| `#validate { \|sig_value, data\| }` custom verify block | not supported, deliberately — §13.6 | ❌ **declined** |
| `#signatures` sorted by ancestor depth | `verify_all`; signing order innermost-first — §5.2 | ➕ **added** |
| `#signed_nodes` | `Verification#signed_nodes`, plus `#signed?` / `#at_signed` | ✅ superset |
| `Signature#errors` → `[:digest_value, :signature]` | typed per-reference errors, `Reference#valid?` — §5.4 | ➕ **added** |
| `Signature#signed?` / `#unsigned?` | `SignedDocument#signatures`, `force:` skip logic — §5.2 | ➕ **added** |
| `force:` — re-sign already-signed | `sign!(force: true)` — §5.2 | ➕ **added** |
| `referenced_documents:` — refs into other documents | `referenced_documents:`, map-only, no fetching — §5.3 | ➕ **added** |
| `instruct` — emit `<?xml?>` or not | `SignedDocument#to_xml(declaration: false)` — §6.7 | ➕ **added** |
| `ec:InclusiveNamespaces PrefixList` | `Transform.exc_c14n(inclusive_prefixes:)` | ✅ |
| `Xmldsig::SchemaError` | `HankoXml::SchemaError < ConfigurationError` | ✅ |
| Pure Ruby, no C dependency | not offered — libxmlsec1 always — §13.6 | ❌ **declined** |

**Not adopted:** their `Canonicalizer`/`Reference`/`Signature` classes are
internal machinery we do not need to expose, since libxmlsec1 performs the
transforms. Their `sign` returning a `String` we improve on with
`SignedDocument` (§6.7).

### 11.2 vs. `instructure/nokogiri-xmlsec-instructure`

| Their API | Ours | |
| --- | --- | --- |
| `Document#sign!(cert:, key:, name:, digest_alg:, signature_alg:, canon_alg:)` | `Signer` + `sign!`; algorithms as Symbols via the registry | ✅ superset |
| `Node#sign!` — sign a subtree | Node accepted as input, becomes the reference target — §6.2 | ✅ |
| `name:` → `<ds:KeyName>` | `key_info :key_name, name:` | ✅ |
| `verify_with(key:)` / `(cert:)` / `(certs: [...])` | `key:` / `certificate:` / `certificates:` | ✅ |
| `verify_with({'key-name' => key})` — select by `<KeyName>` | `keys:` map — §5.3 | ➕ **added** |
| `verify_signature` / `certs: []` — system CA bundle | `store: OpenSSL::X509::Store.new.tap(&:set_default_paths)` — §5.3 | ✅ explicit |
| `verification_time:` — cert validity at a past instant | `verification_time:` — §5.3 | ➕ **added** |
| `verify_certificates: false` | `policy.with(check_certificate_validity: false)` | ✅ |
| `Document#get_id(id)` | `Verification#references[].node`, `resolver:` — §5.9 | ✅ |
| `Node#set_id_attribute(name)` | `id_attributes:` — §5.9 | ✅ |
| RSA/DSA/ECDSA × SHA1–512, c14n/exc-c14n ± comments | full registry — §5.7, plus `c14n11`, `ripemd160`, `hmac` | ✅ superset |
| `XMLSec::{Signing,Verification,Keystore,Encryption,Decryption}Error` | richer hierarchy, `#xmlsec_errors` — §5.10 | ✅ superset |
| **`encrypt!` / `decrypt!`** — XML Encryption | ❌ **not covered** — §11.3 | ❌ **gap** |

### 11.3 The one real gap: XML Encryption

`nokogiri-xmlsec` does `doc.encrypt!(key:)` / `doc.decrypt!(key:)` with
`block_encryption:` (`aes128/192/256-cbc`, `aes*-gcm`, `tripledes-cbc`) and
`key_transport:` (`rsa-1_5`, `rsa-oaep-mgf1p`). We do not, and v1 will not.

**Confirmed with the project owner, 2026-08-31: this project's documents are
signed and never encrypted, so the gap costs nothing here.** The engineering
argument below is why XML Encryption would be expensive; the use case is why it
is not needed. Should that change — `<EncryptedAssertion>` in SAML SSO is the
usual reason it does — reopen this decision rather than assuming it is merely
deferred work already agreed to.

XML Encryption is a separate
context type in libxmlsec1 (`xmlSecEncCtx`, declared in its own `xmlenc.h`
alongside but separate from `xmldsig.h`'s `xmlSecDSigCtx` — verified against the
installed headers), a separate RAII set, and a second
native surface roughly the size of the first — and it does not compose with
anything in this document. Signing is the problem the author actually has;
shipping a good signing library beats shipping half of two.

When it is built, it is `HankoXml::Encryptor` / `HankoXml::Decryptor` with the
same shape as `Signer`/`Verifier` — a `Policy` (which would default-deny
`rsa-1_5` and `tripledes-cbc`, both broken, and both `nokogiri-xmlsec` defaults),
a registry, and bytes across the boundary. Noted in §12 so it is a decision on
the roadmap rather than a hole.

### 11.4 What neither of them has

Recorded because these are the reasons to build this at all rather than use one
of the above:

1. **`Verification#signed?` / `#at_signed`.** Both existing gems answer "is
   there a valid signature", and neither can answer "is *this node* covered".
   `xmldsig` exposes `#signed_nodes`, which is closer than most, but it is a
   list you have to remember to intersect yourself.
2. **A `Policy` object at all.** Neither has algorithm allowlists, external-
   reference denial, duplicate-ID rejection, key-size floors, or reference
   count limits. `nokogiri-xmlsec` will happily verify an XSLT transform.
3. **`require_signed_root`.** No Ruby XML-DSig library enforces it.
4. **Memory safety across the Nokogiri boundary.** `nokogiri-xmlsec` is a C
   extension that shares Nokogiri's `xmlDocPtr` — which is *correct for it*,
   because it compiles against Nokogiri's own headers as one extension. Our
   §3.1 problem is specifically a two-libraries problem, and bytes-across-the-
   boundary is our answer to it.
5. **Captured xmlsec error logs.** `nokogiri-xmlsec` raises `RuntimeError`
   subclasses with terse messages; libxmlsec1's real diagnostics go to stderr.

---

## 12. Out of scope for v1

Listed so that "not implemented" is a decision rather than an omission:

- **XML Encryption** — the one feature `nokogiri-xmlsec` has and we do not.
  Reasoning and future shape in §11.3.
- **XAdES** (`-BES`, `-T`, `-LT`) — signed properties, timestamps, archival.
  Buildable on top of this contract as a profile plus custom `<Object>` content;
  not core.
- **WS-Security / SOAP** binding, including `wsu:Id` resolution as a default.
  The `resolver:` hook (§5.9) is the extension point that makes it possible
  out-of-tree.
- **Timestamp authority (RFC 3161)** interaction.
- **A pure-Ruby signing/verification backend.** Considered and rejected, not
  merely deferred — see §13.6. Verification in Ruby is ruled out permanently.
- **External signers (HSM, cloud KMS, A3 smartcards).** Real need, wrong
  mechanism in the earlier draft. The route is an OpenSSL provider / PKCS#11
  engine key handed to libxmlsec1 (§7.3), which needs proving against a real
  device before it is promised.
- **GVL release / large-document streaming** (§7.1, Phase 4).
- **`zero_copy: true`** beyond the availability predicate, until someone
  measures a need (§7.4).

---

## 13. Decisions

Resolved. Recorded with reasoning so they can be revisited on evidence rather
than re-argued from scratch.

### 13.1 Top-level constant name — `HankoXml`, with an opportunistic alias

Keep `HankoXml` canonical (it matches the gem name and the compiled extension's
`magnus::init`). Define `Xmlsec = HankoXml` only when `Xmlsec` is not already
defined, so loading alongside the `xmlsec` or `nokogiri-xmlsec` gems is not a
constant collision.

### 13.2 `Policy.strict` is the default — **decided: yes, reject legacy**

`valid?`, `verify!` and `Signer` all default to `Policy.strict`, which rejects
SHA-1, RSA-SHA1, XSLT/XPath transforms, external references and HMAC.

Consequence to plan for: the existing `signed_nfe.xml` fixture fails under the
default and must pass `policy: HankoXml::Policy.legacy_sha1`, and so must every
real NFe. That is the intended outcome — SHA-1 in NFe is mandated by the
*Manual de Orientação do Contribuinte*, not chosen, and code that opts into it
should say so at the call site. explicitly passing the right algorithms carries the opt-in once,
in a file with a comment explaining why, so application code never spells it out.

`HankoXml.validate` keeps `Policy.permissive` while deprecated (§10), so nothing
existing breaks silently; the deprecation warning is what announces the change.

### 13.3 `require_signed_root` defaults to `true` — **decided**

Argued in full at §5.8.1. Summary of the reasoning:

- The naive four-line integration must be safe. With `false`, it is not — the
  library would be safe only for people who read this document.
- The fragment case (SAML) is real and must be served, but as a **named preset**
  (`Policy.fragment`) rather than a boolean someone flips to clear an error.
- Opting out is made safe rather than merely possible, by `Verification#partial?`
  (inspectable/assertable) and `Verification#at_signed` (makes the correct read
  shorter to write than the incorrect one).
- The error message names the preset, so hitting it teaches instead of
  prompting a switch to `permissive`.

The failure mode we are choosing: SAML users hit one error, once, and are
pointed at the right construct. The failure mode we are avoiding: everyone else
silently accepts wrapped documents. That trade is clearly correct.

### 13.4 `sign` returns `HankoXml::SignedDocument` — **decided**

Specified at §6.7. A bare `Nokogiri::XML::Document`'s `#to_xml` reindents and
invalidates the signature, silently, producing XML that looks fine and fails at
the counterparty. `SignedDocument#to_xml` is always the safe serialization,
mutators raise instead of corrupting, and `#document` remains as an explicit
escape hatch. `sign!` still returns the caller's own document unwrapped, because
they already hold it.

### 13.5 Nokogiri is optional, not required — **confirmed by the project owner**

Specified at §6.1. The draft of this contract made Nokogiri mandatory by
building Layer 1 on it throughout, which would have been an unannounced
dependency regression: the pre-contract `lib/hanko_xml.rb` never requires
Nokogiri, and `HankoXml.validate(xml_string, cert_pem)` runs today with it
absent.

Verification and template-fill signing stay DOM-free; coverage checks
(`#signed?` / `#at_signed`), schema validation, template *building*, the
`SignedDocument` wrapper need Nokogiri and raise
`NokogiriRequired` without it. The invariant that makes this safe rather than
merely convenient: **a missing Nokogiri may remove a capability, never weaken
one.** `Policy` is enforced identically on both paths, and `#signed?` never
degrades to `true`.

Rejected alternative: build templates in Rust to drop Nokogiri entirely, as the
POC and `nokogiri-xmlsec` do. It moves the most variable logic in the library
back into `unsafe`, against §1's first requirement.

The cost accepted: one new native function (`Native.inspect`, §7), one extra
parse on the Nokogiri path, and a capability matrix that has to stay true.

### 13.6 No pure-Ruby backend — **reversed from the earlier draft**

An earlier draft of this contract planned a `backend: :ruby` (Nokogiri C14N +
OpenSSL) as Phase 5, to unlock external signers and to serve as a differential
test. The project owner pushed back: libxmlsec1 is well maintained, and
reimplementing in Ruby means owning the security fixes. That is correct, and
the backend is removed — **not deferred**.

Being precise about what it would and would not have reimplemented, because the
distinction is what decides the question. It would **not** have reimplemented
the cryptography or the canonicalization: Nokogiri's `#canonicalize` is
libxml2's `xmlC14NDocDumpMemory`, which is the same code libxmlsec1 delegates
C14N to, and the digests and signatures would come from the same OpenSSL that
xmlsec's OpenSSL backend calls. What it *would* have written in Ruby is the
**orchestration** — resolve each reference URI, apply transforms in order,
canonicalize, digest, compare, then assemble and canonicalize `<SignedInfo>`.

**And that orchestration is exactly where XML-DSig vulnerabilities live.** The
signature-wrapping CVEs are not in OpenSSL and not in libxml2's C14N; they are
in which node `#foo` resolves to, whether transforms were applied in order,
whether what was digested is what gets read, duplicate IDs, `RetrievalMethod`.
So the ~200 lines that looked cheap are precisely the expensive ones.

Two of the three original justifications did not survive review:

- *"Environments without libxmlsec1."* Simply wrong: this gem is a compiled
  extension against libxmlsec1. If you cannot install it, you cannot install
  the gem.
- *"Differential testing."* Backwards. It does not require **shipping** a
  second implementation — the `xmlsec1` CLI is already an independent oracle,
  and one we do not have to maintain or security-patch (§7.3).
- *"External signers."* Real, and the only survivor — but it has a better
  answer that keeps libxmlsec1 in charge of the orchestration: a device-backed
  key handle via an OpenSSL provider or PKCS#11 engine (§7.3).

One further asymmetry worth recording, in case this is ever revisited: under
`:xmlsec`, our Ruby-side reference resolution is only a **cross-check** — if it
is wrong we raise `ResolutionMismatch` (§5.9). Under a Ruby verification
backend it would be **authoritative** — if it is wrong we accept a forged
signature. Signing is not attacker-facing (you control the document and the
config; a bug yields a signature that does not verify) but **verification is**.
So if this is ever reopened, it may be reopened for signing only. Ruby-side
verification is closed permanently.

### 13.7 XML Encryption stays out of v1 — **confirmed by the project owner**

§11.3. The only capability `nokogiri-xmlsec` has that we do not. Put to the
project owner on 2026-08-31 and confirmed: this project signs documents and
never encrypts them, so the gap is free. The supporting engineering argument —
a second native surface of comparable size, built on a separate libxmlsec1
context type, composing with nothing in this document — is why it would be
costly, but the use case is why it is not needed. Revisit if encrypted SAML
assertions ever enter scope.

## 14. Implementation phases

Each phase is independently shippable and independently testable.

**Phase 1 — foundations, no new native code.**
`Algorithms`, `Policy`, `Transform`, `Reference`, `KeyInfo`, `Placement`,
`Key`, errors, `SignatureInfo`, `HankoXml.parse` / `.serialize`, `Template`
(builds the `<Signature>` Nokogiri tree), `Signer#template`, and `Dom` — the
single Nokogiri probe (§6.1). Build `Policy` against `SignatureInfo`'s plain
strings, not against Nokogiri nodes, from the first commit: retrofitting the
DOM-free path later means rewriting the policy layer. Testable entirely with
XML assertions and no keys. This is most of the library.

**Phase 2 — native rewrite to the §7 contract.**
Replace `validate_bytes` / `validate_doc_pointer` with `Native.sign` /
`Native.verify` / `Native.inspect` / `Native.versions`, add the error-callback
capture, delete `XmlDoc<'a>` and its `PhantomData`. Verify the `unsafe`-block
count drops despite the extra function — `inspect` is attribute reads over a
document the crate already knows how to parse.

**Phase 3 — `Signer` and `Verifier` end to end.**
Write-back (§6.4), `Verification` including `#signed?`, trust modes, policy
enforcement wired in, `verify_all`. The existing fixture matrix
(`signed_exc_c14n`, `signed_sha512`, `signed_enveloping`, `signed_detached`,
`signed_nfe`) becomes the round-trip suite: sign with `Signer`, verify with
`xmlsec1` CLI as the external oracle, and vice versa.

**Phase 4 — ergonomics and hardening.**
`SignedDocument` (§6.7), `nokogiri_ext`, `verification_time:`,
`keys:` KeyName selection, `schema:` validation, `referenced_documents:`,
`zero_copy_available?`, README rewrite, RBS
signatures in `sig/`, YARD.

**Cross-cutting test requirements**, to be written alongside each phase:

- Every fixture verifies identically under `HankoXml` and under the `xmlsec1`
  CLI. The CLI stays the external oracle it already is.
- An XSW corpus: signature-wrapping documents that verify `true` under a naive
  implementation and must produce `signed?(node) == false` here. Seed it from
  the documents that `benoist/xmldsig` and `nokogiri-xmlsec` both accept, since
  §11.4 claims we do better and the claim should be executable.
- A template-adoption suite: the existing `template_*.xml` fixtures signed via
  `template: :adopt`, asserting the produced signature is byte-identical to the
  matching `signed_*.xml` fixture.
- Every fixture this library signs must verify under `xmlsec1 verify`, and
  every fixture `xmlsec1` signs must verify under this library. That
  bidirectional check against a separate binary is the differential test — it
  needs no second implementation of our own (§7.3).
- A policy corpus: one document per denied algorithm and per denied transform,
  each asserting a `PolicyError` naming the offending URI.
- A round-trip property test: `verify(sign(doc)) == true` across the fixture
  matrix and across `{sign, sign!}` × `{Document, String, Pathname, IO}`.
- An `unsafe`-block count assertion over `ext/hanko_xml/src` (§7.2).
- **The whole suite run twice: once with Nokogiri loaded, once with it hidden**
  (a `$LOAD_PATH` stub that makes `require "nokogiri"` fail). Every DOM-free
  capability in §6.1's matrix must pass in both runs with identical verdicts,
  and every DOM-only one must raise `NokogiriRequired` rather than fail some
  other way. A capability matrix that is not executed is a capability matrix
  that drifts.
