# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the gem version
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) **over the
Ruby API only** — the libxmlsec1 version the extension is built against is
tracked separately, and is reported by `HankoXml::NativeVersion.build_versions`.

## [Unreleased]

### Added

- **#58:** `HankoXml::Xades::Verifier`, XAdES-B verification. After XML-DSig
  verification, it checks that the SignedProperties xmlsec digested is the one in
  the signature's single `QualifyingProperties` (so a decoy is never read), and
  that `SigningCertificate`/`SigningCertificateV2` names the certificate that
  verified. It returns `Xades::Verification#signed_properties`; failures are
  `HankoXml::XadesError`. `Policy#enforce_algorithm!` is public. Real-world
  XAdES samples (from SignXML) and the EU DSS signature-wrapping attacks are pinned in
  `spec/interop/`, and `rake interop:dss` fetches the rest of the DSS corpus.

- **#57:** `HankoXml::Xades::Signer`, XAdES-B (baseline) signing: a
  `<xades:QualifyingProperties>` object with `SigningTime`, `SigningCertificateV2`
  and optional `SignaturePolicyIdentifier`, `SignerRoleV2` and `DataObjectFormat`,
  signed through a second `<SignedInfo>` Reference. It is a thin layer over
  `Signer`; xmlsec does all the digesting and signing. The output conforms to the
  ETSI XAdES 1.3.2 schema. See API_CONTRACT.md §5.9.1.

- **#76:** `Policy#min_dsa_key_bits` (2048 in `strict`, 1024 in `interop`, 0 in
  `permissive`). DSA keys had no size check, so once a policy allowed
  `:dsa_sha1` a key of any size signed and verified.

- **#62:** `Policy.interop`, for verifying legacy signatures from other
  implementations: `Policy.fragment` plus SHA-1 with RSA or DSA, and 1024-bit
  RSA keys. External references, RetrievalMethod, HMAC and XPath/XSLT stay off.
  `spec/interop/` verifies the W3C merlin-xmldsig-twenty-three and
  phaos-xmldsig-three vectors (vendored from the pinned xmlsec1 1.3.12 tarball)
  under it, and pins every vector's outcome with its reason.

- **#61:** `Transform.exc_c14n(inclusive_prefixes:)` and
  `Transform.new(:exc_c14n, inclusive_prefixes:)` emit an
  `<ec:InclusiveNamespaces PrefixList="...">` child, as SAML 2.0 assertions
  need. `API_CONTRACT.md` already documented this, but it did not exist.
  `Transform.c14n` and `Transform.enveloped_signature` shorthands were added
  alongside. Verification of foreign InclusiveNamespaces signatures already
  worked natively, apart from the schema fix below.

- **#63:** `Policy#require_signing_key_usage` (on in `Policy.strict`, off in
  `Policy.permissive`): with `store:`, a signing certificate whose KeyUsage
  extension allows neither `digitalSignature` nor `nonRepudiation` fails
  verification with `UntrustedCertificate`. No extension means no
  restriction. `Verifier.new(store:, certificate_subject:)` additionally
  requires the signing certificate's CN (String) or whole subject
  (`OpenSSL::X509::Name`) to match.

- `HankoXml::NativeVersion.check!` runs at require time and refuses to load
  when the libxmlsec1 present at runtime is not ABI compatible with the headers
  the extension was compiled against. `build.rs` bakes xmlsec's and libxml2's
  struct layouts into the extension via bindgen, and a mismatch is invisible to
  the dynamic linker — every symbol still resolves, and a field is then read at
  the wrong offset. `HANKO_XML_SKIP_VERSION_CHECK` downgrades it to a warning.
- `HankoXml::NativeVersionMismatch`, raised by the above. It subclasses
  `NativeError`, so an existing `rescue HankoXml::Error` still catches it.
- `HankoXml::Native.abi_compatible?`, exposing xmlsec1's
  `xmlSecCheckVersionABICompatible` mode alongside the existing exact-match
  `check_version`.
- Gemspec metadata: `bug_tracker_uri`, `documentation_uri`,
  `rubygems_mfa_required`, and `xmlsec1_version_requirement` (the libxmlsec1
  range these bindings are known to work against).
- A tag-triggered release workflow using RubyGems trusted publishing, which
  builds the gem, installs it into a clean `GEM_HOME` to prove the packaged
  file list is complete, and cuts a GitHub Release. See `RELEASING.md`.
- An opt-in vendored build (`HANKO_XML_VENDOR=1`) that compiles libxml2 and
  xmlsec1 from the source pinned in `dependencies.yml`, verifies their SHA256
  before extracting, and links them statically with hidden visibility. Groundwork
  for precompiled platform gems; the default build still uses system libraries,
  so this path does not run on an ordinary `gem install`. See `VENDORING.md`.
- OpenSSL 3.5.8 (LTS) is vendored statically alongside libxml2 and xmlsec1.
  Linking the system libcrypto could not work for precompiled gems: the build
  container decides the soname the gem records, and it is never the user's --
  a gem built against the container's OpenSSL 1.1 would not load anywhere
  current. The vendored build now has no external crypto dependency at all.
- `spec/symbols_spec.rb`, asserting the extension exports no `xml*`/`xmlSec*`
  symbols. Two statically-linked libxml2 copies in one process (ours and
  Nokogiri's) would otherwise be resolved by load order on Linux, binding our
  calls to the wrong library.

### Fixed

- `Verification#certificate` was always `nil`, although API_CONTRACT.md §5.4
  documents it. It now names the certificate whose key verified: the pinned or
  matching listed certificate, or the `store:` chain leaf. `Native.verify`
  reports the index of the trusted PEM that verified as `:trusted_index`.

- **#74:** `Verifier`'s `referenced_documents:` was documented but never used,
  so no external reference could verify. It is now the only source an external
  reference is read from, and works with `allow_external_references: false`. At
  init the extension replaces xmlsec's file/HTTP/FTP readers with one that serves
  only the map of the verification in progress, so no URI reaches the filesystem
  or network whatever the policy says. An external URI missing from the map fails
  with `ReferenceError`. Keys drop any `#fragment`; values are the signed bytes
  as a `String`, or a `Nokogiri::XML::Document`. `Native.verify` takes the map as
  a sixth argument. The 10 detached and external interop vectors now verify.

- **#67:** `key_info: [:key_name]` signed an empty `<KeyName/>`: xmlsec writes
  the key's own name, and a key loaded from PEM has none. The clause now takes
  the name, as `key_info: [{ key_name: "idp-1" }]` or, in the block form,
  `s.key_info :key_name, name: "idp-1"`, and it also fills an adopted
  template's empty `<KeyName/>`. Signing an empty `<KeyName/>` raises
  `ConfigurationError`.
- **#68:** `Signer` passed namespace-qualified `id_attributes:` pairs
  (`[[href, "Id"]]`) straight to the native layer, which raised `NativeError`.
  It now sends their local names, as `Verifier` already did.
- **#69:** An Ed25519 (or other unsupported) key raised `NoMethodError` from
  inside the library. `Signer.new` now raises `ConfigurationError` naming the
  key type.
- **#70:** A key that does not fit the signature method (an EC key with the
  default `:rsa_sha256`, an RSA key with an adopted ECDSA template) failed as
  an opaque `SigningError: xmlSecDSigCtxSign failed`. It now raises
  `ConfigurationError` before signing, suggesting the method that fits.
- **#71:** A `URI="#id"` whose Id contains an apostrophe could not be signed
  or verified: xmlsec built the XPointer `id('a'b')` by string formatting.
  Bare-name references are now looked up directly in the document's ID table
  (xmlsec's `XMLSEC_DSIG_FLAGS_USE_VISA3D_HACK`), which also no longer lets
  `#a b` select two elements.
- **#72:** Signing an adopted template whose `<X509Data>` already held a
  certificate kept that stale certificate, because xmlsec fills only empty
  leaves. The key-derived `<KeyInfo>` leaves (`X509Certificate`,
  `X509SubjectName`, `X509IssuerSerial`, `X509SKI`, `KeyValue`) of an adopted
  template are now emptied before signing.
- The default `schema: :default` check rejected an `<X509SerialNumber>` over
  24 digits when Nokogiri ran on libxml2 older than 2.12, which happens on
  Linux when the extension is linked against a system libxml2 and loaded
  first. A 20-octet certificate serial has up to 49 digits, so valid
  signatures carrying `:x509_issuer_serial` failed with `SchemaError`. The
  bundled schema now checks the integer with a pattern.

- **#52:** `key_info: [:key_value]` wrote an empty `<KeyValue/>`, so the
  signature could not be verified with `key:` and failed the default schema
  check. xmlsec 1.3 disables KeyValue key data globally; the signing context
  now enables it, along with KeyName and X509Data, for writing only.
  Verification is unchanged and still pins its key (S-01). EC keys now write
  `<dsig11:ECKeyValue>`.
- **#52:** `key_info:` clauses `:x509_subject_name`, `:x509_issuer_serial` and
  `:x509_ski` silently wrote an `<X509Certificate>` instead. The template now
  emits a placeholder for each clause.
- **#52:** Signing copied only `X509Certificate` from xmlsec's output back
  into the caller's document, dropping anything else xmlsec wrote into
  `<KeyInfo>`. The whole signed `<KeyInfo>` is now mirrored.
- **#52:** `Signer#sign` with `placement: :detached` raised `TypeError`. It now
  raises `ConfigurationError`, as API_CONTRACT.md §5.5 documents; build the
  template with `Signer#template` and insert it yourself.

- **#52:** Loading an encrypted private key without `password:` made OpenSSL
  prompt `Enter PEM pass phrase:` on the controlling terminal and block the
  process (a server with a TTY would hang). `Key.from_pem`, `Key.from_der`,
  `Signer.new(key:)` and `Verifier` key parsing now raise `KeyLoadError`, with
  a hint to pass `password:`.

- **#61:** The default `schema: :default` check rejected any
  `<ec:InclusiveNamespaces>` under `<CanonicalizationMethod>`, where the
  XML-DSig schema has a strict wildcard. That is the shape most SAML IdPs
  emit, so their signatures failed with `SchemaError`. The bundled schema now
  imports the W3C exc-c14n schema, and is parsed once rather than on every
  verification.

- **S-21 / #51:** README and guide examples passed file names as Strings
  (`key: "private.pem"`), which are parsed as PEM and raise `KeyLoadError`;
  they now use `Pathname`. A String that fails to parse and has no
  `-----BEGIN` line gets a hint in the `KeyLoadError` message.
- **S-17 / #47:** `SignedDocument` now delegates read-only Nokogiri methods
  (`#at_xpath`, `#xpath`, `#root`, …) and raises `FrozenSignatureError` from
  mutators (`#add_child`, `#root=`, `#remove`, …), as `API_CONTRACT.md` §6.7
  specified. Its serializers raise `FrozenSignatureError` if the document
  changed after signing (through a returned node or `#document`).
  `#to_xml(declaration: false)` no longer raises `NameError` (it referenced a
  nonexistent `SaveOptions::NO_DECL`).
- **S-16 / #46:** Built-in `Algorithms` names and URIs can no longer be
  re-registered, even with `replace: true` (previously
  `register(:digest, :sha256, sha1_uri, replace: true)` made
  `Policy.strict` accept SHA-1). `Policy` resolves its algorithm allowlists
  to URIs at construction, and compares a document's algorithm String
  verbatim rather than looking it up as a registry name.
- **S-15 / #45:** `Key#private_key?` is false for a public-only key (it was
  true for any `PKey`). `Key.from_pem` classifies by PEM block label, and a
  PEM containing both a certificate and a key raises `KeyLoadError` instead
  of silently dropping the certificate. `Key#to_openssl` raises after
  `#dispose!`, like `#to_pem`, and `#dispose!` no longer claims to zeroize.
  `Signer.new` raises `ConfigurationError` when `key:` is not a private key
  or `certificate:` is not a certificate.
- **S-14 / #44:** `Signer.new` raises `ConfigurationError` when `key:` does
  not match `certificate:`.
- **S-13 / #43:** Native errors are classified by the step that failed
  instead of by searching the message for "parse", "key" or "certificate",
  which the xmlsec log could contain from the document itself (an unknown
  `SignatureMethod` href of `urn:parse-key:…` raised `ParseError`). The xmlsec
  log is no longer appended to `#message`; it is set as `#xmlsec_errors`,
  which was always empty on `SigningError` before. A failed native
  verification's `VerificationError#message` is now
  `"Signature verification failed (<status>)"` instead of the first xmlsec
  log line.
- **S-12 / #42:** `max_document_size` is checked before a String, file or IO
  is read or parsed (an IO is read at most one byte past the limit), and
  against the serialized document before `Native.inspect_sig`. An oversized
  String/file/IO now raises `PolicyError` from `Verifier#verify` /
  `#verify_all` as well as from `Signer`, the same way a `ParseError` does;
  an already-parsed Document still yields a failed `Verification`. The native
  layer rejects a document over libxml2's 2 GiB `int` length with
  `ParseError` instead of truncating it, and every PEM length crossing the
  FFI boundary uses a checked conversion.
- **S-05 / #36:** `Signer#sign!` enforces `Policy` on `inspect_sig` output
  before `Native.sign`, for both built and adopted templates. Adopted /
  required templates must also have Reference URIs that match
  `Signer#references` (empty `references` means whole-document `URI=""`).
  A hostile `file://`, SHA-1, or `#attacker-node` template is therefore
  rejected without a native signing call.
- **S-04 / #35:** `Verifier` enforces `Policy` on `inspect_sig` output
  before `Native.verify`, so a `file://` / `http://` Reference is rejected
  without reaching libxmlsec1. The native dsig context also limits
  `enabledReferenceUris` / `transformCtx.enabledUris` to empty and
  same-document URIs on both sign and verify.
- **S-01 / #33:** `Native.verify` pins every trusted PEM as xmlsec `signKey`
  (certificate PEMs via `xmlSecKeyDataFormatCertPem`) so a document-supplied
  `<KeyValue>`, `<DEREncodedKeyValue>`, or `<RetrievalMethod>` cannot become
  the verification key. An empty trust list returns `:invalid` instead of
  succeeding. `Verifier` now raises `ConfigurationError` when no trust source
  is given, matching the existing "exactly one" constructor contract.

- **S-03 / #28 / #34:** `Verification#signed?` / `#references[].node` no longer
  re-resolve `URI="#id"` with a Ruby XPath that can disagree with xmlsec's ID
  table (DTD-typed IDs, `xml:id`). `Native.verify` returns
  `reference_element_indexes` from `xmlGetID` after verification; Ruby maps
  those document-order indexes onto the caller's Nokogiri DOM. `resolver:` is
  now a cross-check against the native locator (`ResolutionMismatch` on
  disagreement). `#signed?` also returns false unless `#valid?` is true.
- `Verification#references` (and everything built on it — `#signed?`,
  `#signed_nodes`, `#covers_root?`, `#at_signed`, `#signed`) raised
  `FrozenError` on every call: the object froze itself in `initialize`, but
  `#references` computed and cached itself lazily on first access. Nothing in
  the test suite called it through the public, memoized path, so this went
  uncaught. `#references` is now computed during construction, before the
  object freezes.
- `Verification#resolve_fragment_reference`'s reference resolution replaced a
  hardcoded, string-interpolated XPath (`@Id='#{id}' or ...`) with
  variable-bound XPath, and made the `id_attributes:`/`resolver:` options it
  already accepted actually used, closing an XPath-injection path in the
  anti-XSW reference resolver.
- `Verifier#verify_single` passed `id_attributes:` straight through to
  `Native.verify`, which only accepts plain strings. A namespace-qualified
  `[ns, name]` entry (a Ruby-side-only refinement `Verification` understands)
  crashed with `"array element is not a String"` the moment a caller used it.
  Native calls now go through `#native_id_attributes`, which reduces each
  entry to its local name — the native ID table is namespace-unaware anyway.
- A caller-supplied `resolver:` was never checked against `id_attributes:`
  when both were configured, so `Verification#signed?` could report a node as
  covered based on the resolver's answer while `Native.verify` (which only
  ever sees `id_attributes:`) verified a *different* node with the same ID.
  `HankoXml::ResolutionMismatch` existed for exactly this per
  `API_CONTRACT.md` §5.9 but was never raised. It now is, whenever `resolver:`
  and `id_attributes:` are both non-empty and disagree on a reference's
  target.
- `Verifier` accepted `store:` and `key:` at construction but never used them
  during verification, so documented trust modes failed closed. `store:` now
  identifies the KeyInfo end-entity (not document order), validates that cert
  through `OpenSSL::X509::StoreContext` without mutating the caller's store,
  and hands libxmlsec1 only the validated leaf. `key:` / key-valued `keys:`
  entries pass a public-key PEM into `Native.verify`, which pins it as
  `signKey` so KeyInfo is ignored, matching `API_CONTRACT.md` §5.6.

### Changed

- **#75:** Verification and signing no longer resolve the references inside an
  `<Object><Manifest>` (xmlsec's `XMLSEC_DSIG_FLAGS_IGNORE_MANIFESTS`). Policy
  only inspects `<SignedInfo>`, so a Manifest's URIs, transforms and digest
  methods reached xmlsec unchecked. Only the native allowlists stood in the way,
  and a digest method the policy forbids was still used there. A `<SignedInfo>`
  reference to the Manifest still signs the Manifest element itself, as XML-DSig
  core validation specifies. The phaos Manifest interop vectors now verify.

- `SECURITY_REVIEW.md` is the follow-up tracker (GitHub issues could not be
  opened from the cloud agent). It records which findings PR #30 closed
  (S-02, S-08) and which S-01 closed (certificate-PEM KeyValue bypass and
  empty-trust). `SIGNING_TEST_COVERAGE.md` marks trust-source specs T1–T7
  and S-01 group K as passing.
- `spec.files` is now an allowlist over `git ls-files` rather than a reject
  list. The gem was shipping the entire Astro docs site, `API_CONTRACT.md`, and
  the design assets — 103 files and 734 KB, now 44 files and 169 KB.
- CI runs the matrix on both Ubuntu and macOS across Ruby 3.1–3.4, instead of
  Ruby 3.3.6 on Ubuntu alone.
- `required_ruby_version` is now `>= 3.1.0`. Ruby 3.0 is end-of-life and was
  never in the CI matrix.

## [0.1.0] - 2026-08-31

- Initial release
