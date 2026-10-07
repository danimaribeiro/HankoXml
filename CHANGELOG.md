# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the gem version
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) **over the
Ruby API only** — the libxmlsec1 version the extension is built against is
tracked separately, and is reported by `HankoXml::NativeVersion.build_versions`.

## [Unreleased]

### Added

- **#102:** Verification works without Nokogiri. `Verifier` (`#verify`,
  `#verify!`, `#valid?`, `#verify_all`), `HankoXml.valid?`, `HankoXml.verify!`
  and `HankoXml.signature_present?` take a String, a path or an IO and run on
  bytes, with every check they run with Nokogiri: policy, `schema: :default`,
  `require_signed_root`, `reject_duplicate_ids`, `max_document_size` and
  signature selection by index. Bytes input is parsed strictly, rejecting what
  a strict Nokogiri parse rejects. Without a DOM, `Verification#covers_root?`
  and `#partial?` still answer, and `#signed?`, `#signed_nodes`, `#at_signed`,
  `#signed`, XPath `signature:`, `resolver:`, a custom `Nokogiri::XML::Schema`,
  `Xades::Verifier` and signing raise `NokogiriRequired`.
  `HankoXml.capabilities[:verify]` is always `true`. `spec/without_nokogiri`
  runs in a process with Nokogiri hidden, from the regular suite and through
  `rake spec:without_nokogiri`. Signing into a template on bytes is next.

- **#60:** RSA-PSS (RFC 6931 `sha*-rsa-MGF1`), SHA-3 digests and ECDSA-SHA3
  are first-class `Algorithms` entries, allowed by `Policy.xades` (strict plus
  those methods) and still denied by `Policy.strict`. libxmlsec1 1.3 implements
  the URIs; xmlsec 1.2 fails closed inside `Native.sign` / `Native.verify`.
  SHA-3 `DigestMethod` klasses are enabled on the native reference-transform
  allow-list when the linked xmlsec registered them (S-10). `Signer` treats
  `rsa_pss_*` as RSA and `ecdsa_sha3_*` as EC for the key-type check.
  ECDSA-SHA3 uses RFC 9231's `http://www.w3.org/2021/04/xmldsig-more#`
  URIs. `Xades::Signer` and `Xades::Verifier` both digest a SHA-3
  `CertDigest` (the verifier used to raise on one).

- **#59:** SignXML-produced XAdES-B interop. `XAdESSigner` 5.1.0 signatures
  (payload + SignedProperties + KeyInfo references, `SigningCertificateV2`,
  optional policy/role/`DataObjectFormat`) verify with `Xades::Verifier` under
  `Policy.strict`. The reverse — a HankoXml XAdES-B signature accepted by
  SignXML's `XAdESVerifier` with `expect_references: 2` — runs when `python3`
  can import `signxml`. See `spec/interop/xades/signxml-produced/`.

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

- **#102:** libxml2's parse errors no longer go to stderr. They land in
  `ParseError#xmlsec_errors`, like xmlsec's own log.

- **#102:** `HankoXml::Verifier.default_schema` raises `NokogiriRequired`
  without Nokogiri, instead of a `NameError`. Every Nokogiri call now goes
  through `HankoXml::Dom`, the first step toward using HankoXml without
  Nokogiri; a spec fails if any other file in `lib/` names the Nokogiri
  constant or requires Nokogiri.

- **#96:** `ParseError`, `SchemaError` and `NativeError` messages are fixed
  strings. libxml2's diagnostics, which quote the document, moved to
  `#xmlsec_errors`. A native error during verification keeps its class and
  xmlsec log instead of being re-wrapped as `NativeError`/`ParseError` with its
  message copied. Anything that matched libxml2 text in `#message` (for
  example `/depth/`) must match `#xmlsec_errors` now.
- **#96:** `HankoXml::Error` filters key material: a `Key` or `OpenSSL::PKey`
  passed as the message becomes `[FILTERED]`, and private-key PEM text is
  redacted from `#message` and `#xmlsec_errors`, as the contract promised.
- **#96:** `Policy#enforce!` / `#violations` called without `document:`
  (or `sig_node:` / `id_attributes:`) report `require_signed_root` and
  `reject_duplicate_ids` as violations instead of silently skipping them.
  `Signer` and `Verifier` always passed the document, so they are unaffected.
- **#96:** A non-root `Nokogiri::XML::Node` passed to `Signer#sign` / `#sign!`
  is the default reference target (`"#<its Id>"`) when the `Signer` has no
  `references:`. It used to sign the whole document. A node without an Id
  raises `ConfigurationError`.
- **#96:** `Verification::Reference#errors` holds a `DigestMismatch` (with
  `#reference_uri`) when xmlsec reported that reference's digest as wrong. It
  was always `[]`.
- **#96:** `HankoXml.capabilities` reports every capability as unavailable
  without Nokogiri, including `verify`; it used to claim verification worked.
  `NokogiriRequired` no longer suggests a DOM-free alternative that doesn't
  exist.
- **#96:** `Verifier` `signature: :all` raises a `ConfigurationError` that
  points at `#verify_all` (#105).
- **#96:** `Verification#signature_method` and `#canonicalization_method`
  return registry names (`:rsa_sha256`, `:exc_c14n`), as the contract always
  showed, instead of URI Strings. An algorithm the registry doesn't know comes
  back as its URI, here and in `#digest_methods` (which used to give `nil`).
- **#96:** RBS: `Verification` (`Reference`, `certificate`, `references`,
  `signed`, `covers_root?`, the metadata readers), `Signer` (`key:` required,
  `namespaces:`, `policy:`, public `template`, `reference`), `Policy`
  (`referenced_uris:`), `Verifier` (`resolver:`) and `Error` match the code.
- **#96:** `namespaces:` now reaches every caller-supplied XPath. The
  `Signer`'s map is merged under a `Placement`'s own, and `Verification#at_signed`
  / `#signed` see their `ns` argument merged over the `Verifier`'s map and
  `HankoXml::NS` (so `ds:` is always bound). Before, both options were stored
  and ignored. A `Placement` XPath with an unbound prefix raises
  `PlacementError` instead of Nokogiri's `XPath::SyntaxError`.

- **#91:** `Verification#signed_nodes` returns `[]` when the verification is
  invalid, like `#signed?`. It used to return the resolved reference nodes even
  though nothing had been proven about them.
- **#95:** A String `signature:` (XPath) on `Verifier` must select exactly one
  `<ds:Signature>`: several matches raise `MultipleSignatures` instead of the
  first being verified silently. The XPath now sees `namespaces:` merged over
  `HankoXml::NS`, so prefixed expressions such as `(//ds:Signature)[2]` work.
- **#94:** `Verification#digest_methods` returns `[]` instead of raising
  `NoMethodError` on a verification that failed before the signature was
  inspected.
- **#93:** RBS: `PolicyError` and `PlacementError` are `ConfigurationError`s, as
  in the code, and the missing error classes are declared.
- **#92:** `API_CONTRACT.md` §5.8 no longer claims that `allow_hmac: true` with
  `certificate:` raises at `Verifier.new`. The HMAC key-confusion attack is
  stopped by key pinning in xmlsec, now pinned by a spec over every public value
  the HMAC could be keyed on.

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

- **#96:** Five verification errors no longer quote the document in `#message`,
  as §5.10 requires. The detail moves to `#xmlsec_errors`, or to
  `ReferenceError#reference_uri` for an external Reference URI missing from
  `referenced_documents:`. Affected: the `UntrustedCertificate` for a `<KeyName>`
  missing from `keys:` (the KeyName), for an invalid `<X509Certificate>`
  (OpenSSL's text) and for a `certificate_subject:` mismatch (both subjects),
  and `ResolutionMismatch` (the reference fragment). RBS for `SignatureInfo`,
  `Verifier` and `Policy` matches the code again, and API_CONTRACT §5.6, §5.8
  and §7 describe the native layer as #142 left it.

- **#102:** Every check now runs on the document's bytes through the native
  layer, with or without Nokogiri, so there is one implementation.
  `schema: :default` validates on the extension's libxml2 rather than
  Nokogiri's, so its verdict follows that build: the system libxml2 2.9 line
  admits a no-namespace element under `<Object>`'s `##any` wildcard, as the XSD
  allows, where newer releases reject it. `reject_duplicate_ids` now matches an
  ID attribute by local name whatever its namespace, as `xmlSecAddIDs`
  registers it, so `p:Id="a"` next to `Id="a"` is a duplicate; it used to see
  only attributes without a namespace. `require_signed_root` takes the root's
  IDs from xmlsec's ID table, so a namespaced or `xml:id` ID on the root now
  counts. A String input is handed to the native layer as given rather than
  re-serialized through Nokogiri. `Policy#violations` / `#enforce!` check both
  from `xml_bytes:` alone; `document:` still works and is serialized, and
  `sig_node:` is accepted but unused. They check `max_document_size` first, on
  `document:`'s serialized form too, and skip the structural checks for an
  oversized document so it is never parsed natively (S-12).

- **#109:** Nokogiri stays an optional dependency. The gemspec's description
  and comment, README's new installation section and `NokogiriRequired`'s
  message now say HankoXml works with Nokogiri and without it, and name what
  needs it.

- **#96:** API_CONTRACT no longer describes features that don't exist. It now
  says 0.1.0 needs Nokogiri for every call (DOM-free verification is #102), and
  drops `Verifier.without_trust_verification` / `#trusted?` (#103),
  `Verification#signed_info` / `#certificate_chain` / `#key_info` (#104),
  `signature: :all` (#105), the `HankoXml.parse` NOBLANKS guard and
  `zero_copy:`. It also records that `valid?` raises `MultipleSignatures`
  (S-11).
- **#96:** API_CONTRACT's stale sections now match the code: PKCS#12 bundles
  hold `HankoXml::Key`s, `Policy`'s field list includes `schema:`,
  `nokogiri_ext`'s `doc.sign` returns a `SignedDocument`,
  `SignedDocument#inspect` has no `valid=`, and §7 lists the six native
  functions with `Native.verify`'s real arguments and result keys.

- **#89:** **Breaking:** `HankoXml.verify` is removed and `HankoXml.valid?` is
  added, as `API_CONTRACT.md` §5.1 always specified. A `Verification` is always
  truthy, so `if HankoXml.verify(doc, ...)` passed for a forged document. Use
  `HankoXml.valid?` for a boolean, `HankoXml.verify!` to raise, or
  `HankoXml::Verifier.new(...).verify(doc)` for the `Verification`.

- **#87:** **Breaking:** `HankoXml.signed?(xml)` is now
  `HankoXml.signature_present?(xml)`, and the Nokogiri extension's `doc.signed?`
  is now `doc.signature_present?`. The check is structural (a populated
  `<Signature>` exists) and runs no crypto, and the old name read like the trust
  check that `Verification#signed?(node)` actually is. There is no alias.

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
