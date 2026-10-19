# HankoXml Assurance Roadmap

How we could gain more confidence that HankoXml is correct than example-based
specs alone can give. This is a proposal, not a record of work done: nothing
below is implemented yet. When an item lands, move it to "In place" and cite the
spec or workflow that carries it.

## Where we are

In place today:

- Example-based RSpec suites, including `spec/hanko_xml/adversarial_spec.rb`
  (tampering, signature wrapping, key substitution, XXE, entity expansion, weak
  keys) and the interop fixtures under `spec/interop`.
- `SECURITY_REVIEW.md`, whose `S-xx` findings are cited by the specs that guard
  them.
- `unsafe` confined by the compiler: `#![deny(unsafe_code)]` at the crate root
  of `ext/hanko_xml`, with `#[allow(unsafe_code)]` only on the `dsig`,
  `errors` and `sys` modules and on `rstring_to_bytes` in `lib.rs`. Every
  `unsafe` block carries a `// SAFETY:` comment, enforced by
  `clippy::undocumented_unsafe_blocks` under CI's `clippy -D warnings`.
  `spec/hanko_xml/native_spec.rb` fails if any of these attributes is removed
  or widened (#185).
- CI on system and vendored libxml2/xmlsec1, plus `cargo-deny`,
  `clippy -D warnings` and `bundler-audit` (`.github/workflows/security.yml`).

What these cannot do: an example spec checks the inputs someone thought of. Each
`S-xx` finding was an input nobody had thought of. The items below are ways to
check statements of the form "for **all** inputs, X never happens".

## What a proof could and could not give us

Formal verification proves that code matches a specification. Two limits decide
how much of it is worth doing here.

1. **The trusted base is unverified C.** Canonicalization, digests, signature
   math, reference resolution and key handling run in libxmlsec1, libxml2 and
   OpenSSL, by design (see "Security conventions" in `CLAUDE.md`). Proving our
   Rust glue correct would not change what those libraries do. Our assurance for
   them comes from their own history of scrutiny and fuzzing, from pinning
   versions (`VENDORING.md`), and from testing our use of them on both builds.
2. **XML-DSig failures are mostly specification failures.** Signature wrapping,
   document-chosen keys (S-01), ID resolution mismatch (S-03) and policy ordering
   (S-04, S-05) were all cases where every component did its job and the
   composition was wrong. A proof tool only helps after the intended property is
   written down precisely. Writing it down is most of the value.

So the plan is: state the invariants, test them as universal properties, fuzz
the boundary, and use proof tools only on the small part we own outright, which
is the `unsafe` Rust.

## 1. Write the invariants down

Add a "Security invariants" section to `API_CONTRACT.md`, each one phrased as a
universal statement and numbered (`I-xx`) so specs can cite it the way they cite
`S-xx`. A starting list, all of which the code is already meant to uphold:

- **I-01 Round trip.** For every document, supported key, and policy-allowed
  algorithm set, `Verifier` accepts what `Signer` produced, with the matching
  trusted key.
- **I-02 Tamper evidence.** For every signed document and every change to the
  bytes covered by a reference (after canonicalization), verification fails.
- **I-03 Signed means signed.** For every verified document and node `n`,
  `Verification#signed?(n)` is true only if `n` lies inside the node set xmlsec
  digested for a valid reference. Wrapping attacks are violations of this one.
- **I-04 Key pinning.** For every document, the verification result does not
  depend on the content of `<KeyInfo>`. Replacing or removing `<KeyInfo>` never
  turns an invalid result into a valid one (S-01).
- **I-05 Policy before crypto.** For every input that violates the policy, no
  external reference is dereferenced, no denied transform runs, and
  `Native.sign` is never called (S-04, S-05, S-10).
- **I-06 Caller's document untouched on failure.** If `sign!` raises, the
  caller's document is byte-identical to what was passed in (S-05).
- **I-07 No key material in errors.** For every failure, the exception message
  and the captured xmlsec log contain no bytes of the private key.
- **I-08 Fail closed.** For every input, including malformed XML and arbitrary
  bytes, the verifier returns invalid or raises a `HankoXml::Error`. It never
  returns valid on an error path and never crashes the process.
- **I-09 Build independence.** I-01 to I-08 hold on both the system and the
  vendored library builds, and whichever of hanko_xml or Nokogiri loads first.

This is the FLAME habit applied to a security library: decide the invariant
first, then write the code that keeps it.

## 2. Property-based specs

Turn the invariants into generated tests. A generator builds random documents
(depth, namespaces, `Id` placement, mixed content, comments, entity-free DTDs),
picks a key type, algorithms and reference shape, and the spec asserts the
invariant. On failure the framework shrinks the input to a minimal case, which
then becomes a fixed regression spec.

Properties worth having, in rough order of value:

- **Mutation (I-02, I-03).** Sign a generated document, apply one random
  mutation (flip a byte, move a subtree, duplicate the signed element, inject a
  sibling with the same `Id`, wrap the signature), then check that either
  verification fails or every node reported by `signed?` is unchanged. This is a
  systematic search for wrapping variants instead of the handful we wrote by
  hand.
- **KeyInfo independence (I-04).** Replace `<KeyInfo>` with generated content,
  including another valid key's `<KeyValue>` and certificates. The result must
  equal the result without the replacement.
- **Policy monotonicity (I-05).** For generated policies `P` and `Q` where `Q`
  allows a subset of `P`, anything `Q` accepts `P` accepts. A violation means a
  policy field is read inconsistently, as in S-06.
- **Round trip and differential (I-01).** Everything we sign verifies here and
  with the `xmlsec1` command line tool, and the reverse. Disagreement between
  two implementations finds bugs without anyone having to know the right answer.
- **Atomicity (I-06).** Generated hostile templates under `:adopt`: `sign!`
  raises and the input document serializes to the same bytes as before.

Tooling: `prop_check` or `rantly` as a development dependency. Keep the default
run small (about 100 cases per property) so CI stays fast, and add a scheduled
workflow with a large case count and a random seed that is printed on failure.

## 3. Fuzz the native boundary

Property tests generate well-formed input. A coverage-guided fuzzer generates
the other kind and is what finds memory errors and hangs (I-08).

- A `cargo-fuzz` target that calls the verify path in `dsig.rs` with arbitrary
  bytes and a fixed trusted key, built with AddressSanitizer. Seed the corpus
  with `spec/fixtures` and the interop documents, and give it an XML dictionary.
- A second target for the sign path with `:adopt`, feeding arbitrary bytes as
  the template.
- Assertions: no crash, no sanitizer report, no run over a time budget, and the
  result is never "valid" for an input that does not contain the fixed key's
  signature.
- Run it against the vendored build, since that is what platform gem users get.
  libxml2 and xmlsec1 are already fuzzed upstream (OSS-Fuzz), so the target here
  is our use of them: ownership of `xmlDocPtr` and contexts, error paths that
  free things, the error log callback in `errors.rs`, and length conversions
  like the one behind S-12.
- Start as a scheduled job with a short budget. Every crash becomes a fixture
  and a spec.

## 4. Check the `unsafe` Rust

`unsafe` is confined to two files, which makes this tractable.

- **Sanitizers in CI.** Run the existing RSpec suite once against an extension
  built with AddressSanitizer and LeakSanitizer. This is the cheapest way to find
  a double free or a leak on an error path, because the specs already exercise
  those paths.
- **Document every `unsafe` block.** Done (#185, see "Where we are"). Each
  `// SAFETY:` comment states the precondition its block relies on (pointer
  non-null, who owns it, which lifetime covers it). These comments are the pre
  and postconditions a proof would need, so keep them precise when the code
  changes.
- **Replace the `unsafe` counting spec with the compiler.** Done (#185):
  rustc enforces `deny(unsafe_code)`, and `native_spec.rb` only checks that
  the attributes stay in place.
- **RAII for every xmlsec and libxml2 handle.** `OwnedXmlDoc` exists. If any
  context, key, or key manager is still freed by hand on some path, wrap it, so
  "freed exactly once" is guaranteed by the type and not by reading each return.
- **Kani for the pure parts.** Kani cannot execute FFI calls, so it cannot check
  calls into xmlsec. It can prove properties of code around them: length and
  integer conversions never truncate or overflow (S-12), buffer indexing in the
  error log never goes out of bounds, enum to flag mappings are total. This needs
  that logic factored into functions with no FFI in them, which is a good
  refactor anyway. Low priority: do it after the items above.

Miri is not useful here for the same FFI reason.

## 5. Things that are cheap and not proofs

- **Mutation testing** (`mutant` on `lib/hanko_xml/policy.rb` and
  `verifier.rb`). It changes the code and checks that a spec fails. A surviving
  mutant in a policy check is a missing spec, which is exactly how S-06 (eleven
  unenforced fields) could have been caught mechanically.
- **Constant-time comparison** is xmlsec's and OpenSSL's job. We should confirm
  that no Ruby code compares digests or HMAC values with `==`, and add a spec
  that greps for it if any such comparison ever appears.
- **Steep in CI** for `sig/`, so the RBS signatures are checked against the code
  and cannot drift.

## Suggested order

| Step | Item | Cost | Finds |
|------|------|------|-------|
| 1 | Invariants `I-01`..`I-09` in `API_CONTRACT.md` | small | unclear requirements |
| 2 | Mutation and KeyInfo independence properties | medium | wrapping and trust bugs |
| 3 | ASan/LSan run of the existing suite | small | memory errors on error paths |
| 4 | ~~`// SAFETY:` comments, clippy lint, `deny(unsafe_code)`~~ (done, #185) | small | unsound assumptions |
| 5 | `cargo-fuzz` verify target, scheduled | medium | crashes, hangs, I-08 |
| 6 | Differential test against `xmlsec1` CLI | medium | interop and semantics bugs |
| 7 | Mutation testing on policy and verifier | small | missing specs |
| 8 | Policy monotonicity, atomicity properties | medium | S-05/S-06 class bugs |
| 9 | Kani on FFI-free helpers | large | integer and indexing bugs |

Each step gets its own issue and goes through a PR like any other change to
`spec/`, `ext/` or the workflows.

## Background reading

- R. van de Geijn, M. Myers: *LAFF-On Programming for Correctness*. Hoare logic
  and deriving loops from invariants, the method behind libflame.
- Somorovsky et al.: *On Breaking SAML: Be Whoever You Want to Be* (USENIX
  Security 2012). The catalogue of signature wrapping attacks that I-03 is
  about.
- HACL\* and Fiat-Crypto: verified cryptographic code in production, and a
  useful reference for what full verification costs.
- The Kani Rust Verifier book, and the `cargo-fuzz` book.
