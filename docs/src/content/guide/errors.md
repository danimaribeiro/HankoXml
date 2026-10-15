---
title: Errors
description: The HankoXml exception hierarchy and what each error means.
order: 7
---

# Errors

Every HankoXml error descends from `HankoXml::Error` — rescue that to catch anything the library
raises. Errors carry structured context, not just a message.

```
StandardError
└── HankoXml::Error                  base; rescue this to catch everything
    ├── HankoXml::ConfigurationError invalid Signer/Verifier construction
    │   ├── HankoXml::PolicyError    a Policy allowlist was violated
    │   ├── HankoXml::PlacementError placement XPath matched 0 or >1 nodes
    │   ├── HankoXml::NokogiriRequired  this capability needs a DOM
    │   └── HankoXml::SchemaError    <Signature> failed XSD validation
    ├── HankoXml::ParseError         the XML would not parse
    ├── HankoXml::KeyLoadError       key or certificate unreadable / unsupported
    ├── HankoXml::ReferenceError     a reference target does not exist, is
    │                                ambiguous, or has no ID attribute
    ├── HankoXml::SigningError       libxmlsec1 could not produce a signature
    ├── HankoXml::VerificationError  verification did not succeed (raised by verify!)
    │   ├── HankoXml::SignatureInvalid       cryptographic mismatch
    │   ├── HankoXml::SignatureMissing       no <ds:Signature> in the document
    │   ├── HankoXml::MultipleSignatures     signature: :only and >1 present
    │   ├── HankoXml::UntrustedCertificate   chain/pinning failed
    │   ├── HankoXml::CertificateExpired     outside notBefore/notAfter, as of
    │   │                                    verification_time
    │   ├── HankoXml::DigestMismatch         one <Reference>'s digest is wrong;
    │   │                                    carries #reference_uri
    │   ├── HankoXml::ResolutionMismatch     resolver vs xmlsec disagree
    │   └── HankoXml::XadesError             a XAdES signed-properties check failed
    ├── HankoXml::NotSignedError     Verification#at_signed found a node that
    │                                the signature does not cover
    ├── HankoXml::FrozenSignatureError  a mutator was called on a
    │                                SignedDocument
    └── HankoXml::NativeError        libxmlsec1 failed in an unexpected way
        └── HankoXml::NativeVersionMismatch  the loaded libxmlsec1/libxml2 do not
                                             match the build (raised at require)
```

> Note the name is `HankoXml::KeyLoadError`, not `KeyError` — deliberately avoiding a name that
> shadows a Ruby core class.

## Structured context

```ruby
begin
  HankoXml.verify!(xml, certificate: cert)
rescue HankoXml::Error => e
  e.xmlsec_errors  # => ["func=xmlSecOpenSSLEvpSignatureVerify:file=signatures.c:
                   #      line=444:obj=rsa-sha256:subj=EVP_VerifyFinal:error=18:
                   #      data do not match"]
  e.signature_node # => Nokogiri::XML::Element, when one was located
  e.reference_uri  # => "#infNFe01", on ReferenceError
end
```

`#xmlsec_errors` is captured by installing an `xmlSecErrorsSetCallback` handler that appends into a
thread-local buffer, drained on each native call. This is the difference between
`SigningError: failed to sign` and an actual diagnosis.

`#message` is always a fixed string from HankoXml, and the exception class depends on where the
failure happened, never on the log's wording. The xmlsec log can quote text from the document
(algorithm URIs, Reference URIs, node names), so it appears only in `#xmlsec_errors`. Treat that
array as untrusted input before logging or displaying it.

**`HankoXml::Error` and subclasses never carry key material.** The error constructor filters any
value that came from a `Key`.

## Per-reference errors

`DigestMismatch` and similar failures carry `#reference_uri` because "the digest of reference 2 does
not match" and "the signature over `<SignedInfo>` does not match" are completely different bugs —
the first means the data changed, the second means the key or the canonicalization is wrong. See
[`Verification::Reference`](/reference/verification#reference) for the per-reference `#errors`
accessor.
