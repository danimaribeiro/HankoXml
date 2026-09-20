---
title: Algorithms
description: HankoXml::Algorithms — the process-global registry of signature, digest, canonicalization, and transform algorithms.
order: 6
---

# `HankoXml::Algorithms`

Every algorithm slot accepts either a **Symbol** (looked up here) or a **String URI** (used
verbatim, subject to `Policy`).

```ruby
HankoXml::Algorithms.signature[:rsa_sha256]
# => #<Entry name=:rsa_sha256 uri="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" secure=true>

HankoXml::Algorithms.uri_for(:signature, :rsa_sha256)  # => "http://..."
HankoXml::Algorithms.name_for(:signature, "http://...") # => :rsa_sha256, or nil
HankoXml::Algorithms.secure?(:digest, :sha1)            # => false

HankoXml::Algorithms.register(
  :signature, :hmac_sha512,
  "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512",
  secure: true
)
```

Registration is process-global and additive. Built-in names and URIs can never be re-registered,
even with `replace: true`; `replace: true` only replaces an algorithm you registered yourself.
**Registering does not grant use** — a `Policy` must also allow it. A `Policy` resolves its
allowlists to URIs when it is created, so registering or replacing an algorithm later never changes
what an existing policy (including `Policy.strict`) accepts. That separation means registering an
algorithm never silently makes it acceptable to every verifier in the process.

## Built-in tables

### Canonicalization (`Algorithms.canonicalization`) — also usable as transforms

| Name | URI | `secure?` |
| --- | --- | --- |
| `:c14n` | `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` | ✅ |
| `:c14n_with_comments` | `…-20010315#WithComments` | ✅ |
| `:exc_c14n` | `http://www.w3.org/2001/10/xml-exc-c14n#` | ✅ |
| `:exc_c14n_with_comments` | `http://www.w3.org/2001/10/xml-exc-c14n#WithComments` | ✅ |
| `:c14n11` | `http://www.w3.org/2006/12/xml-c14n11` | ✅ |
| `:c14n11_with_comments` | `http://www.w3.org/2006/12/xml-c14n11#WithComments` | ✅ |

### Digest (`Algorithms.digest`)

| Name | URI | `secure?` |
| --- | --- | --- |
| `:sha1` | `http://www.w3.org/2000/09/xmldsig#sha1` | ❌ |
| `:sha224` | `http://www.w3.org/2001/04/xmldsig-more#sha224` | ✅ |
| `:sha256` | `http://www.w3.org/2001/04/xmlenc#sha256` | ✅ |
| `:sha384` | `http://www.w3.org/2001/04/xmldsig-more#sha384` | ✅ |
| `:sha512` | `http://www.w3.org/2001/04/xmlenc#sha512` | ✅ |
| `:ripemd160` | `http://www.w3.org/2001/04/xmlenc#ripemd160` | ❌ |
| `:sha3_224` | `http://www.w3.org/2007/05/xmldsig-more#sha3-224` | ✅ |
| `:sha3_256` | `http://www.w3.org/2007/05/xmldsig-more#sha3-256` | ✅ |
| `:sha3_384` | `http://www.w3.org/2007/05/xmldsig-more#sha3-384` | ✅ |
| `:sha3_512` | `http://www.w3.org/2007/05/xmldsig-more#sha3-512` | ✅ |

(The `xmlenc` / `xmldsig-more` split for sha256/384/512 is not a typo — it is what the specs say. SHA-3 and RSA-PSS need libxmlsec1 1.3+ to sign or verify; they are still first-class names on xmlsec 1.2, which then fails closed.)

### Signature (`Algorithms.signature`)

| Name | URI | `secure?` |
| --- | --- | --- |
| `:rsa_sha1` | `http://www.w3.org/2000/09/xmldsig#rsa-sha1` | ❌ |
| `:rsa_sha224` | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha224` | ✅ |
| `:rsa_sha256` | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` | ✅ |
| `:rsa_sha384` | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha384` | ✅ |
| `:rsa_sha512` | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha512` | ✅ |
| `:rsa_pss_sha256` | `http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1` | ✅ |
| `:rsa_pss_sha384` | `http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1` | ✅ |
| `:rsa_pss_sha512` | `http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1` | ✅ |
| `:ecdsa_sha256` | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256` | ✅ |
| `:ecdsa_sha384` | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384` | ✅ |
| `:ecdsa_sha512` | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512` | ✅ |
| `:ecdsa_sha3_256` | `http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha3-256` | ✅ |
| `:ecdsa_sha3_384` | `http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha3-384` | ✅ |
| `:ecdsa_sha3_512` | `http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha3-512` | ✅ |
| `:dsa_sha1` | `http://www.w3.org/2000/09/xmldsig#dsa-sha1` | ❌ |
| `:hmac_sha256` | `http://www.w3.org/2001/04/xmldsig-more#hmac-sha256` | ✅ but see [Policy](/reference/policy) |

### Transform (`Algorithms.transform`) — the canonicalization table above, plus

| Name | URI | `secure?` |
| --- | --- | --- |
| `:enveloped_signature` | `http://www.w3.org/2000/09/xmldsig#enveloped-signature` | ✅ |
| `:base64` | `http://www.w3.org/2000/09/xmldsig#base64` | ✅ |
| `:xpath` | `http://www.w3.org/TR/1999/REC-xpath-19991116` | ❌ |
| `:xpath_filter2` | `http://www.w3.org/2002/06/xmldsig-filter2` | ❌ |
| `:xslt` | `http://www.w3.org/TR/1999/REC-xslt-19991116` | ❌ |

`secure?` is a *default recommendation*, not a hard gate — `Policy.strict` is a SHA-2 RSA/ECDSA subset, not every `secure?` name. RSA-PSS and SHA-3 are `secure?` but only `Policy.xades` (or `Policy#with`) allows them. See the [Policy reference](/reference/policy)
for how algorithm allowlists interact with these tables.
