# Security Policy

HankoXml signs and verifies XML. A bug that lets a forged or altered document
verify, lets the document choose its own verification key, or leaks key
material is a vulnerability, and we want to hear about it privately first.

## Reporting a vulnerability

Report it through GitHub's private vulnerability reporting:
<https://github.com/danimaribeiro/HankoXml/security/advisories/new>.

Please don't open a public issue, pull request or discussion for a suspected
vulnerability. A useful report includes:

- the HankoXml version, and whether the gem is a platform gem (vendored
  libraries) or the source gem built against system libxml2 and libxmlsec1
  (`HankoXml::NativeVersion.build_versions` prints both);
- a minimal document, key or certificate and the code that reproduces it;
- what you expected and what happened.

Use throwaway keys in reports. Never send a production private key.

## What happens next

- We acknowledge the report within 7 days.
- We confirm or rule out the issue, and agree a disclosure date with you,
  normally within 90 days of the report.
- The fix ships as a patch release with a GitHub Security Advisory and a CVE.
  The advisory is also submitted to
  [ruby-advisory-db](https://github.com/rubysec/ruby-advisory-db), so
  `bundler-audit` warns affected users.
- You are credited in the advisory unless you ask not to be.

## Supported versions

Before 1.0, only the latest minor release gets security fixes.

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Scope

In scope: the Ruby API under `lib/`, the native extension under `ext/`, the
default `Policy` presets, the release workflows, and the build of the vendored
libraries in the platform gems.

Vulnerabilities in libxml2, libxmlsec1 or OpenSSL themselves belong upstream.
Tell us as well when they affect the versions pinned in `dependencies.yml`,
since the platform gems bundle those copies; see "Responding to upstream
security fixes" in [RELEASING.md](RELEASING.md). Each GitHub release carries
an SBOM (`hanko_xml-X.Y.Z.cdx.json`) listing the bundled versions, so you can
check whether a platform gem includes an affected one.

Known limits that are documented rather than bugs: choosing which certificate
to trust is the caller's decision, `Policy.permissive` and the other presets
allow what they say they allow, and the XAdES caveats S-22 to S-24 in
[SECURITY_REVIEW.md](SECURITY_REVIEW.md) describe what the timestamp and
long-term validation checks can and can't vouch for.

## Past findings

[SECURITY_REVIEW.md](SECURITY_REVIEW.md) lists every finding from the
project's internal security review (`S-01` to `S-24`), how each was fixed, and
the specs that guard it.
