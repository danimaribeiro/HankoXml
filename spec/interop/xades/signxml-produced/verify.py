#!/usr/bin/env python3
"""Verify a HankoXml-produced XAdES-B document with SignXML 5.1.0 (#59).

SignXML's XAdESSigner always adds a third Reference over KeyInfo, so
XAdESVerifier defaults to expect_references=3. HankoXml::Xades::Signer signs
the payload and SignedProperties only. Pass expect_references=2.

Usage, from the repository root:

    python3 spec/interop/xades/signxml-produced/verify.py signed.xml
"""

import argparse
import sys
from pathlib import Path

from signxml import DigestAlgorithm
from signxml.xades import XAdESSignatureConfiguration, XAdESSignaturePolicy, XAdESVerifier

ROOT = Path(__file__).resolve().parents[4]
DEFAULT_CERT = ROOT / "spec/fixtures/signer.crt"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xml")
    parser.add_argument("--cert", default=str(DEFAULT_CERT))
    parser.add_argument("--policy-id")
    parser.add_argument("--policy-digest")
    parser.add_argument("--policy-description", default="")
    args = parser.parse_args()

    kwargs = {
        "x509_cert": Path(args.cert).read_text(),
        "expect_config": XAdESSignatureConfiguration(expect_references=2),
    }
    if args.policy_id:
        kwargs["expect_signature_policy"] = XAdESSignaturePolicy(
            Identifier=args.policy_id,
            Description=args.policy_description,
            DigestMethod=DigestAlgorithm.SHA256,
            DigestValue=args.policy_digest,
        )

    XAdESVerifier().verify(Path(args.xml).read_bytes(), **kwargs)
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
