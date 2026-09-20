#!/usr/bin/env python3
"""Regenerate the SignXML XAdES-B fixtures in this directory (#59).

Pins SignXML 5.1.0. IDs are random (SignXML's XAdESSigner uses secrets.token_hex),
so regenerating rewrites the committed XML. Only do that when SignXML's output
shape changes; the specs pin signed-property values from the committed files.

Usage, from the repository root:

    python3 -m pip install 'signxml==5.1.0'
    python3 spec/interop/xades/signxml-produced/generate.py
"""

from pathlib import Path

from lxml import etree
from signxml import DigestAlgorithm
from signxml.xades import XAdESDataObjectFormat, XAdESSignaturePolicy, XAdESSigner

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
KEY = (ROOT / "spec/fixtures/signer.key").read_text()
CERT = (ROOT / "spec/fixtures/signer.crt").read_text()
DOC = b'<Invoice xmlns="urn:x"><Total>150.00</Total></Invoice>'


def write(name, element):
    path = HERE / name
    path.write_bytes(etree.tostring(element, xml_declaration=True, encoding="UTF-8"))
    print(f"wrote {path.relative_to(ROOT)}")


def main():
    write("enveloped-default.xml", XAdESSigner().sign(etree.fromstring(DOC), key=KEY, cert=CERT))

    policy = XAdESSignaturePolicy(
        Identifier="urn:oid:2.16.76.1.7.1.6.2.3",
        Description="AD-RB",
        DigestMethod=DigestAlgorithm.SHA256,
        DigestValue="Ohixl6upD6av8N7pEvDABhEL6hM=",
    )
    fmt = XAdESDataObjectFormat(Description="Invoice", MimeType="text/xml")
    write(
        "enveloped-full.xml",
        XAdESSigner(
            signature_policy=policy,
            claimed_roles=["Chief Financial Officer"],
            data_object_format=fmt,
            c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        ).sign(etree.fromstring(DOC), key=KEY, cert=CERT),
    )


if __name__ == "__main__":
    main()
