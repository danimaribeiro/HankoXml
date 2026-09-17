# XAdES schema

`XAdES01903v132-202407.xsd` is the ETSI EN 319 132-1 XAdES 1.3.2 schema, taken
from the EU DSS project (`esig/dss`, `specs-xades/src/main/resources/xsd/`, commit
`da2ce560536e`). Its import of the W3C XML-DSig schema is rewritten to the copy
bundled in `lib/hanko_xml/`, so validation never fetches anything.
`spec/hanko_xml/xades_signer_spec.rb` validates the `<xades:QualifyingProperties>`
that `HankoXml::Xades::Signer` produces against it. Nothing under `spec/` ships
in the gem.
