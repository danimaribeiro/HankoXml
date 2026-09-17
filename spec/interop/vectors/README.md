# XML-DSig interop vectors

Signatures produced by other XML-DSig implementations, verified by
`spec/interop/interop_spec.rb` (#62).

| Directory | Produced by | Taken from |
| --- | --- | --- |
| `merlin-xmldsig-twenty-three/` | Baltimore Technologies (Merlin Hughes), W3C XML-DSig interop, 2002 | `xmlsec1-1.3.12/tests/merlin-xmldsig-twenty-three/` |
| `phaos-xmldsig-three/` | Phaos XML Toolkit, W3C XML-DSig interop, 2002 | `xmlsec1-1.3.12/tests/phaos-xmldsig-three/` |

The source is the xmlsec1 1.3.12 release tarball that the vendored build pins in
`dependencies.yml` (SHA256
`24045199af12d93fe5fdbbbf7e386e823e4842071e9432e2b90ac108b889a923`). xmlsec1 is
MIT licensed (`Copyright` in that tarball), and the vectors are the W3C
interoperability samples it redistributes. Nothing under `spec/` ships in the gem.

Copied: every `signature*.xml`, each suite's readme, the certificates and the phaos
CRL the spec uses as trust anchors, and `external-data/`, the documents xmlsec's suite
maps the external reference URIs to (served through `referenced_documents:`, #74). Not
copied: the `.tmpl` templates and the `c14n` intermediate outputs.

xmlsec's own expected result for each vector, and the keys and trust it uses, are
in `tests/testDSig.sh` in the same tarball. The spec records where HankoXml's
outcome differs from xmlsec's, and why.
