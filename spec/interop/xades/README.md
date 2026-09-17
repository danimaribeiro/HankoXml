# XAdES interop vectors

XAdES signatures produced by other implementations, verified by
`spec/interop/xades_interop_spec.rb` (#58). Nothing under `spec/` ships in the gem.

| Directory | What | Source | License |
| --- | --- | --- | --- |
| `signxml/` | 8 real-world XAdES samples from other implementations (XAdES-B to -LTA, RSA and ECDSA) | [SignXML](https://github.com/XML-Security/signxml) `test/xades/` at commit `2a9f5306d511fdf6c02b9ba2acee45e96d18328a` | Apache-2.0 |
| `dss/validation/xsw/` | 10 files from the EU DSS validator: 4 valid signatures and 6 signature-wrapping attacks | [EU DSS](https://github.com/esig/dss) `dss-xades/src/test/resources/validation/xsw/` at commit `c8aea1f90958a851f651fe39f1575fcbd6d4a11d` | LGPL-2.1 |

Every file was checked against its git blob id at that commit.

## The rest of the DSS corpus

DSS's `dss-xades` test resources hold 247 XML files (about 40 MB). Only the ones the
specs use are committed. `dss/MANIFEST.tsv` lists all of them, pinned to the DSS
commit above, with each file's git blob id, its size, and whether it is vendored.

```sh
bundle exec rake interop:dss
```

fetches the files not vendored into `dss/corpus/` (git-ignored), and verifies each
against its blob id. Nothing fetches them during the spec run.

At the time of vendoring, a pass over those 237 files under `Policy.interop` (trusting
each file's own certificate) found 85 valid XAdES signatures, and failures from:

- signatures that are not what DSS tests them for (data files, manifests, plain XML-DSig);
- XPath Filter 2.0 or XPath transforms, which the native layer refuses;
- detached signatures needing `referenced_documents:`;
- DSS's own negative cases (wrong certificate digest, malformed IssuerSerial, tampered values), all refused;
- one XAdES 1.2.2 signature (`Signature-X-CZ_ICZ-1.xml`): only 1.3.2 is supported.

Promote a file to the specs by copying it to the same relative path under `dss/`,
setting its manifest row to `yes`, and adding its expected outcome.
