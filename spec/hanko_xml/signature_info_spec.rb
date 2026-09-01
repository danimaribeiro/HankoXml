# frozen_string_literal: true

RSpec.describe HankoXml::SignatureInfo do
  let(:info) do
    described_class.new(
      signature_method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      canonicalization_method: "http://www.w3.org/2001/10/xml-exc-c14n#",
      references: [
        { uri: "#infNFe01", digest_method: "http://www.w3.org/2001/04/xmlenc#sha256",
          transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"] }
      ]
    )
  end

  it "resolves algorithm names from URIs" do
    expect(info.signature_method_name).to eq(:rsa_sha256)
    expect(info.canonicalization_method_name).to eq(:exc_c14n)
  end

  it "wraps references as ReferenceInfo" do
    ref = info.references.first
    expect(ref).to be_a(described_class::ReferenceInfo)
    expect(ref.uri).to eq("#infNFe01")
    expect(ref.digest_method_name).to eq(:sha256)
    expect(ref.transform_names).to eq([:enveloped_signature])
    expect(ref.fragment?).to be true
    expect(ref.external?).to be false
  end

  it "flags an external (non-fragment, non-empty) reference URI" do
    ref = described_class::ReferenceInfo.new(uri: "http://example.com/doc.xml",
                                             digest_method: "http://www.w3.org/2001/04/xmlenc#sha256")
    expect(ref.external?).to be true
  end

  it "is frozen" do
    expect(info).to be_frozen
  end

  it ".from_native builds from a Native.inspect-shaped Hash" do
    info = described_class.from_native(
      signature_method: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
      canonicalization_method: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
      signature_count: 2,
      key_names: ["idp-1"],
      certificates: [],
      references: [{ uri: "", digest_method: "http://www.w3.org/2000/09/xmldsig#sha1", transforms: [] }]
    )

    expect(info.signature_count).to eq(2)
    expect(info.key_names).to eq(["idp-1"])
    expect(info.references.size).to eq(1)
  end
end
