# frozen_string_literal: true

RSpec.describe HankoXml::Policy do
  let(:compliant_info) do
    HankoXml::SignatureInfo.new(
      signature_method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      canonicalization_method: "http://www.w3.org/2001/10/xml-exc-c14n#",
      references: [
        { uri: "", digest_method: "http://www.w3.org/2001/04/xmlenc#sha256",
          transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"] }
      ]
    )
  end

  describe ".strict" do
    it "is the default preset" do
      expect(described_class.strict.digest_methods).to include(:sha256)
      expect(described_class.strict.digest_methods).not_to include(:sha1)
    end

    it "requires the signed root" do
      expect(described_class.strict.require_signed_root).to be true
    end

    it "is frozen and memoized" do
      expect(described_class.strict).to equal(described_class.strict)
      expect(described_class.strict).to be_frozen
    end
  end

  describe ".fragment" do
    it "is strict minus require_signed_root" do
      expect(described_class.fragment.require_signed_root).to be false
      expect(described_class.fragment.digest_methods).to eq(described_class.strict.digest_methods)
    end
  end

  describe ".legacy_sha1" do
    it "adds SHA-1 digest and RSA-SHA1 signature to strict" do
      expect(described_class.legacy_sha1.digest_methods).to include(:sha1)
      expect(described_class.legacy_sha1.signature_methods).to include(:rsa_sha1)
    end
  end

  describe "#with" do
    it "returns a new Policy with overrides applied, leaving the original untouched" do
      strict = described_class.strict
      relaxed = strict.with(max_references: 100)

      expect(relaxed.max_references).to eq(100)
      expect(strict.max_references).to eq(8)
    end
  end

  describe "#violations" do
    it "is empty for a compliant SignatureInfo under .strict" do
      expect(described_class.strict.violations(compliant_info)).to be_empty
    end

    it "flags a disallowed digest method" do
      info = HankoXml::SignatureInfo.new(
        signature_method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        canonicalization_method: "http://www.w3.org/2001/10/xml-exc-c14n#",
        references: [{ uri: "", digest_method: "http://www.w3.org/2000/09/xmldsig#sha1", transforms: [] }]
      )

      violations = described_class.strict.violations(info)
      expect(violations).not_to be_empty
      expect(violations.first).to be_a(HankoXml::PolicyError)
      expect(violations.first.message).to match(/digest method/)
    end

    it "flags a disallowed signature method" do
      info = HankoXml::SignatureInfo.new(
        signature_method: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalization_method: "http://www.w3.org/2001/10/xml-exc-c14n#",
        references: [{ uri: "", digest_method: "http://www.w3.org/2001/04/xmlenc#sha256", transforms: [] }]
      )

      expect(described_class.strict.violations(info).map(&:message).join).to match(/signature method/)
    end

    it "accepts SHA-1 under .legacy_sha1" do
      info = HankoXml::SignatureInfo.new(
        signature_method: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalization_method: "http://www.w3.org/2001/10/xml-exc-c14n#",
        references: [{ uri: "", digest_method: "http://www.w3.org/2000/09/xmldsig#sha1", transforms: [] }]
      )

      expect(described_class.legacy_sha1.violations(info)).to be_empty
    end

    it "flags an external reference when allow_external_references is false" do
      info = HankoXml::SignatureInfo.new(
        signature_method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        canonicalization_method: "http://www.w3.org/2001/10/xml-exc-c14n#",
        references: [{ uri: "http://example.com/doc.xml", digest_method: "http://www.w3.org/2001/04/xmlenc#sha256",
                       transforms: [] }]
      )

      expect(described_class.strict.violations(info).map(&:message).join).to match(/external/)
    end

    it "flags a reference count above max_references" do
      refs = 9.times.map do
        { uri: "##{_1}", digest_method: "http://www.w3.org/2001/04/xmlenc#sha256",
          transforms: [] }
      end
      info = HankoXml::SignatureInfo.new(
        signature_method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        canonicalization_method: "http://www.w3.org/2001/10/xml-exc-c14n#",
        references: refs
      )

      expect(described_class.strict.violations(info).map(&:message).join).to match(/max_references/)
    end
  end

  describe "#enforce!" do
    it "does not raise for a compliant SignatureInfo" do
      expect { described_class.strict.enforce!(compliant_info) }.not_to raise_error
    end

    it "raises HankoXml::PolicyError for a violating SignatureInfo" do
      info = HankoXml::SignatureInfo.new(
        signature_method: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        canonicalization_method: "http://www.w3.org/2001/10/xml-exc-c14n#",
        references: []
      )

      expect { described_class.strict.enforce!(info) }.to raise_error(HankoXml::PolicyError)
    end
  end
end
