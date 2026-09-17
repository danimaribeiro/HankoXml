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

  describe ".interop" do
    it "differs from fragment only by SHA-1 with RSA or DSA and 1024-bit RSA keys" do
      interop = described_class.interop.to_h
      fragment = described_class.fragment.to_h

      expect(interop.reject { |field, value| fragment[field] == value }).to eq(
        digest_methods: fragment[:digest_methods] + [:sha1],
        signature_methods: fragment[:signature_methods] + %i[rsa_sha1 dsa_sha1],
        min_rsa_key_bits: 1024
      )
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

    # S-06: fields that only need signature_info (no DOM/key material).
    it "flags an HMAC signature method regardless of signature_methods (allow_hmac)" do
      info = HankoXml::SignatureInfo.new(
        signature_method: "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
        canonicalization_method: "http://www.w3.org/2001/10/xml-exc-c14n#",
        references: [{ uri: "", digest_method: "http://www.w3.org/2001/04/xmlenc#sha256", transforms: [] }]
      )
      policy = described_class.strict.with(signature_methods: described_class.strict.signature_methods + [:hmac_sha256])

      expect(policy.violations(info).map(&:message).join).to match(/allow_hmac/)
    end

    it "allows HMAC when allow_hmac is true" do
      info = HankoXml::SignatureInfo.new(
        signature_method: "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
        canonicalization_method: "http://www.w3.org/2001/10/xml-exc-c14n#",
        references: [{ uri: "", digest_method: "http://www.w3.org/2001/04/xmlenc#sha256", transforms: [] }]
      )
      policy = described_class.strict.with(
        signature_methods: described_class.strict.signature_methods + [:hmac_sha256],
        allow_hmac: true
      )

      expect(policy.violations(info)).to be_empty
    end

    it "flags a RetrievalMethod in KeyInfo when allow_retrieval_method is false" do
      info = HankoXml::SignatureInfo.new(
        signature_method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        canonicalization_method: "http://www.w3.org/2001/10/xml-exc-c14n#",
        references: [{ uri: "", digest_method: "http://www.w3.org/2001/04/xmlenc#sha256", transforms: [] }],
        has_retrieval_method: true
      )

      expect(described_class.strict.violations(info).map(&:message).join).to match(/RetrievalMethod/)
    end

    it "flags a same-document XPointer reference when allow_same_document_xpointer is false" do
      info = HankoXml::SignatureInfo.new(
        signature_method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        canonicalization_method: "http://www.w3.org/2001/10/xml-exc-c14n#",
        references: [{ uri: "#xpointer(/)", digest_method: "http://www.w3.org/2001/04/xmlenc#sha256",
                       transforms: [] }]
      )

      expect(described_class.strict.violations(info).map(&:message).join).to match(/allow_same_document_xpointer/)
    end
  end

  # S-16: a later Algorithms.register must not change what a Policy accepts.
  describe "algorithm allowlist snapshot" do
    let(:old_uri) { "http://example.com/digest-snapshot-test-v1" }
    let(:new_uri) { "http://example.com/digest-snapshot-test-v2" }

    def info_with_digest(uri)
      HankoXml::SignatureInfo.new(
        signature_method: compliant_info.signature_method,
        canonicalization_method: compliant_info.canonicalization_method,
        references: [{ uri: "", digest_method: uri,
                       transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"] }]
      )
    end

    after do
      table = HankoXml::Algorithms.digest
      table.instance_variable_get(:@by_name).delete(:snapshot_test)
      [old_uri, new_uri].each { |uri| table.instance_variable_get(:@by_uri).delete(uri) }
    end

    it "keeps the URIs a name resolved to when the Policy was built" do
      HankoXml::Algorithms.register(:digest, :snapshot_test, old_uri, secure: true)
      policy = described_class.strict.with(digest_methods: [:snapshot_test])

      HankoXml::Algorithms.register(:digest, :snapshot_test, new_uri, secure: true, replace: true)

      expect(policy.violations(info_with_digest(old_uri))).to be_empty
      expect(policy.violations(info_with_digest(new_uri)).map(&:message).join).to match(/digest_methods/)
    end

    it "compares a document's algorithm String verbatim, not as a registry name" do
      expect(described_class.strict.violations(info_with_digest("sha256")).map(&:message).join)
        .to match(/digest_methods/)
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
