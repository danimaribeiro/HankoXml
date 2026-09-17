# frozen_string_literal: true

RSpec.describe HankoXml::Algorithms do
  describe ".uri_for / .name_for" do
    it "resolves a known Symbol to its URI" do
      expect(described_class.uri_for(:signature, :rsa_sha256))
        .to eq("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
    end

    it "resolves a URI back to its Symbol" do
      expect(described_class.name_for(:digest, "http://www.w3.org/2001/04/xmlenc#sha256")).to eq(:sha256)
    end

    it "returns nil for an unknown URI" do
      expect(described_class.name_for(:digest, "http://example.com/unknown")).to be_nil
    end

    it "passes an unregistered URI String through verbatim" do
      expect(described_class.uri_for(:transform, "http://example.com/custom")).to eq("http://example.com/custom")
    end
  end

  describe ".secure?" do
    it "flags SHA-1 as insecure" do
      expect(described_class.secure?(:digest, :sha1)).to be false
    end

    it "flags SHA-256 as secure" do
      expect(described_class.secure?(:digest, :sha256)).to be true
    end

    it "flags an unknown algorithm as insecure" do
      expect(described_class.secure?(:digest, "http://example.com/unknown")).to be false
    end
  end

  describe ".register" do
    after { described_class.signature.instance_variable_get(:@by_name).delete(:rsa_pss_sha256_test) }

    it "adds a new algorithm" do
      described_class.register(:signature, :rsa_pss_sha256_test,
                               "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1-test", secure: true)

      expect(described_class.uri_for(:signature, :rsa_pss_sha256_test))
        .to eq("http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1-test")
    end

    it "refuses to silently replace a built-in name" do
      expect do
        described_class.register(:signature, :rsa_sha256, "http://example.com/evil", secure: true)
      end.to raise_error(ArgumentError, /built in/)
    end

    # S-16: built-ins are what Policy presets are written in terms of.
    it "refuses to replace a built-in name even with replace: true" do
      expect do
        described_class.register(:digest, :sha256, "http://www.w3.org/2000/09/xmldsig#sha1",
                                 secure: true, replace: true)
      end.to raise_error(ArgumentError, /built in/)
      expect(described_class.uri_for(:digest, :sha256)).to eq("http://www.w3.org/2001/04/xmlenc#sha256")
    end

    it "refuses to re-register a built-in URI under another name" do
      expect do
        described_class.register(:digest, :sha1_is_fine_test, "http://www.w3.org/2000/09/xmldsig#sha1",
                                 secure: true, replace: true)
      end.to raise_error(ArgumentError, /built in as :sha1/)
      expect(described_class.secure?(:digest, "http://www.w3.org/2000/09/xmldsig#sha1")).to be false
    end

    it "still lets a custom registration be replaced, dropping its old URI" do
      old_uri = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1-test"
      new_uri = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1-test2"
      described_class.register(:signature, :rsa_pss_sha256_test, old_uri, secure: true)
      described_class.register(:signature, :rsa_pss_sha256_test, new_uri, secure: true, replace: true)

      expect(described_class.uri_for(:signature, :rsa_pss_sha256_test)).to eq(new_uri)
      expect(described_class.name_for(:signature, old_uri)).to be_nil
      described_class.signature.instance_variable_get(:@by_uri).delete(new_uri)
    end
  end

  it "every canonicalization algorithm is also usable as a transform" do
    described_class.canonicalization.names.each do |name|
      expect(described_class.uri_for(:transform, name)).to eq(described_class.uri_for(:canonicalization, name))
    end
  end
end
