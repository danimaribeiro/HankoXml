# frozen_string_literal: true

RSpec.describe HankoXml::KeyInfo do
  describe ".coerce" do
    it "wraps a single Symbol" do
      clauses = described_class.coerce(:x509_certificate)
      expect(clauses.map(&:name)).to eq([:x509_certificate])
    end

    it "wraps an Array of Symbols" do
      clauses = described_class.coerce(%i[x509_certificate key_name])
      expect(clauses.map(&:name)).to eq(%i[x509_certificate key_name])
    end

    it "raises HankoXml::ConfigurationError for an unknown clause" do
      expect { described_class.coerce(:not_a_clause) }.to raise_error(HankoXml::ConfigurationError)
    end

    it "returns a frozen Array" do
      expect(described_class.coerce(:x509_certificate)).to be_frozen
    end
  end

  describe "Parsed" do
    it "is frozen and exposes key_names / certificates" do
      parsed = described_class::Parsed.new(key_names: ["idp-1"], certificates: ["PEM"])
      expect(parsed.key_names).to eq(["idp-1"])
      expect(parsed.certificates).to eq(["PEM"])
      expect(parsed).to be_frozen
    end
  end
end
