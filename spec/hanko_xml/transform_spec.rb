# frozen_string_literal: true

RSpec.describe HankoXml::Transform do
  it "resolves a Symbol to its URI" do
    transform = described_class.new(:enveloped_signature)
    expect(transform.uri).to eq("http://www.w3.org/2000/09/xmldsig#enveloped-signature")
    expect(transform.name).to eq(:enveloped_signature)
  end

  it "accepts a URI String verbatim" do
    transform = described_class.new("http://www.w3.org/2001/10/xml-exc-c14n#")
    expect(transform.name).to eq(:exc_c14n)
  end

  it "raises HankoXml::ConfigurationError for an unknown algorithm" do
    expect { described_class.new(:not_a_real_transform) }.to raise_error(HankoXml::ConfigurationError)
  end

  it "#enveloped_signature? is true only for the enveloped-signature transform" do
    expect(described_class.new(:enveloped_signature).enveloped_signature?).to be true
    expect(described_class.new(:c14n).enveloped_signature?).to be false
  end

  it "is frozen and value-comparable" do
    a = described_class.new(:c14n)
    b = described_class.new(:c14n)
    expect(a).to be_frozen
    expect(a).to eq(b)
  end

  describe "inclusive_prefixes (#61)" do
    it "defaults to none" do
      expect(described_class.new(:exc_c14n).inclusive_prefixes).to eq([])
    end

    it ".exc_c14n builds an exclusive c14n transform with a PrefixList" do
      transform = described_class.exc_c14n(inclusive_prefixes: [:xs, "#default"])
      expect(transform.name).to eq(:exc_c14n)
      expect(transform.inclusive_prefixes).to eq(%w[xs #default])
      expect(transform.inclusive_prefixes).to be_frozen
      expect(described_class.exc_c14n(with_comments: true).name).to eq(:exc_c14n_with_comments)
    end

    it "is part of equality" do
      expect(described_class.exc_c14n(inclusive_prefixes: %w[xs]))
        .to eq(described_class.new(:exc_c14n, inclusive_prefixes: %w[xs]))
      expect(described_class.exc_c14n(inclusive_prefixes: %w[xs])).not_to eq(described_class.new(:exc_c14n))
    end

    it "rejects prefixes on a transform that is not exclusive c14n" do
      expect { described_class.new(:c14n, inclusive_prefixes: %w[xs]) }
        .to raise_error(HankoXml::ConfigurationError, /exclusive c14n/)
    end

    it "rejects values that are not namespace prefixes" do
      ["x s", "1xs", "xs:string", "", "#other"].each do |bad|
        expect { described_class.exc_c14n(inclusive_prefixes: [bad]) }
          .to raise_error(HankoXml::ConfigurationError, /not namespace prefixes/)
      end
    end
  end

  it "has .c14n and .enveloped_signature shorthands" do
    expect(described_class.c14n).to eq(described_class.new(:c14n))
    expect(described_class.enveloped_signature).to eq(described_class.new(:enveloped_signature))
  end

  it ".coerce passes through an existing Transform" do
    transform = described_class.new(:c14n)
    expect(described_class.coerce(transform)).to equal(transform)
  end
end
