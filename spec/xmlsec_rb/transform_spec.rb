# frozen_string_literal: true

RSpec.describe XmlsecRb::Transform do
  it "resolves a Symbol to its URI" do
    transform = described_class.new(:enveloped_signature)
    expect(transform.uri).to eq("http://www.w3.org/2000/09/xmldsig#enveloped-signature")
    expect(transform.name).to eq(:enveloped_signature)
  end

  it "accepts a URI String verbatim" do
    transform = described_class.new("http://www.w3.org/2001/10/xml-exc-c14n#")
    expect(transform.name).to eq(:exc_c14n)
  end

  it "raises XmlsecRb::ConfigurationError for an unknown algorithm" do
    expect { described_class.new(:not_a_real_transform) }.to raise_error(XmlsecRb::ConfigurationError)
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

  it ".coerce passes through an existing Transform" do
    transform = described_class.new(:c14n)
    expect(described_class.coerce(transform)).to equal(transform)
  end
end
