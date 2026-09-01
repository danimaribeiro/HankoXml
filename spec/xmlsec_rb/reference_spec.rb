# frozen_string_literal: true

RSpec.describe XmlsecRb::Reference do
  it "defaults to a whole-document enveloped reference" do
    ref = described_class.new
    expect(ref.uri).to eq("")
    expect(ref.transforms.map(&:name)).to eq([:enveloped_signature])
    expect(ref.digest_method).to eq(:sha256)
    expect(ref.enveloped?).to be true
  end

  it "#fragment? / #target_id for a #id URI" do
    ref = described_class.new(uri: "#payload-1")
    expect(ref.fragment?).to be true
    expect(ref.target_id).to eq("payload-1")
  end

  it "#fragment? is false for the whole-document URI" do
    expect(described_class.new(uri: "").fragment?).to be false
  end

  it "#digest_method_uri resolves the Symbol" do
    ref = described_class.new(digest_method: :sha512)
    expect(ref.digest_method_uri).to eq("http://www.w3.org/2001/04/xmlenc#sha512")
  end

  it "is frozen" do
    expect(described_class.new).to be_frozen
  end

  describe ".coerce" do
    it "wraps a String as a fragment/whole-document URI" do
      ref = described_class.coerce("#foo")
      expect(ref.uri).to eq("#foo")
    end

    it "expands a Hash of keywords" do
      ref = described_class.coerce(uri: "#foo", digest_method: :sha1)
      expect(ref.digest_method).to eq(:sha1)
    end

    it "passes through an existing Reference" do
      ref = described_class.new
      expect(described_class.coerce(ref)).to equal(ref)
    end
  end
end
