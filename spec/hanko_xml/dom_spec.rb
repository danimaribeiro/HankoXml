# frozen_string_literal: true

require "nokogiri"
require "openssl"
require "pathname"

RSpec.describe HankoXml::Dom do
  it "reports Nokogiri as available in this suite" do
    expect(described_class.available?).to be true
  end

  it "#document? / #node? / #certificate? / #pkey? classify Nokogiri/OpenSSL objects" do
    doc = Nokogiri::XML("<a/>")
    expect(described_class.document?(doc)).to be true
    expect(described_class.node?(doc.root)).to be true
    expect(described_class.document?("not a doc")).to be false

    cert = OpenSSL::X509::Certificate.new(File.read(Pathname.new(__dir__).join("..", "fixtures", "signer.crt")))
    expect(described_class.certificate?(cert)).to be true

    key = OpenSSL::PKey::RSA.new(File.read(Pathname.new(__dir__).join("..", "fixtures", "signer.key")))
    expect(described_class.pkey?(key)).to be true
  end

  describe "#require!" do
    it "does not raise when Nokogiri is available" do
      expect { described_class.require!("some capability") }.not_to raise_error
    end
  end

  describe "#capabilities" do
    it "reports every capability true when Nokogiri is loaded" do
      caps = described_class.capabilities
      expect(caps[:sign]).to be true
      expect(caps[:coverage_checks]).to be true
      expect(caps[:schema]).to be true
    end
  end
end
