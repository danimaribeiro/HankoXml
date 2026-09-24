# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "pathname"

# #96: a Node passed to sign/sign! is the default reference target
# (API_CONTRACT.md §6.2), instead of silently signing the whole document.
RSpec.describe "Signer#sign with a Node (#96)" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:key_pem) { fixtures.join("signer.key").read }
  let(:cert_pem) { fixtures.join("signer.crt").read }
  let(:signer) { HankoXml::Signer.new(key: key_pem, certificate: cert_pem) }
  let(:doc) { Nokogiri::XML(%(<Envelope><Data Id="d1">A</Data><Other>B</Other></Envelope>)) }
  let(:ds) { { "ds" => HankoXml::NS["ds"] } }

  def reference_uris(xml)
    Nokogiri::XML(xml.to_s).xpath("//ds:Reference/@URI", ds).map(&:value)
  end

  it "signs \"#<Id>\" when given a non-root element with an Id" do
    signed = signer.sign(doc.at("Data"))

    expect(reference_uris(signed)).to eq(["#d1"])
    verification = HankoXml::Verifier.new(certificate: cert_pem, policy: HankoXml::Policy.fragment).verify(signed.to_s)
    expect(verification.valid?).to be true
    expect(verification.signed?(verification.document.at("Data"))).to be true
    expect(verification.signed?(verification.document.at("Other"))).to be false
    expect(doc.at_xpath("//ds:Signature", ds)).to be_nil
  end

  it "does the same for sign!, in place" do
    signer.sign!(doc.at("Data"))

    expect(reference_uris(doc)).to eq(["#d1"])
  end

  it "signs the whole document for the root element, as before" do
    expect(reference_uris(signer.sign(doc.root))).to eq([""])
  end

  it "keeps the Signer's own references: when it has them" do
    explicit = HankoXml::Signer.new(key: key_pem, certificate: cert_pem, references: [""])

    expect(reference_uris(explicit.sign(doc.at("Data")))).to eq([""])
  end

  it "raises ConfigurationError for an element without an Id instead of signing something else" do
    expect { signer.sign(doc.at("Other")) }
      .to raise_error(HankoXml::ConfigurationError, /Other node .* has no .* attribute/)
  end
end
