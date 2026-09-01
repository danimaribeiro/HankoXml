# frozen_string_literal: true

require "spec_helper"
require "xmlsec_rb/nokogiri_ext"

RSpec.describe "Nokogiri Core Extensions" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:unsigned_xml) { fixtures.join("template_detached.xml").read }
  let(:signed_xml) { fixtures.join("signed_detached.xml").read }
  let(:signer_cert_pem) { fixtures.join("signer.crt").read }
  let(:signer_key_pem) { fixtures.join("signer.key").read }

  it "adds #signature_valid? to Nokogiri::XML::Document" do
    doc = Nokogiri::XML(signed_xml)
    expect(doc.signature_valid?(certificate: signer_cert_pem)).to be true
  end

  it "adds #signatures and #signed? to Nokogiri::XML::Document" do
    doc = Nokogiri::XML(signed_xml)
    expect(doc.signed?).to be true
    expect(doc.signatures.size).to eq(1)

    unsigned_doc = Nokogiri::XML(unsigned_xml)
    expect(unsigned_doc.signed?).to be false
  end

  it "adds #sign to Nokogiri::XML::Document" do
    doc = Nokogiri::XML(unsigned_xml)
    signed_doc = doc.sign(key: signer_key_pem, certificate: signer_cert_pem)
    expect(signed_doc).to be_a(XmlsecRb::SignedDocument)
    expect(signed_doc.valid?(certificate: signer_cert_pem)).to be true
    
    # Original is untouched
    expect(doc.signed?).to be false
  end

  it "adds #sign! to Nokogiri::XML::Document" do
    doc = Nokogiri::XML(unsigned_xml)
    doc.sign!(key: signer_key_pem, certificate: signer_cert_pem)
    expect(doc.signed?).to be true
    expect(doc.signature_valid?(certificate: signer_cert_pem)).to be true
  end
end
