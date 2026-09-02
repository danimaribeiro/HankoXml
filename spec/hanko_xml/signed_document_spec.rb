# frozen_string_literal: true

require "spec_helper"

RSpec.describe HankoXml::SignedDocument do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:signed_xml) { fixtures.join("signed_exc_c14n.xml").read }
  let(:signer_cert_pem) { fixtures.join("signer.crt").read }

  it "preserves bytes exactly when serialized via #to_xml" do
    doc = Nokogiri::XML(signed_xml)
    # Nokogiri's standard serialization can be safe or unsafe depending on
    # exactly what is in the document. SignedDocument guarantees AS_XML without format.
    signed_doc = HankoXml::SignedDocument.new(doc)
    safe = signed_doc.to_xml
    expect(safe).to eq(doc.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML))
    expect(HankoXml.verify(safe, certificate: signer_cert_pem).valid?).to be true
  end

  it "delegates #signatures" do
    doc = Nokogiri::XML(signed_xml)
    signed_doc = HankoXml::SignedDocument.new(doc)
    expect(signed_doc.signatures.size).to eq(1)
  end

  it "delegates #valid?" do
    doc = Nokogiri::XML(signed_xml)
    signed_doc = HankoXml::SignedDocument.new(doc)
    expect(signed_doc.valid?(certificate: signer_cert_pem)).to be true
  end
end
