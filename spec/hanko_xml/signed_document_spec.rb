# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "stringio"

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
    expect(HankoXml.valid?(safe, certificate: signer_cert_pem)).to be true
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

  describe "immutability (S-17)" do
    subject(:signed_doc) { HankoXml::SignedDocument.new(Nokogiri::XML(signed_xml)) }

    it "passes Verifier options such as policy: through #valid?" do
      tiny = HankoXml::Policy.strict.with(max_document_size: 16)
      expect(signed_doc.valid?(certificate: signer_cert_pem, policy: tiny)).to be false
    end

    it "delegates read-only Nokogiri methods" do
      expect(signed_doc.root).to equal(signed_doc.document.root)
      expect(signed_doc.at_xpath("//ds:SignatureValue", ds: HankoXml::NS["ds"])).not_to be_nil
      expect(signed_doc.xpath("//ds:Signature", ds: HankoXml::NS["ds"]).size).to eq(1)
      expect(signed_doc.errors).to eq([])
    end

    it "raises FrozenSignatureError from mutators, pointing at #document" do
      %i[add_child root= remove content=].each do |mutator|
        expect { signed_doc.public_send(mutator, Nokogiri::XML::Node.new("x", signed_doc.document)) }.to raise_error(
          HankoXml::FrozenSignatureError,
          /#document/
        )
      end
    end

    it "refuses to serialize after a node handed out by a reader was modified" do
      signed_doc.root.first_element_child.content = "tampered"

      expect { signed_doc.to_xml }.to raise_error(HankoXml::FrozenSignatureError, /modified after signing/)
      expect { signed_doc.to_s }.to raise_error(HankoXml::FrozenSignatureError)
      expect { signed_doc.bytes }.to raise_error(HankoXml::FrozenSignatureError)
      expect { signed_doc.write_to(StringIO.new) }.to raise_error(HankoXml::FrozenSignatureError)
    end

    it "keeps #document as an escape hatch serialized with HankoXml.serialize" do
      signed_doc.document.root.add_child(Nokogiri::XML::Node.new("Extra", signed_doc.document))

      expect { signed_doc.to_xml(declaration: false) }.to raise_error(HankoXml::FrozenSignatureError)
      expect(HankoXml.serialize(signed_doc.document)).to include("<Extra/>")
    end

    it "serializes normally, with or without the declaration, when unchanged" do
      expect(signed_doc.to_xml).to start_with("<?xml")
      expect(signed_doc.to_xml(declaration: false)).not_to start_with("<?xml")
      expect(HankoXml.valid?(signed_doc.to_xml(declaration: false), certificate: signer_cert_pem)).to be true
    end
  end
end
