# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"

RSpec.describe "ID resolution (S-03 / #28)" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:signer_key) { OpenSSL::PKey::RSA.new(fixtures.join("signer.key").read) }
  let(:signer_cert) { fixtures.join("signer.crt") }

  # X1: DTD ID typing makes xmlsec digest the Invoice while Ruby XPath used to
  # prefer the earlier Order with the same Id value.
  def dtd_duplicate_id_xml
    <<~XML
      <?xml version="1.0"?>
      <!DOCTYPE Root [
        <!ATTLIST Invoice Id ID #IMPLIED>
      ]>
      <Root>
        <Order Id="inv-1"><Amount>1</Amount></Order>
        <Invoice Id="inv-1"><Amount>100</Amount></Invoice>
      </Root>
    XML
  end

  # This file's whole point is duplicate/ambiguous ID resolution (S-03), so
  # reject_duplicate_ids (S-06) -- which would otherwise reject the very
  # fixtures these specs need to construct -- is deliberately off here.
  def fragment_policy
    HankoXml::Policy.fragment.with(reject_duplicate_ids: false)
  end

  def sign_fragment(xml)
    HankoXml::Signer
      .new(
        key: signer_key,
        certificate: signer_cert,
        references: [HankoXml::Reference.new(uri: "#inv-1", transforms: [])],
        policy: fragment_policy
      )
      .sign(xml)
      .document
  end

  def verify_fragment(doc)
    HankoXml::Verifier.new(certificate: signer_cert, policy: fragment_policy).verify(doc)
  end

  it "X1: signed? follows xmlsec's DTD ID table, not document-order XPath" do
    signed = sign_fragment(dtd_duplicate_id_xml)
    result = verify_fragment(signed)

    order = signed.at_xpath("//Order")
    invoice = signed.at_xpath("//Invoice")

    expect(result).to be_valid
    expect(result.references.first.node).to eq(invoice)
    expect(result).to be_signed(invoice)
    expect(result).not_to be_signed(order)
    expect { result.at_signed("//Order") }.to raise_error(HankoXml::NotSignedError)
    expect(result.at_signed("//Invoice")).to eq(invoice)
  end

  it "X3: xml:id on the signed element wins over a plain Id attacker earlier in the document" do
    xml = <<~XML
      <?xml version="1.0"?>
      <Root>
        <Order Id="inv-1"><Amount>1</Amount></Order>
        <Invoice xml:id="inv-1"><Amount>100</Amount></Invoice>
      </Root>
    XML

    signed = sign_fragment(xml)
    result = verify_fragment(signed)

    order = signed.at_xpath("//Order")
    invoice = signed.at_xpath("//Invoice")

    expect(result).to be_valid
    expect(result.references.first.node).to eq(invoice)
    expect(result).to be_signed(invoice)
    expect(result).not_to be_signed(order)
  end

  it "empty URI still covers the document root via native element index" do
    signed = HankoXml::Signer
      .new(key: signer_key, certificate: signer_cert)
      .sign("<Envelope xmlns=\"urn:ex\"><Data>hi</Data></Envelope>")
      .document

    result = HankoXml::Verifier.new(certificate: signer_cert).verify(signed)

    expect(result).to be_valid
    expect(result.references.first.node).to eq(signed.root)
    expect(result).to be_signed(signed.at_xpath("//*[local-name()='Data']"))
  end

  it "flags ResolutionMismatch when resolver disagrees with the native locator" do
    signed = sign_fragment(dtd_duplicate_id_xml)
    resolver = ->(document, _id) { document.at_xpath("//Order") }

    result = HankoXml::Verifier
      .new(certificate: signer_cert, policy: fragment_policy, resolver: resolver)
      .verify(signed)

    expect(result).not_to be_valid
    expect(result.errors).to include(an_instance_of(HankoXml::ResolutionMismatch))
    # Native locator is still recorded on the reference; #signed? stays false
    # because the verification is invalid (API_CONTRACT §5.4).
    expect(result.references.first.node).to eq(signed.at_xpath("//Invoice"))
    expect(result).not_to be_signed(signed.at_xpath("//Invoice"))
    expect(result).not_to be_signed(signed.at_xpath("//Order"))
  end

  # S-20: xmlSecAddIDs(doc, root, ids) is handed the root itself, so the
  # root's own Id must be registered too, or URI="#rootId" would fail natively
  # while Ruby's XPath resolves it.
  describe "root-element Id (S-20)" do
    let(:root_id_xml) { %(<Envelope xmlns="urn:hanko_xml:example" Id="root-1"><Data>A</Data></Envelope>) }
    let(:signed_xml) do
      HankoXml.sign(root_id_xml, key: signer_key, certificate: signer_cert, references: ["#root-1"]).to_xml
    end

    it "signs and verifies a Reference to the root element's own Id under Policy.strict" do
      result = HankoXml::Verifier.new(certificate: signer_cert).verify(signed_xml)

      expect(result.valid?).to be true
      expect(result.covers_root?).to be true
      expect(result.signed?(result.document.root)).to be true
    end

    it "resolves the root Id natively to the root element" do
      native = HankoXml::Native.verify(signed_xml, [signer_cert.read], [], %w[Id ID id], 0, [])

      expect(native[:status]).to eq(:succeeded)
      expect(native[:reference_element_indexes]).to eq([0])
      expect(native[:reference_valid]).to eq([true])
    end

    it "detects tampering inside the root-referenced content" do
      expect(HankoXml.valid?(signed_xml.sub(">A<", ">B<"), certificate: signer_cert)).to be false
    end
  end
end
