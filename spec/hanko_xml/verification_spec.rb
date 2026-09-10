# frozen_string_literal: true

require "spec_helper"
require "nokogiri"

RSpec.describe HankoXml::Verification do
  let(:digest_method) { "http://www.w3.org/2001/04/xmlenc#sha256" }
  let(:signature_method) { "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" }
  let(:canonicalization_method) { "http://www.w3.org/2001/10/xml-exc-c14n#" }

  def build_verification(doc:, uri:, id_attributes: %w[Id ID id], resolver: nil)
    described_class.new(
      valid: true,
      errors: [],
      signature_info: HankoXml::SignatureInfo.new(
        signature_method: signature_method,
        canonicalization_method: canonicalization_method,
        references: [{ uri: uri, digest_method: digest_method, transforms: [] }]
      ),
      signature_node: nil,
      document: doc,
      id_attributes: id_attributes,
      resolver: resolver
    )
  end

  def resolve(uri, **kwargs)
    verification = build_verification(uri: uri, **kwargs)
    reference = HankoXml::SignatureInfo::ReferenceInfo.new(uri: uri, digest_method: digest_method)
    verification.send(:resolve_reference, reference, 0)
  end

  it "does not allow XPath injection via reference ID values" do
    doc = Nokogiri::XML("<root><signed Id=\"safe\"/><wrapped Id=\"attacker\"/></root>")
    expect(resolve("#' or '1'='1", doc: doc)).to be_nil
  end

  it "resolves fragment references using configured id_attributes" do
    doc = Nokogiri::XML("<root><target CustomId=\"payload-1\"/><other Id=\"payload-1\"/></root>")
    node = resolve("#payload-1", doc: doc, id_attributes: ["CustomId"])

    expect(node["CustomId"]).to eq("payload-1")
  end

  it "uses the configured resolver for fragment lookup" do
    doc = Nokogiri::XML("<root><target data-ref=\"payload-1\"/></root>")
    seen_id = nil
    resolver = lambda do |document, id|
      seen_id = id
      document.at_xpath("//*[@data-ref=$id]", nil, id: id)
    end
    node = resolve("#payload-1", doc: doc, id_attributes: [], resolver: resolver)

    expect(node["data-ref"]).to eq("payload-1")
    expect(seen_id).to eq("payload-1")
  end

  it "computes #references and #signed? without raising FrozenError" do
    doc = Nokogiri::XML("<root><signed Id=\"payload-1\"/></root>")
    verification = build_verification(doc: doc, uri: "#payload-1")

    expect(verification.references.map(&:uri)).to eq(["#payload-1"])
    expect(verification).to be_signed(doc.at_xpath("//signed"))
  end

  it "flags ResolutionMismatch when the resolver and id_attributes disagree" do
    doc = Nokogiri::XML("<root><a Id=\"x\"/><b data-ref=\"x\"/></root>")
    resolver = ->(document, id) { document.at_xpath("//*[@data-ref=$id]", nil, id: id) }
    verification = build_verification(doc: doc, uri: "#x", id_attributes: ["Id"], resolver: resolver)

    expect(verification).not_to be_valid
    expect(verification.errors).to include(an_instance_of(HankoXml::ResolutionMismatch))
    expect(verification).not_to be_signed(doc.at_xpath("//a"))
  end

  it "does not flag ResolutionMismatch when the resolver and id_attributes agree" do
    doc = Nokogiri::XML("<root><a Id=\"x\"/></root>")
    resolver = ->(document, id) { document.at_xpath("//*[@Id=$id]", nil, id: id) }
    verification = build_verification(doc: doc, uri: "#x", id_attributes: ["Id"], resolver: resolver)

    expect(verification).to be_valid
    expect(verification.errors).to be_empty
  end

  it "does not flag ResolutionMismatch when id_attributes is empty (fully delegated to the resolver)" do
    doc = Nokogiri::XML("<root><target data-ref=\"payload-1\"/></root>")
    resolver = ->(document, id) { document.at_xpath("//*[@data-ref=$id]", nil, id: id) }
    verification = build_verification(doc: doc, uri: "#payload-1", id_attributes: [], resolver: resolver)

    expect(verification).to be_valid
    expect(verification.errors).to be_empty
  end

  it "prefers native element indexes over Ruby ID XPath" do
    doc = Nokogiri::XML("<root><order Id=\"inv-1\"/><invoice Id=\"inv-1\"/></root>")
    # Document-order: root=0, order=1, invoice=2. Point at invoice the way
    # xmlsec's ID table would after a DTD typed the Invoice element.
    verification = described_class.new(
      valid: true,
      errors: [],
      signature_info: HankoXml::SignatureInfo.new(
        signature_method: signature_method,
        canonicalization_method: canonicalization_method,
        references: [{ uri: "#inv-1", digest_method: digest_method, transforms: [] }]
      ),
      signature_node: nil,
      document: doc,
      id_attributes: ["Id"],
      reference_element_indexes: [2]
    )

    expect(verification.references.first.node).to eq(doc.at_xpath("//invoice"))
    expect(verification).to be_signed(doc.at_xpath("//invoice"))
    expect(verification).not_to be_signed(doc.at_xpath("//order"))
  end

  it "returns false from #signed? when the verification is invalid" do
    doc = Nokogiri::XML("<root><signed Id=\"payload-1\"/></root>")
    verification = described_class.new(
      valid: false,
      errors: [HankoXml::VerificationError.new("nope")],
      signature_info: HankoXml::SignatureInfo.new(
        signature_method: signature_method,
        canonicalization_method: canonicalization_method,
        references: [{ uri: "#payload-1", digest_method: digest_method, transforms: [] }]
      ),
      signature_node: nil,
      document: doc
    )

    expect(verification).not_to be_signed(doc.at_xpath("//signed"))
  end
end
