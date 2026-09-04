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
    verification.send(:resolve_reference, reference)
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
end
