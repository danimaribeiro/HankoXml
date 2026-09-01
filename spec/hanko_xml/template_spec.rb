# frozen_string_literal: true

require "nokogiri"
require "openssl"
require "pathname"

RSpec.describe HankoXml::Template do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:key_pem) { fixtures.join("signer.key").read }
  let(:doc) { Nokogiri::XML("<Envelope xmlns=\"urn:x\"><Data>hi</Data></Envelope>") }

  def signer(**overrides)
    HankoXml::Signer.new(key: key_pem, **overrides)
  end

  it "builds a whole-document enveloped <Signature> by default" do
    sig = signer.template(doc)

    expect(sig.name).to eq("Signature")
    expect(sig.namespace.href).to eq(HankoXml::NS["ds"])
    expect(sig.at_xpath("ds:SignedInfo/ds:CanonicalizationMethod", HankoXml::NS)["Algorithm"])
      .to eq("http://www.w3.org/2001/10/xml-exc-c14n#")
    expect(sig.at_xpath("ds:SignedInfo/ds:SignatureMethod", HankoXml::NS)["Algorithm"])
      .to eq("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

    reference = sig.at_xpath("ds:SignedInfo/ds:Reference", HankoXml::NS)
    expect(reference["URI"]).to eq("")
    expect(reference.at_xpath("ds:Transforms/ds:Transform", HankoXml::NS)["Algorithm"])
      .to eq("http://www.w3.org/2000/09/xmldsig#enveloped-signature")
    expect(reference.at_xpath("ds:DigestMethod", HankoXml::NS)["Algorithm"])
      .to eq("http://www.w3.org/2001/04/xmlenc#sha256")
    expect(reference.at_xpath("ds:DigestValue", HankoXml::NS).content).to eq("")
  end

  it "leaves SignatureValue empty" do
    sig = signer.template(doc)
    expect(sig.at_xpath("ds:SignatureValue", HankoXml::NS).content).to eq("")
  end

  it "builds an empty <X509Data/> for the default key_info: [:x509_certificate]" do
    sig = signer.template(doc)
    x509_data = sig.at_xpath("ds:KeyInfo/ds:X509Data", HankoXml::NS)
    expect(x509_data).not_to be_nil
    expect(x509_data.children).to be_empty
  end

  it "omits <KeyInfo> entirely when key_info: []" do
    sig = signer(key_info: []).template(doc)
    expect(sig.at_xpath("ds:KeyInfo", HankoXml::NS)).to be_nil
  end

  it "builds a <KeyName/> for the :key_name clause" do
    sig = signer(key_info: [:key_name]).template(doc)
    expect(sig.at_xpath("ds:KeyInfo/ds:KeyName", HankoXml::NS)).not_to be_nil
  end

  it "reflects custom references built via the block form" do
    s = HankoXml::Signer.new(key: key_pem) do |cfg|
      cfg.reference "#payload-1", transforms: %i[enveloped_signature c14n], digest_method: :sha1
    end

    sig = s.template(doc)
    reference = sig.at_xpath("ds:SignedInfo/ds:Reference", HankoXml::NS)
    expect(reference["URI"]).to eq("#payload-1")
    expect(reference.xpath("ds:Transforms/ds:Transform", HankoXml::NS).map { |t| t["Algorithm"] })
      .to eq(["http://www.w3.org/2000/09/xmldsig#enveloped-signature",
              "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"])
  end

  it "sets Signature/@Id when signature_id: is given" do
    sig = signer(signature_id: "sig-1").template(doc)
    expect(sig["Id"]).to eq("sig-1")
  end

  it "does not insert the template into the document" do
    signer.template(doc)
    expect(doc.at_xpath("ds:Signature", HankoXml::NS)).to be_nil
  end

  it "works without raising when Nokogiri is present" do
    expect { signer.template(doc) }.not_to raise_error
  end
end
