# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require "pathname"

# S-01: a document-supplied <KeyValue> / <DEREncodedKeyValue> / <RetrievalMethod>
# must not become the verification key. Trusted cert PEMs pin signKey, and an
# empty trust list fails closed.
RSpec.describe "S-01 KeyValue trust" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:signer_key_pem) { fixtures.join("signer.key").read }
  let(:signer_cert_pem) { fixtures.join("signer.crt").read }
  let(:other_key_pem) { fixtures.join("other.key").read }
  let(:other_cert_pem) { fixtures.join("other.crt").read }
  let(:id_attrs) { %w[Id ID id] }
  let(:ds) { "http://www.w3.org/2000/09/xmldsig#" }
  let(:dsig11) { "http://www.w3.org/2009/xmldsig11#" }

  def key_value_template
    <<~XML
      <Envelope xmlns="urn:probe"><Data>Hello</Data>
        <Signature xmlns="#{ds}">
          <SignedInfo>
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="">
              <Transforms>
                <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
              </Transforms>
              <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
              <DigestValue/>
            </Reference>
          </SignedInfo>
          <SignatureValue/>
          <KeyInfo><KeyValue/></KeyInfo>
        </Signature>
      </Envelope>
    XML
  end

  def no_keyinfo_template
    key_value_template.sub(%r{<KeyInfo><KeyValue/></KeyInfo>\n}, "")
  end

  def sign_with(template, key_pem)
    HankoXml::Native.sign(template, key_pem, [], id_attrs, 0)
  end

  def forged_by_other(template = key_value_template)
    sign_with(template, other_key_pem)
  end

  def parse(xml)
    Nokogiri::XML(xml)
  end

  describe "Native.verify" do
    it "does not accept an attacker KeyValue when the trusted PEM is signer.crt (K1)" do
      result = HankoXml::Native.verify(forged_by_other, [signer_cert_pem], [], id_attrs, 0)

      expect(result[:status]).not_to eq(:succeeded)
    end

    it "fails closed when the trust list is empty (K2)" do
      result = HankoXml::Native.verify(forged_by_other, [], [], id_attrs, 0)

      expect(result[:status]).not_to eq(:succeeded)
      expect(result[:errors].join).to match(/no trusted key or certificate/)
    end

    it "rejects a forged document that carries both attacker X509Certificate and KeyValue (K4)" do
      doc = parse(forged_by_other)
      key_info = doc.at_xpath("//ds:KeyInfo", HankoXml::NS)
      x509 = doc.create_element("X509Data")
      x509.namespace = key_info.namespace
      cert = doc.create_element("X509Certificate")
      cert.namespace = key_info.namespace
      cert.content = other_cert_pem.gsub(/-----(BEGIN|END) CERTIFICATE-----/, "").gsub(/\s+/, "")
      x509.add_child(cert)
      key_info.add_child(x509)

      result = HankoXml::Native.verify(doc.to_xml, [signer_cert_pem], [], id_attrs, 0)

      expect(result[:status]).not_to eq(:succeeded)
    end

    it "rejects a forged document with <DEREncodedKeyValue> (K5)" do
      doc = parse(forged_by_other)
      key_info = doc.at_xpath("//ds:KeyInfo", HankoXml::NS)
      key_info.children.remove
      der = Nokogiri::XML::Node.new("DEREncodedKeyValue", doc)
      der.default_namespace = dsig11
      der.content = [OpenSSL::PKey::RSA.new(other_key_pem).public_key.to_der].pack("m0")
      key_info.add_child(der)

      result = HankoXml::Native.verify(doc.to_xml, [signer_cert_pem], [], id_attrs, 0)

      expect(result[:status]).not_to eq(:succeeded)
    end

    it "rejects a forged document with RetrievalMethod pointing at an in-document KeyValue (K6)" do
      doc = parse(forged_by_other)
      sig = doc.at_xpath("//ds:Signature", HankoXml::NS)
      key_info = doc.at_xpath("//ds:KeyInfo", HankoXml::NS)
      key_value = key_info.at_xpath("./ds:KeyValue", HankoXml::NS)
      key_value["Id"] = "k"
      key_value.unlink

      key_info.children.remove
      retrieval = doc.create_element("RetrievalMethod")
      retrieval.namespace = key_info.namespace
      retrieval["URI"] = "#k"
      retrieval["Type"] = "#{ds}RSAKeyValue"
      key_info.add_child(retrieval)

      object = doc.create_element("Object")
      object.namespace = sig.namespace
      object.add_child(key_value)
      sig.add_child(object)

      result = HankoXml::Native.verify(doc.to_xml, [signer_cert_pem], [], id_attrs, 0)

      expect(result[:status]).not_to eq(:succeeded)
    end

    it "verifies a legit document with no KeyInfo against signer.crt (K7)" do
      signed = sign_with(no_keyinfo_template, signer_key_pem)
      result = HankoXml::Native.verify(signed, [signer_cert_pem], [], id_attrs, 0)

      expect(result[:status]).to eq(:succeeded)
    end

    it "rejects a legit document when trusted is a different certificate (K8)" do
      signed = sign_with(key_value_template, signer_key_pem)
      result = HankoXml::Native.verify(signed, [other_cert_pem], [], id_attrs, 0)

      expect(result[:status]).not_to eq(:succeeded)
    end

    it "verifies a legit KeyValue signature against the signer certificate" do
      signed = sign_with(key_value_template, signer_key_pem)
      result = HankoXml::Native.verify(signed, [signer_cert_pem], [], id_attrs, 0)

      expect(result[:status]).to eq(:succeeded)
    end

    it "accepts any one of several pinned certificates" do
      signed = sign_with(key_value_template, signer_key_pem)
      result = HankoXml::Native.verify(signed, [other_cert_pem, signer_cert_pem], [], id_attrs, 0)

      expect(result[:status]).to eq(:succeeded)
    end
  end

  describe "HankoXml.verify" do
    it "rejects a KeyValue forgery with certificate: signer.crt (K3)" do
      result = HankoXml.verify(forged_by_other, certificate: signer_cert_pem)

      expect(result.valid?).to be false
      expect(result.errors).not_to be_empty
    end

    it "rejects a KeyValue forgery with certificates: [signer.crt]" do
      result = HankoXml.verify(forged_by_other, certificates: [signer_cert_pem])

      expect(result.valid?).to be false
    end

    it "rejects a KeyValue forgery with a cert-valued keys: entry" do
      doc = parse(forged_by_other)
      key_info = doc.at_xpath("//ds:KeyInfo", HankoXml::NS)
      name = doc.create_element("KeyName")
      name.namespace = key_info.namespace
      name.content = "alice"
      key_info.prepend_child(name)

      result = HankoXml.verify(doc, keys: { "alice" => signer_cert_pem })

      expect(result.valid?).to be false
    end

    it "still accepts a genuine signature via certificate:" do
      signed = sign_with(key_value_template, signer_key_pem)

      expect(HankoXml.verify(signed, certificate: signer_cert_pem).valid?).to be true
    end
  end
end
