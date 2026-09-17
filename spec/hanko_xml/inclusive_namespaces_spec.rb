# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "pathname"

# #61: ec:InclusiveNamespaces PrefixList on exclusive c14n, in the SAML 2.0
# shape that needs it -- a signed Assertion fragment whose xsi:type value
# uses the xs prefix declared on the enclosing Response.
RSpec.describe "Exclusive c14n InclusiveNamespaces" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:signer_key_pem) { fixtures.join("signer.key").read }
  let(:signer_cert_pem) { fixtures.join("signer.crt").read }
  let(:other_cert_pem) { fixtures.join("other.crt").read }
  let(:saml_ns) { { "saml" => "urn:oasis:names:tc:SAML:2.0:assertion" } }
  let(:ec_ns) { { "ds" => HankoXml::NS["ds"], "ec" => HankoXml::Transform::EXC_C14N_NS } }
  let(:xs_binding) { %(xmlns:xs="http://www.w3.org/2001/XMLSchema") }
  let(:xs_rebound) { %(xmlns:xs="urn:attacker:types") }

  let(:unsigned_response) do
    <<~XML
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" #{xs_binding} ID="response-1"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="assertion-1"><saml:Issuer>https://idp.example.test</saml:Issuer><saml:AttributeStatement><saml:Attribute Name="role"><saml:AttributeValue xsi:type="xs:string">admin</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>
    XML
  end

  def signer(inclusive_prefixes)
    HankoXml::Signer.new(
      key: signer_key_pem,
      certificate: signer_cert_pem,
      policy: HankoXml::Policy.fragment,
      placement: HankoXml::Placement.after("//saml:Assertion/saml:Issuer", namespaces: saml_ns),
      references: [
        HankoXml::Reference.new(
          uri: "#assertion-1",
          transforms: [:enveloped_signature, HankoXml::Transform.exc_c14n(inclusive_prefixes: inclusive_prefixes)]
        )
      ]
    )
  end

  def verify(xml, certificate: signer_cert_pem)
    HankoXml.verify(xml, certificate: certificate, policy: HankoXml::Policy.fragment)
  end

  describe "signing" do
    it "emits ec:InclusiveNamespaces inside the exclusive c14n Transform" do
      template = signer(%w[xs #default]).template(Nokogiri::XML(unsigned_response))
      node = template.at_xpath(".//ds:Transform/ec:InclusiveNamespaces", ec_ns)

      expect(node).not_to be_nil
      expect(node["PrefixList"]).to eq("xs #default")
      expect(node.parent["Algorithm"]).to eq(HankoXml::Transform::EXC_C14N_NS)
    end

    it "emits nothing extra without inclusive_prefixes" do
      template = signer([]).template(Nokogiri::XML(unsigned_response))
      expect(template.at_xpath(".//ec:InclusiveNamespaces", ec_ns)).to be_nil
    end

    it "produces a signature that verifies and covers the Assertion" do
      result = verify(signer(%w[xs]).sign(unsigned_response).to_s)

      expect(result.errors).to be_empty
      expect(result.valid?).to be true
      expect(result.at_signed("//saml:AttributeValue", saml_ns).text).to eq("admin")
    end

    it "binds the listed prefix into the digest" do
      signed = signer(%w[xs]).sign(unsigned_response).to_s
      expect(verify(signed.sub(xs_binding, xs_rebound)).valid?).to be false
    end

    it "leaves an unlisted, unused-by-name prefix out of the digest" do
      signed = signer([]).sign(unsigned_response).to_s
      expect(verify(signed.sub(xs_binding, xs_rebound)).valid?).to be true
    end
  end

  describe "verifying an IdP-shaped fixture" do
    # PrefixList on both CanonicalizationMethod and the Reference transform,
    # Signature placed after the Assertion's Issuer. Signed from the template
    # through Native.sign, not HankoXml's Template builder.
    let(:signed_xml) { fixtures.join("signed_saml_inclusive_namespaces.xml").read }

    it "verifies under Policy.fragment with the default schema check" do
      result = verify(signed_xml)

      expect(result.errors).to be_empty
      expect(result.valid?).to be true
      expect(result.signed?(result.document.root)).to be false
      expect(result.at_signed("//saml:AttributeValue", saml_ns).text).to eq("admin")
    end

    it "rejects it against the wrong certificate" do
      expect(verify(signed_xml, certificate: other_cert_pem).valid?).to be false
    end

    it "rejects it when the inclusive prefix is rebound on the Response" do
      expect(signed_xml).to include(xs_binding)
      expect(verify(signed_xml.sub(xs_binding, xs_rebound)).valid?).to be false
    end

    it "rejects it when the PrefixList itself is edited" do
      expect(verify(signed_xml.sub('PrefixList="xs"', 'PrefixList="xsi"')).valid?).to be false
    end

    it "still schema-checks the InclusiveNamespaces element" do
      tampered = signed_xml.sub('PrefixList="xs"/>', 'PrefixList="xs" Unexpected="1"/>')
      result = verify(tampered)

      expect(result.valid?).to be false
      expect(result.errors.map(&:class)).to eq([HankoXml::SchemaError])
    end
  end
end
