# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require "pathname"

# #86: Xades::Verifier reads XAdES 1.2.2 and 1.1.1 signed properties too, with
# every structural check from #58. Xades::Signer still writes only 1.3.2.
RSpec.describe "XAdES 1.1.1 and 1.2.2 signed properties (#86)" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:key_pem) { fixtures.join("signer.key").read }
  let(:cert_pem) { fixtures.join("signer.crt").read }
  let(:certificate) { OpenSSL::X509::Certificate.new(cert_pem) }
  let(:v122) { "http://uri.etsi.org/01903/v1.2.2#" }
  let(:v111) { "http://uri.etsi.org/01903/v1.1.1#" }
  let(:ds) { HankoXml::NS["ds"] }

  # A legacy XAdES signature over <Invoice>, signed through an adopted
  # template, since Xades::Signer writes only 1.3.2.
  def legacy_signed(namespace:, type: HankoXml::Xades::SIGNED_PROPERTIES_TYPE, target: "#S")
    type_attribute = type ? %( Type="#{type}") : ""
    digest = OpenSSL::Digest::SHA256.base64digest(certificate.to_der)
    template = <<~XML
      <Invoice xmlns="urn:x"><Total>150.00</Total><ds:Signature xmlns:ds="#{ds}" Id="S"><ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI=""><ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference>
      <ds:Reference URI="#sp"#{type_attribute}><ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference>
      </ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data/></ds:KeyInfo>
      <ds:Object><xa:QualifyingProperties xmlns:xa="#{namespace}" Target="#{target}">
      <xa:SignedProperties Id="sp"><xa:SignedSignatureProperties>
      <xa:SigningTime>2016-04-21T11:32:34Z</xa:SigningTime>
      <xa:SigningCertificate><xa:Cert><xa:CertDigest>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>#{digest}</ds:DigestValue>
      </xa:CertDigest><xa:IssuerSerial><ds:X509IssuerName>#{certificate.issuer.to_s(OpenSSL::X509::Name::RFC2253)}</ds:X509IssuerName>
      <ds:X509SerialNumber>#{certificate.serial}</ds:X509SerialNumber></xa:IssuerSerial></xa:Cert></xa:SigningCertificate>
      <xa:SignerRole><xa:ClaimedRoles><xa:ClaimedRole>Notary</xa:ClaimedRole></xa:ClaimedRoles></xa:SignerRole>
      </xa:SignedSignatureProperties></xa:SignedProperties></xa:QualifyingProperties></ds:Object>
      </ds:Signature></Invoice>
    XML
    references = [
      HankoXml::Reference.new(uri: "", transforms: %i[enveloped_signature exc_c14n]),
      HankoXml::Reference.new(uri: "#sp", transforms: %i[exc_c14n], type: type)
    ]
    HankoXml::Signer.new(key: key_pem, certificate: cert_pem, references: references).sign(template).to_s
  end

  def verify(document)
    HankoXml::Xades::Verifier.new(certificate: cert_pem).verify(document)
  end

  def expect_xades_error(result, message)
    expect(result.valid?).to be false
    expect(result.errors.last).to be_a(HankoXml::XadesError)
    expect(result.errors.last.message).to match(message)
  end

  {
    "1.2.2" => "http://uri.etsi.org/01903/v1.2.2#",
    "1.1.1" => "http://uri.etsi.org/01903/v1.1.1#"
  }.each do |version, namespace|
    it "reads #{version} signed properties, with the generic or the #{version} Reference Type" do
      [HankoXml::Xades::SIGNED_PROPERTIES_TYPE, "#{namespace}SignedProperties"].each do |type|
        result = verify(legacy_signed(namespace: namespace, type: type))

        expect(result.errors).to be_empty
        expect(result.signed_properties.signing_time).to eq(Time.utc(2016, 4, 21, 11, 32, 34))
        expect(result.signed_properties.claimed_roles).to eq(["Notary"])
      end
    end
  end

  it "finds an untyped SignedProperties Reference by the element xmlsec digested" do
    expect(verify(legacy_signed(namespace: v122, type: nil)).errors).to be_empty
  end

  it "refuses a Reference Type naming another version than the QualifyingProperties" do
    result = verify(legacy_signed(namespace: v122, type: "#{v111}SignedProperties"))
    expect_xades_error(result, /names another XAdES version/)
  end

  it "accepts the bare Target older signers wrote, but only in the older namespaces" do
    expect(verify(legacy_signed(namespace: v122, target: "S")).errors).to be_empty
    expect_xades_error(verify(legacy_signed(namespace: HankoXml::Xades::NS, target: "S")),
                       /does not target this <Signature>/)
    expect_xades_error(verify(legacy_signed(namespace: v122, target: "Other")), /does not target this <Signature>/)
  end

  it "refuses QualifyingProperties in two XAdES namespaces" do
    signed = legacy_signed(namespace: v122)
    decoy = %(<ds:Object><xades:QualifyingProperties xmlns:xades="#{HankoXml::Xades::NS}" Target="#S"/></ds:Object>)
    attacked = signed.sub("</ds:Signature>", "#{decoy}</ds:Signature>")
    expect(attacked).not_to eq(signed)

    expect_xades_error(verify(attacked), /exactly one <xades:QualifyingProperties>/)
  end

  it "doesn't treat an unknown namespace as XAdES" do
    signed = legacy_signed(namespace: "http://uri.etsi.org/01903/v9.9.9#", type: nil)
    expect_xades_error(verify(signed), /exactly one <Reference> of Type/)
  end
end
