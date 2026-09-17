# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require "pathname"

# #57: XAdES-B signing. xmlsec digests the SignedProperties Reference and signs;
# these specs pin the structure, that the properties are really signed, and
# conformance to the ETSI XAdES 1.3.2 schema.
RSpec.describe HankoXml::Xades::Signer do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:key_pem) { fixtures.join("signer.key").read }
  let(:cert_pem) { fixtures.join("signer.crt").read }
  let(:certificate) { OpenSSL::X509::Certificate.new(cert_pem) }
  let(:xml) { %(<Invoice xmlns="urn:x"><Total Id="total">150.00</Total></Invoice>) }
  let(:ns) { { "ds" => HankoXml::NS["ds"], "xades" => HankoXml::Xades::NS } }
  let(:signing_time) { Time.utc(2026, 9, 17, 14, 32, 5) }
  let(:full_options) do
    {
      claimed_roles: ["Chief Financial Officer"],
      signature_policy: { identifier: "urn:oid:2.16.76.1.7.1.6.2.3", description: "AD-RB",
                          digest_value: OpenSSL::Digest::SHA256.base64digest("policy document") },
      data_object_format: { mime_type: "text/xml", description: "Invoice", encoding: "UTF-8" }
    }
  end
  let(:schema) do
    path = fixtures.join("xades", "XAdES01903v132-202407.xsd")
    Nokogiri::XML::Schema.from_document(Nokogiri::XML(path.read, path.to_s))
  end

  def signer(**options)
    described_class.new(key: key_pem, certificate: cert_pem, signing_time: signing_time, **options)
  end

  def sign(source = xml, **options)
    signer(**options).sign(source).to_s
  end

  def verify(signed, **options)
    HankoXml.verify(signed, certificate: cert_pem, **options)
  end

  def schema_errors(signed)
    properties = Nokogiri::XML(signed).at_xpath("//xades:QualifyingProperties", ns)
    standalone = Nokogiri::XML::Document.new
    standalone.root = properties.dup(1, standalone)
    schema.validate(Nokogiri::XML(standalone.to_xml)).map(&:message)
  end

  describe "the signature" do
    let(:signed) { sign }
    let(:doc) { Nokogiri::XML(signed) }
    let(:signature) { doc.at_xpath("//ds:Signature", ns) }

    it "verifies under Policy.strict" do
      expect(verify(signed).valid?).to be true
    end

    it "signs the document and the SignedProperties, in that order" do
      references = signature.xpath("ds:SignedInfo/ds:Reference", ns)
      signed_properties = signature.at_xpath("ds:Object/xades:QualifyingProperties/xades:SignedProperties", ns)

      expect(references.map { |r| r["URI"] }).to eq(["", "##{signed_properties["Id"]}"])
      expect(references.last["Type"]).to eq("http://uri.etsi.org/01903#SignedProperties")
      expect(references.last.xpath("ds:Transforms/ds:Transform", ns).map { |t| t["Algorithm"] })
        .to eq(["http://www.w3.org/2001/10/xml-exc-c14n#"])
    end

    it "targets the <Signature> from QualifyingProperties" do
      qualifying = signature.at_xpath("ds:Object/xades:QualifyingProperties", ns)
      expect(qualifying["Target"]).to eq("##{signature["Id"]}")
    end

    it "writes SigningTime in UTC" do
      expect(doc.at_xpath("//xades:SigningTime", ns).text).to eq("2026-09-17T14:32:05Z")
    end

    it "commits to the certificate in SigningCertificateV2" do
      cert = doc.at_xpath("//xades:SigningCertificateV2/xades:Cert", ns)
      issuer_serial = OpenSSL::ASN1.decode(cert.at_xpath("xades:IssuerSerialV2", ns).text.unpack1("m0"))
      directory_name = issuer_serial.value[0].value[0]

      expect(cert.at_xpath("xades:CertDigest/ds:DigestMethod", ns)["Algorithm"])
        .to eq("http://www.w3.org/2001/04/xmlenc#sha256")
      expect(cert.at_xpath("xades:CertDigest/ds:DigestValue", ns).text)
        .to eq(OpenSSL::Digest::SHA256.base64digest(certificate.to_der))
      expect([directory_name.tag, directory_name.tag_class]).to eq([4, :CONTEXT_SPECIFIC])
      expect(OpenSSL::X509::Name.new(directory_name.value[0].to_der)).to eq(certificate.issuer)
      expect(issuer_serial.value[1].value).to eq(certificate.serial)
    end

    it "conforms to the ETSI XAdES 1.3.2 schema" do
      expect(schema_errors(signed)).to be_empty
    end
  end

  describe "tampering with the signed properties" do
    let(:signed) { sign(**full_options) }

    it "breaks the signature" do
      expect(verify(signed).valid?).to be true
      expect(verify(signed.sub("2026-09-17T14:32:05Z", "2020-01-01T00:00:00Z")).valid?).to be false
      expect(verify(signed.sub("Chief Financial Officer", "Chief Executive Officer")).valid?).to be false
    end
  end

  describe "optional properties" do
    let(:signed) { sign(**full_options) }
    let(:doc) { Nokogiri::XML(signed) }

    it "writes SignaturePolicyIdentifier, SignerRoleV2 and DataObjectFormat, and conforms to the schema" do
      policy = doc.at_xpath("//xades:SignaturePolicyIdentifier/xades:SignaturePolicyId", ns)

      expect(policy.at_xpath("xades:SigPolicyId/xades:Identifier", ns).text).to eq("urn:oid:2.16.76.1.7.1.6.2.3")
      expect(policy.at_xpath("xades:SigPolicyId/xades:Description", ns).text).to eq("AD-RB")
      expect(policy.at_xpath("xades:SigPolicyHash/ds:DigestValue", ns).text)
        .to eq(OpenSSL::Digest::SHA256.base64digest("policy document"))
      expect(doc.xpath("//xades:SignerRoleV2/xades:ClaimedRoles/xades:ClaimedRole", ns).map(&:text))
        .to eq(["Chief Financial Officer"])
      expect(schema_errors(signed)).to be_empty
    end

    it "points each DataObjectFormat at a signed Reference" do
      formats = doc.xpath("//xades:DataObjectFormat", ns)
      reference_ids = doc.xpath("//ds:SignedInfo/ds:Reference[not(@Type)]/@Id", ns).map(&:value)

      expect(formats.map { |f| f["ObjectReference"] }).to eq(reference_ids.map { |id| "##{id}" })
      expect(formats.first.at_xpath("xades:MimeType", ns).text).to eq("text/xml")
      expect(verify(signed).valid?).to be true
    end

    it "writes SignaturePolicyImplied" do
      signed = sign(signature_policy: :implied)

      expect(Nokogiri::XML(signed).at_xpath("//xades:SignaturePolicyIdentifier/xades:SignaturePolicyImplied", ns))
        .not_to be_nil
      expect(schema_errors(signed)).to be_empty
    end
  end

  it "signs its own references, including those added in the block form" do
    xades = described_class.new(key: key_pem, certificate: cert_pem, policy: HankoXml::Policy.fragment) do |s|
      s.reference "#total"
    end
    signed = xades.sign(xml).to_s

    expect(Nokogiri::XML(signed).xpath("//ds:Reference", ns).map { |r| r["URI"] })
      .to eq(["#total", "##{xades.signed_properties_id}"])
    expect(verify(signed, policy: HankoXml::Policy.fragment).valid?).to be true
  end

  it "follows digest_method: for the certificate digest and the SignedProperties Reference" do
    doc = Nokogiri::XML(sign(digest_method: :sha512))
    sha512 = "http://www.w3.org/2001/04/xmlenc#sha512"

    expect(doc.at_xpath("//xades:CertDigest/ds:DigestMethod", ns)["Algorithm"]).to eq(sha512)
    expect(doc.at_xpath("//xades:CertDigest/ds:DigestValue", ns).text)
      .to eq(OpenSSL::Digest::SHA512.base64digest(certificate.to_der))
    expect(doc.at_xpath("//ds:Reference[@Type]/ds:DigestMethod", ns)["Algorithm"]).to eq(sha512)
  end

  it "defaults SigningTime to when #sign runs" do
    before = Time.now.utc - 1
    time = Time.iso8601(Nokogiri::XML(described_class.new(key: key_pem, certificate: cert_pem).sign(xml).to_s)
                                   .at_xpath("//xades:SigningTime", ns).text)

    expect(time).to be_between(before, Time.now.utc + 1)
  end

  it "uses signature_id:, and generates a distinct one per Signer otherwise" do
    expect(signer(signature_id: "sig-1").signed_properties_id).to eq("sig-1-signedprops")
    expect(signer.signature_id).not_to eq(signer.signature_id)
  end

  it "puts ds: and xades: nodes in their namespaces in the caller's DOM (sign!)" do
    doc = Nokogiri::XML(xml)
    signer.sign!(doc)

    expect(doc.xpath("//xades:CertDigest/ds:DigestMethod", ns).size).to eq(1)
    expect(doc.xpath("//ds:Object/xades:QualifyingProperties", ns).size).to eq(1)
  end

  it "shows the XAdES template through #template without signing" do
    template = signer.template(xml)

    expect(template.at_xpath("ds:Object/xades:QualifyingProperties/xades:SignedProperties", ns)).not_to be_nil
    expect(template.at_xpath("ds:SignatureValue", ns).text).to be_empty
  end

  describe "configuration errors" do
    it "requires certificate:" do
      expect { described_class.new(key: key_pem) }.to raise_error(HankoXml::ConfigurationError, /certificate/)
    end

    it "only builds new signatures" do
      expect { signer(template: :adopt) }.to raise_error(HankoXml::ConfigurationError, /always builds/)
      signed = sign
      expect { signer.sign(signed) }.to raise_error(HankoXml::ConfigurationError, /already exists/)
    end

    it "rejects a signature policy digest that is not Base64" do
      expect { signer(signature_policy: { identifier: "urn:oid:1.2", digest_value: "not base64!" }) }
        .to raise_error(HankoXml::ConfigurationError, /Base64/)
    end

    it "rejects an empty data_object_format" do
      expect { signer(data_object_format: {}) }.to raise_error(HankoXml::ConfigurationError, /mime_type/)
    end

    it "rejects a signing_time that is not a Time" do
      expect { signer(signing_time: "2026-09-17") }.to raise_error(HankoXml::ConfigurationError, /Time/)
    end
  end
end
