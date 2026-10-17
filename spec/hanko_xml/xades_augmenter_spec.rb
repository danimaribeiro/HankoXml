# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require "pathname"
require_relative "../support/fake_tsa"

# #167: unsigned properties added to an existing XAdES signature: a
# SignatureTimeStamp (B to T) and CertificateValues / RevocationValues (T to
# LT), without changing anything a Reference covers.
RSpec.describe HankoXml::Xades::Augmenter do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:key_pem) { fixtures.join("signer.key").read }
  let(:cert_pem) { fixtures.join("signer.crt").read }
  let(:certificate) { OpenSSL::X509::Certificate.new(cert_pem) }
  let(:xml) { %(<Invoice xmlns="urn:x"><Total Id="total">150.00</Total></Invoice>) }
  let(:ns) { { "ds" => HankoXml::NS["ds"], "xades" => HankoXml::Xades::NS } }
  let(:tsa) { FakeTsa.new }
  let(:schema) do
    path = fixtures.join("xades", "XAdES01903v132-202407.xsd")
    Nokogiri::XML::Schema.from_document(Nokogiri::XML(path.read, path.to_s))
  end

  # A CA that issues a CRL and an OCSP response about the signer's
  # certificate. Only their types matter here; #168 validates them.
  let(:ca_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:crl) do
    OpenSSL::X509::CRL.new.tap do |crl|
      crl.version = 1
      crl.issuer = certificate.issuer
      crl.last_update = Time.utc(2026, 9, 17, 15)
      crl.next_update = Time.utc(2026, 9, 24, 15)
      crl.sign(ca_key, OpenSSL::Digest.new("SHA256"))
    end
  end
  let(:ocsp_response) { ocsp(OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL) }
  let(:validation_data) do
    { certificates: [certificate, tsa.ca_certificate], crls: [crl], ocsp_responses: [ocsp_response.to_der] }
  end

  def ocsp(status)
    basic = OpenSSL::OCSP::BasicResponse.new
    id = OpenSSL::OCSP::CertificateId.new(certificate, certificate, OpenSSL::Digest.new("SHA256"))
    basic.add_status(id, OpenSSL::OCSP::V_CERTSTATUS_GOOD, 0, nil, Time.utc(2026, 9, 17, 15), nil, [])
    basic.sign(certificate, OpenSSL::PKey.read(key_pem), [], OpenSSL::OCSP::NOCERTS)
    OpenSSL::OCSP::Response.create(status, status == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL ? basic : nil)
  end

  def sign(timestamper: nil, **options)
    HankoXml::Xades::Signer.new(key: key_pem, certificate: cert_pem, timestamper: timestamper, **options)
                           .sign(xml).to_s
  end

  def verify(document, **options)
    HankoXml::Xades::Verifier.new(certificate: cert_pem, tsa_certificates: [tsa.ca_certificate], **options)
                             .verify(document.to_s)
  end

  def unsigned_properties(document)
    Nokogiri::XML(document.to_s).at_xpath("//xades:UnsignedSignatureProperties", ns)
  end

  # Everything a Reference or the SignatureValue covers, as bytes.
  def signed_parts(document)
    doc = Nokogiri::XML(document.to_s)
    %w[//ds:SignedInfo //ds:SignatureValue //xades:SignedProperties //*[@Id='total']].map do |path|
      doc.at_xpath(path, ns).canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)
    end
  end

  def schema_errors(document)
    properties = Nokogiri::XML(document.to_s).at_xpath("//xades:QualifyingProperties", ns)
    standalone = Nokogiri::XML::Document.new
    standalone.root = properties.dup(1, standalone)
    schema.validate(Nokogiri::XML(standalone.to_xml)).map(&:message)
  end

  def encapsulated(document, path)
    unsigned_properties(document).xpath(path, ns).map { |node| node.text.unpack1("m0") }
  end

  describe "B to T" do
    let(:signed) { sign }
    let(:augmented) { described_class.new(timestamper: tsa.timestamper).augment(signed) }

    it "adds a SignatureTimeStamp that Xades::Verifier verifies, leaving the signed bytes as they were" do
      result = verify(augmented)

      expect(result.errors).to be_empty
      signature_id = Nokogiri::XML(signed).at_xpath("//ds:Signature", ns)["Id"]
      expect(result.signature_timestamps.map(&:id)).to eq(["#{signature_id}-sigts"])
      expect(signed_parts(augmented)).to eq(signed_parts(signed))
      expect(HankoXml::Verifier.new(certificate: cert_pem).verify(augmented.to_s)).to be_valid
      expect(schema_errors(augmented)).to be_empty
    end

    it "does not touch the caller's document" do
      doc = Nokogiri::XML(signed)
      before = HankoXml.serialize(doc)
      described_class.new(timestamper: tsa.timestamper).augment(doc)

      expect(HankoXml.serialize(doc)).to eq(before)
    end

    it "adds a second SignatureTimeStamp with its own Id" do
      twice = described_class.new(timestamper: tsa.timestamper).augment(augmented.to_s)
      result = verify(twice)

      expect(result.errors).to be_empty
      expect(result.signature_timestamps.map(&:id).last).to end_with("-sigts-2")
    end

    it "finds the QualifyingProperties Object among several" do
      doc = Nokogiri::XML(signed)
      signature = doc.at_xpath("//ds:Signature", ns)
      extra = doc.create_element("Object")
      signature.at_xpath("ds:Object", ns).add_previous_sibling(extra)
      extra.namespace = signature.namespace
      result = verify(described_class.new(timestamper: tsa.timestamper).augment(HankoXml.serialize(doc)))

      expect(result.errors).to be_empty
      expect(result.signature_timestamps.size).to eq(1)
    end

    it "puts UnsignedSignatureProperties before an existing UnsignedDataObjectProperties" do
      doc = Nokogiri::XML(signed)
      qualifying = doc.at_xpath("//xades:QualifyingProperties", ns)
      qualifying.add_child("<xades:UnsignedProperties><xades:UnsignedDataObjectProperties>" \
                           "<xades:UnsignedDataObjectProperty>note</xades:UnsignedDataObjectProperty>" \
                           "</xades:UnsignedDataObjectProperties></xades:UnsignedProperties>")
      augmented = described_class.new(timestamper: tsa.timestamper).augment(HankoXml.serialize(doc))
      names = Nokogiri::XML(augmented.to_s).at_xpath("//xades:UnsignedProperties", ns).element_children.map(&:name)

      expect(names).to eq(%w[UnsignedSignatureProperties UnsignedDataObjectProperties])
      expect(schema_errors(augmented)).to be_empty
      expect(verify(augmented)).to be_valid
    end
  end

  describe "T to LT" do
    let(:signed) { sign(timestamper: tsa.timestamper) }
    let(:augmented) { described_class.new(validation_data: validation_data).augment(signed) }

    it "embeds the certificates, CRLs and OCSP responses as Base64 DER, after the SignatureTimeStamp" do
      expect(unsigned_properties(augmented).element_children.map(&:name))
        .to eq(%w[SignatureTimeStamp CertificateValues RevocationValues])
      expect(encapsulated(augmented, "xades:CertificateValues/xades:EncapsulatedX509Certificate"))
        .to eq([certificate.to_der, tsa.ca_certificate.to_der])
      expect(encapsulated(augmented, "xades:RevocationValues/xades:CRLValues/xades:EncapsulatedCRLValue"))
        .to eq([crl.to_der])
      expect(encapsulated(augmented, "xades:RevocationValues/xades:OCSPValues/xades:EncapsulatedOCSPValue"))
        .to eq([ocsp_response.to_der])
    end

    it "conforms to the XAdES 1.3.2 schema and still verifies, signed bytes unchanged" do
      expect(schema_errors(augmented)).to be_empty
      expect(signed_parts(augmented)).to eq(signed_parts(signed))
      expect(verify(augmented).errors).to be_empty
    end

    it "writes only the parts it is given" do
      only_ocsp = described_class.new(validation_data: { ocsp_responses: [ocsp_response] }).augment(signed)
      revocation = unsigned_properties(only_ocsp).at_xpath("xades:RevocationValues", ns)

      expect(unsigned_properties(only_ocsp).at_xpath("xades:CertificateValues", ns)).to be_nil
      expect(revocation.element_children.map(&:name)).to eq(%w[OCSPValues])
      expect(schema_errors(only_ocsp)).to be_empty
    end

    it "refuses LT on a signature without a SignatureTimeStamp" do
      expect { described_class.new(validation_data: validation_data).augment(sign) }
        .to raise_error(HankoXml::ConfigurationError, /builds on XAdES-T.*pass timestamper:/)
    end
  end

  it "goes from B to LT in one call, timestamp first" do
    augmented = described_class.new(timestamper: tsa.timestamper, validation_data: validation_data).augment(sign)

    expect(unsigned_properties(augmented).element_children.map(&:name))
      .to eq(%w[SignatureTimeStamp CertificateValues RevocationValues])
    expect(verify(augmented).errors).to be_empty
  end

  describe "Xades::Signer validation_data:" do
    it "writes LT at signing time" do
      signed = sign(timestamper: tsa.timestamper, validation_data: validation_data)

      expect(unsigned_properties(signed).element_children.map(&:name))
        .to eq(%w[SignatureTimeStamp CertificateValues RevocationValues])
      expect(schema_errors(signed)).to be_empty
      expect(verify(signed).errors).to be_empty
    end

    it "needs timestamper:" do
      expect { sign(validation_data: validation_data) }
        .to raise_error(HankoXml::ConfigurationError, /validation_data: needs timestamper:/)
    end
  end

  describe "documents it refuses" do
    let(:augmenter) { described_class.new(timestamper: tsa.timestamper) }

    it "needs exactly one signature, or signature:" do
      expect { augmenter.augment(xml) }.to raise_error(HankoXml::ConfigurationError, /no <ds:Signature>/)

      doc = Nokogiri::XML(sign)
      doc.root.add_child(Nokogiri::XML(sign).at_xpath("//ds:Signature", ns))
      expect { augmenter.augment(HankoXml.serialize(doc)) }
        .to raise_error(HankoXml::ConfigurationError, /has 2 signatures; pass signature:/)
      expect { augmenter.augment(HankoXml.serialize(doc), signature: 2) }
        .to raise_error(HankoXml::ConfigurationError, /signature: 2 not found/)

      augmented = Nokogiri::XML(augmenter.augment(HankoXml.serialize(doc), signature: -1).to_s)
      first, second = augmented.xpath("//ds:Signature", ns).to_a
      value = second.at_xpath("ds:SignatureValue", ns).canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)
      expect(first.at_xpath(".//xades:SignatureTimeStamp", ns)).to be_nil
      expect(second.at_xpath(".//xades:SignatureTimeStamp", ns)).not_to be_nil
      expect(tsa.requests.last.message_imprint).to eq(OpenSSL::Digest.digest("SHA256", value))
    end

    it "refuses an unsigned template" do
      doc = Nokogiri::XML(sign)
      doc.at_xpath("//ds:SignatureValue", ns).content = ""
      expect { augmenter.augment(HankoXml.serialize(doc)) }.to raise_error(HankoXml::ConfigurationError, /not signed/)
    end

    it "refuses other XAdES versions and ambiguous containers" do
      legacy = sign.gsub(HankoXml::Xades::NS, "http://uri.etsi.org/01903/v1.2.2#")
      expect { augmenter.augment(legacy) }.to raise_error(HankoXml::XadesError, /only XAdES 1.3.2/)

      doc = Nokogiri::XML(sign(timestamper: tsa.timestamper))
      unsigned = doc.at_xpath("//xades:UnsignedProperties", ns)
      copy = unsigned.dup(1)
      copy.xpath(".//@Id").each(&:unlink)
      unsigned.add_next_sibling(copy)
      expect { augmenter.augment(HankoXml.serialize(doc)) }
        .to raise_error(HankoXml::XadesError, /at most one <xades:UnsignedProperties>/)
    end

    it "fails closed when the TSA's answer does not hold, as the Signer does" do
      wrong = described_class.new(timestamper: tsa.timestamper { |request| request.tap { |r| r.nonce = r.nonce + 1 } })
      expect { wrong.augment(sign) }.to raise_error(HankoXml::SigningError, /nonce/)
    end
  end

  describe "configuration" do
    it "needs something to add, and a callable timestamper" do
      expect { described_class.new }.to raise_error(HankoXml::ConfigurationError, /pass timestamper:, validation_data:/)
      expect { described_class.new(timestamper: "https://tsa.example") }
        .to raise_error(HankoXml::ConfigurationError, /must respond to #call/)
    end

    it "checks the imprint algorithms against the policy" do
      expect { described_class.new(timestamper: tsa.timestamper, timestamp_digest_method: :sha1) }
        .to raise_error(HankoXml::PolicyError)
      expect { described_class.new(timestamper: tsa.timestamper, timestamp_canonicalization_method: :sha256) }
        .to raise_error(HankoXml::ConfigurationError, /timestamp_canonicalization_method: :sha256/)
    end

    it "type-checks the validation data" do
      {
        { certificates: [key_pem] } => /certificates: must be X.509 certificates/,
        { certificates: ["not a pem"] } => /certificates: must be X.509 certificates/,
        { crls: ["not a crl"] } => /crls: must be X.509 CRLs/,
        { crls: [certificate] } => /crls: must be X.509 CRLs/,
        { ocsp_responses: ["not der"] } => /ocsp_responses: must be DER OCSPResponses/,
        { ocsp_responses: [ocsp(OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED)] } => /responseStatus 6/,
        {} => /needs certificates:, crls: or ocsp_responses:/
      }.each do |data, message|
        expect { described_class.new(validation_data: data) }.to raise_error(HankoXml::ConfigurationError, message)
      end
      expect { described_class.new(validation_data: "x") }
        .to raise_error(HankoXml::ConfigurationError, /must be a Xades::ValidationData/)
    end

    it "is frozen and inspects without the material" do
      augmenter = described_class.new(timestamper: tsa.timestamper, validation_data: validation_data)

      expect(augmenter).to be_frozen
      expect(augmenter.validation_data).to be_frozen
      expect(augmenter.inspect).to eq("#<HankoXml::Xades::Augmenter timestamper=true validation_data=true>")
    end
  end
end
