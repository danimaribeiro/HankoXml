# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require "pathname"

# #58: XAdES-B verification. The attacks below all leave the XML-DSig signature
# valid, so only the XAdES checks can catch them.
RSpec.describe HankoXml::Xades::Verifier do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:key_pem) { fixtures.join("signer.key").read }
  let(:cert_pem) { fixtures.join("signer.crt").read }
  let(:other_cert_pem) { fixtures.join("other.crt").read }
  let(:certificate) { OpenSSL::X509::Certificate.new(cert_pem) }
  let(:ns) { { "ds" => HankoXml::NS["ds"], "xades" => HankoXml::Xades::NS } }
  let(:xml) { %(<Invoice xmlns="urn:x"><Total>150.00</Total></Invoice>) }
  let(:policy_hash) { OpenSSL::Digest::SHA256.base64digest("policy document") }
  let(:signed) do
    HankoXml::Xades::Signer.new(
      key: key_pem, certificate: cert_pem, signing_time: Time.utc(2026, 9, 17, 14, 32, 5),
      claimed_roles: ["Chief Financial Officer"], data_object_format: { mime_type: "text/xml" },
      signature_policy: { identifier: "urn:oid:2.16.76.1.7.1.6.2.3", digest_value: policy_hash }
    ).sign(xml).to_s
  end

  def verify(document = signed, **options)
    described_class.new(**{ certificate: cert_pem }.merge(options)).verify(document)
  end

  def tamper(document = signed)
    doc = Nokogiri::XML(document)
    yield doc
    HankoXml.serialize(doc)
  end

  def expect_xades_error(result, message)
    expect(result.valid?).to be false
    expect(result.errors.last).to be_a(HankoXml::XadesError)
    expect(result.errors.last.message).to match(message)
    expect(result.signed_properties).to be_nil
  end

  describe "a genuine XAdES-B signature" do
    let(:result) { verify }

    it "is valid and exposes the signed properties" do
      expect(result).to be_a(HankoXml::Xades::Verification)
      expect(result.valid?).to be true
      expect(result.signed_properties.to_h).to eq(
        signing_time: Time.utc(2026, 9, 17, 14, 32, 5),
        signature_policy: HankoXml::Xades::SignaturePolicy.new(
          identifier: "urn:oid:2.16.76.1.7.1.6.2.3", digest_value: policy_hash,
          digest_method: "http://www.w3.org/2001/04/xmlenc#sha256"
        ),
        claimed_roles: ["Chief Financial Officer"],
        data_object_formats: [{ object_reference: result.signed_properties.data_object_formats.first[:object_reference],
                                mime_type: "text/xml", description: nil, encoding: nil }]
      )
    end

    it "names the certificate that verified" do
      expect(result.certificate).to eq(certificate)
    end

    it "verifies through certificates: and store: too" do
      store = OpenSSL::X509::Store.new.tap { |s| s.add_cert(certificate) }

      expect(verify(certificate: nil, certificates: [other_cert_pem, cert_pem]).valid?).to be true
      expect(verify(certificate: nil, store: store).valid?).to be true
    end

    it "wraps every signature from verify_all" do
      results = described_class.new(certificate: cert_pem).verify_all(signed)
      expect(results.map(&:class)).to eq([HankoXml::Xades::Verification])
      expect(results.first.signed_properties).not_to be_nil
    end
  end

  describe "a decoy SignedProperties (XAdES signature wrapping)" do
    # DSS XSW-enveloped-fake-signedProperties.xml, without its XPath transform:
    # the signed SignedProperties moves to its own <Object>, and the
    # QualifyingProperties holds a forged one. xmlsec still verifies, since the
    # Reference finds the real one by Id.
    let(:attacked) do
      tamper do |doc|
        signature = doc.at_xpath("//ds:Signature", ns)
        real = doc.at_xpath("//xades:SignedProperties", ns)
        decoy = real.dup
        decoy["Id"] = "decoy"
        decoy.at_xpath(".//xades:SigningTime", ns).content = "2218-08-30T14:39:36Z"
        real.add_previous_sibling(decoy)
        holder = doc.create_element("Object")
        holder.namespace = signature.namespace
        holder.add_namespace_definition("xades", HankoXml::Xades::NS)
        signature.add_child(holder)
        holder.add_child(real)
      end
    end

    it "is still a valid XML-DSig signature" do
      expect(HankoXml.valid?(attacked, certificate: cert_pem)).to be true
    end

    it "is refused, and the forged time is never read" do
      result = verify(attacked)

      expect_xades_error(result, /not the one in this signature's QualifyingProperties/)
      expect(result.signed?(Nokogiri::XML(attacked).root)).to be false
    end
  end

  it "refuses a second QualifyingProperties" do
    attacked = tamper do |doc|
      object = doc.at_xpath("//ds:Object", ns)
      copy = object.dup
      # Without its Id, so reject_duplicate_ids is not what stops it.
      copy.at_xpath(".//xades:SignedProperties", ns).remove_attribute("Id")
      object.add_next_sibling(copy)
    end

    expect_xades_error(verify(attacked), /exactly one <xades:QualifyingProperties>/)
  end

  it "refuses QualifyingProperties that target another signature (Target is not signed)" do
    attacked = tamper { |doc| doc.at_xpath("//xades:QualifyingProperties", ns)["Target"] = "#elsewhere" }
    expect_xades_error(verify(attacked), /does not target this <Signature>/)
  end

  it "refuses a certificate the signed properties do not name, even with the same key" do
    impostor = OpenSSL::X509::Certificate.new(cert_pem)
    impostor.serial = certificate.serial + 1
    impostor.sign(OpenSSL::PKey.read(key_pem), OpenSSL::Digest.new("SHA256"))

    expect(HankoXml.valid?(signed, certificate: impostor)).to be true
    expect_xades_error(verify(certificate: impostor), /does not name the certificate that verified/)
  end

  it "refuses a plain XML-DSig signature" do
    plain = HankoXml.sign(xml, key: key_pem, certificate: cert_pem).to_s
    expect_xades_error(verify(plain), /exactly one <Reference> of Type/)
  end

  it "keeps #signed? and #at_signed closed when the XAdES checks fail" do
    attacked = tamper { |doc| doc.at_xpath("//xades:QualifyingProperties", ns)["Target"] = "#elsewhere" }
    result = verify(attacked)

    expect(result.signed?(result.document.root)).to be false
    expect { result.at_signed("//x:Total", "x" => "urn:x") }.to raise_error(HankoXml::NotSignedError)
    expect { described_class.new(certificate: cert_pem).verify!(attacked) }.to raise_error(HankoXml::XadesError)
  end

  it "keeps a failed XML-DSig result as it was" do
    result = verify(signed.sub("150.00", "999.00"))

    expect(result.valid?).to be false
    expect(result.errors.map(&:class)).to eq([HankoXml::VerificationError])
    expect(result.signed_properties).to be_nil
  end

  describe "signature_policy:" do
    it "accepts the expected policy" do
      expected = { identifier: "urn:oid:2.16.76.1.7.1.6.2.3", digest_value: policy_hash }
      expect(verify(signature_policy: expected).valid?).to be true
    end

    it "refuses another policy" do
      expected = { identifier: "urn:oid:2.16.76.1.7.1.6.2.3", digest_value: OpenSSL::Digest::SHA256.base64digest("x") }
      expect_xades_error(verify(signature_policy: expected), /not the expected signature policy/)
      expect_xades_error(verify(signature_policy: :implied), /not the expected signature policy/)
    end
  end

  it "needs certificate-based trust" do
    expect { described_class.new(key: certificate.public_key) }
      .to raise_error(HankoXml::ConfigurationError, /certificate:, certificates: or store:/)
    expect { described_class.new(keys: { "a" => certificate.public_key }) }
      .to raise_error(HankoXml::ConfigurationError, /certificate:/)
  end
end
