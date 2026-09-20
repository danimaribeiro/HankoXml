# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "open3"
require "openssl"
require "pathname"
require "tempfile"

# #59: documents produced by SignXML 5.1.0's XAdESSigner, verified by
# HankoXml::Xades::Verifier under Policy.strict. These are not the real-world
# samples SignXML vendors (those are #58); they are what XAdESSigner emits
# today. The reverse (HankoXml sign → SignXML verify) runs when python3 can
# import signxml; CI does not install it.
module SignxmlProducedXades
  ROOT = Pathname.new(__dir__).join("xades", "signxml-produced")
  FIXTURES = Pathname.new(__dir__).join("..", "fixtures")
  CERT = FIXTURES.join("signer.crt").read.freeze
  KEY = FIXTURES.join("signer.key").read.freeze
  OTHER = FIXTURES.join("other.crt").read.freeze
  POLICY_DIGEST = "Ohixl6upD6av8N7pEvDABhEL6hM="
  POLICY_ID = "urn:oid:2.16.76.1.7.1.6.2.3"
  INVOICE = %(<Invoice xmlns="urn:x"><Total>150.00</Total></Invoice>).freeze

  module_function

  def xml(name)
    ROOT.join(name).binread
  end

  def verify(name, **options)
    HankoXml::Xades::Verifier.new(**{ certificate: CERT }.merge(options)).verify(xml(name))
  end

  def signxml_available?
    _out, status = Open3.capture2e("python3", "-c", "import signxml")
    status.success?
  end
end

RSpec.describe "SignXML-produced XAdES-B (#59)" do
  let(:ns) { { "ds" => HankoXml::NS["ds"], "xades" => HankoXml::Xades::NS } }

  describe "enveloped-default.xml" do
    let(:result) { SignxmlProducedXades.verify("enveloped-default.xml") }

    it "verifies under Policy.strict" do
      expect(result.errors).to be_empty
      expect(result.valid?).to be true
      expect(result.signed?(result.document.root)).to be true
    end

    it "exposes SignXML's default SignedProperties" do
      expect(result.signed_properties.signing_time).to eq(Time.utc(2026, 9, 20, 5, 29, 36))
      expect(result.signed_properties.signature_policy).to be_nil
      expect(result.signed_properties.claimed_roles).to eq([])
      expect(result.signed_properties.data_object_formats).to eq(
        [{ object_reference: "#SignXMLReference5E10DBFA", mime_type: "text/xml",
           description: "Default XAdES payload description", encoding: nil }]
      )
    end

    it "signs KeyInfo as a third Reference, and still pins the caller's certificate (S-01)" do
      doc = Nokogiri::XML(SignxmlProducedXades.xml("enveloped-default.xml"))
      uris = doc.xpath("//ds:Reference/@URI", ns).map(&:value)

      expect(uris.size).to eq(3)
      expect(uris).to include("##{doc.at_xpath("//ds:KeyInfo", ns)["Id"]}")
      expect(doc.at_xpath("//ds:KeyValue", ns)).not_to be_nil
      expect(SignxmlProducedXades.verify("enveloped-default.xml", certificate: SignxmlProducedXades::OTHER)
               .valid?).to be false
    end
  end

  describe "enveloped-full.xml" do
    let(:result) { SignxmlProducedXades.verify("enveloped-full.xml") }

    it "verifies under Policy.strict, including inclusive c14n 1.0" do
      expect(result.errors).to be_empty
      expect(result.valid?).to be true
    end

    it "reads SignaturePolicyIdentifier, SignerRole (v1) and DataObjectFormat" do
      expect(result.signed_properties.to_h).to eq(
        signing_time: Time.utc(2026, 9, 20, 5, 29, 36),
        signature_policy: HankoXml::Xades::SignaturePolicy.new(
          identifier: SignxmlProducedXades::POLICY_ID, digest_value: SignxmlProducedXades::POLICY_DIGEST,
          digest_method: "http://www.w3.org/2001/04/xmlenc#sha256", description: "AD-RB"
        ),
        claimed_roles: ["Chief Financial Officer"],
        data_object_formats: [{ object_reference: "#SignXMLReference7950BC46", mime_type: "text/xml",
                                description: "Invoice", encoding: nil }]
      )
    end

    it "enforces signature_policy: against the signed identifier" do
      matching = SignxmlProducedXades.verify(
        "enveloped-full.xml",
        signature_policy: { identifier: SignxmlProducedXades::POLICY_ID,
                            digest_value: SignxmlProducedXades::POLICY_DIGEST, description: "AD-RB" }
      )
      mismatch = SignxmlProducedXades.verify(
        "enveloped-full.xml",
        signature_policy: { identifier: "urn:oid:1.2.3", digest_value: SignxmlProducedXades::POLICY_DIGEST }
      )

      expect(matching.valid?).to be true
      expect(mismatch.valid?).to be false
      expect(mismatch.errors.last).to be_a(HankoXml::XadesError)
      expect(mismatch.errors.last.message).to match(/signature policy/)
    end
  end

  describe "HankoXml-produced XAdES-B, verified by SignXML" do
    it "is accepted when SignXML is installed (expect_references: 2)" do
      skip "python3 with signxml==5.1.0 is not installed" unless SignxmlProducedXades.signxml_available?

      signed = HankoXml::Xades::Signer.new(
        key: SignxmlProducedXades::KEY, certificate: SignxmlProducedXades::CERT,
        signing_time: Time.utc(2026, 9, 17, 14, 32, 5),
        claimed_roles: ["Chief Financial Officer"],
        data_object_format: { mime_type: "text/xml", description: "Invoice" },
        signature_policy: { identifier: SignxmlProducedXades::POLICY_ID,
                            digest_value: SignxmlProducedXades::POLICY_DIGEST, description: "AD-RB" },
        signature_id: "xades-interop-59"
      ).sign(SignxmlProducedXades::INVOICE).to_s

      Tempfile.create(["hanko-xades", ".xml"]) do |file|
        file.write(signed)
        file.flush
        out, status = Open3.capture2e(
          "python3", SignxmlProducedXades::ROOT.join("verify.py").to_s, file.path,
          "--policy-id", SignxmlProducedXades::POLICY_ID,
          "--policy-digest", SignxmlProducedXades::POLICY_DIGEST,
          "--policy-description", "AD-RB"
        )
        expect(status.success?).to eq(true), out
        expect(out).to include("ok")
      end
    end
  end
end
