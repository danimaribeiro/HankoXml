# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require "pathname"

# #58: XAdES signatures HankoXml did not produce (see xades/README.md).
# SignXML's real-world samples come from other implementations; the EU DSS
# xsw/ set are signature-wrapping attacks. Each is verified under
# Policy.interop, trusting the certificate the file itself carries (as
# SignXML's own suite does), at the midpoint of that certificate's validity.
# These check the XML-DSig signature and the signed properties, so their
# SignatureTimeStamps are left out (timestamps: :ignore); the timestamps have
# their own section below (#163).
module XadesInteropVectors
  ROOT = Pathname.new(__dir__).join("xades")
  XPATH = [:policy, /\(:xpath\) .* not in this policy's transforms/].freeze

  # path => outcome: :valid, or [:policy | :native, message].
  EXPECTED = {
    "signxml/11068_signed.xml" => :valid,
    "signxml/Signature-X-CZ_SEF-4.xml" => :valid,  # XAdES-T
    "signxml/Signature-X-CZ_SEF-5.xml" => :valid,  # XAdES-LT
    "signxml/Signature-X-HU_POL-3.xml" => :valid,  # XAdES-LTA
    "signxml/Signature-X-SK_DIT-1.xml" => :valid,
    "signxml/Signature-X-UK_ASC-2.xml" => :valid,
    "signxml/X_AT_SIT_1.xml" => :valid,            # ECDSA
    "signxml/TEST_S1a_C1a_InTL_VALID.xml" => XPATH,
    "dss/validation/xsw/original.xml" => :valid,
    "dss/validation/xsw/TSL-CY-sign.xml" => :valid,
    "dss/validation/xsw/TSL-noID.xml" => :valid,
    "dss/validation/xsw/disable-checks.xml" => :valid,
    # Attacks. DSS: TOTAL_FAILED / FORMAT_FAILURE.
    "dss/validation/xsw/XSW-enveloped-fake-content.xml" => [:native, /data and digest do not match/],
    "dss/validation/xsw/XSW-enveloped-fake-content-two-same-id.xml" => [:policy, /reject_duplicate_ids/],
    # A decoy SignedProperties; its XPath transform stops it first here. The
    # same attack without it is in spec/hanko_xml/xades_verifier_spec.rb.
    "dss/validation/xsw/XSW-enveloped-fake-signedProperties.xml" => XPATH,
    # Valid signatures around unsigned fake content; see "what stays unsigned".
    "dss/validation/xsw/XSW-enveloped-fake-content-misplaced.xml" => :valid,
    "dss/validation/xsw/XSW-enveloping-fake-object.xml" => :valid,
    "dss/validation/xsw/XSW-enveloping-fake-manifest.xml" => :valid,
    # #85: XPath Filter 2.0 subtracting the signatures from the whole document.
    "dss/validation/evidence-record/incorporation/X-B-B.xml" => :valid,
    # Its first signature uses URI="#xpointer(/)", which Policy.interop leaves off.
    "dss/validation/evidence-record/incorporation/X-B-LT-two-sigs.xml" => [:policy, /allow_same_document_xpointer/],
    # Filters HankoXml can't model in #signed?: name() comparisons and intersect.
    "dss/validation/Signature-X-BE_ECON-3.xml" => [:policy, /XPath Filter 2.0/],
    "dss/validation/Signature-X-AT-1.xml" => [:policy, /XPath Filter 2.0/], # also XAdES 1.1.1
    "dss/validation/qes-xades111-filter2.xml" => [:policy, /XPath Filter 2.0/], # also XAdES 1.1.1
    # #86: XAdES 1.2.2. CZ_ICZ-1 has an untyped SignedProperties Reference and
    # Target="Signature". FR_NOT-3 repeats id values in its content; see below.
    "dss/validation/Signature-X-CZ_ICZ-1.xml" => :valid,
    "dss/validation/Signature-X-FR_NOT-3.xml" => [:policy, /reject_duplicate_ids/]
  }.freeze

  module_function

  def verify(path, policy: HankoXml::Policy.interop, **options)
    xml = ROOT.join(path).binread
    certificate = embedded_certificate(xml)
    midpoint = Time.at((certificate.not_before.to_i + certificate.not_after.to_i) / 2)
    HankoXml::Xades::Verifier.new(certificate: certificate, policy: policy, verification_time: midpoint,
                                  signature: :first, **{ timestamps: :ignore }.merge(options)).verify(xml)
  end

  # A TSA store trusting the certificates the token itself carries, as the
  # signer's certificate is trusted above. Test-only: these TSAs' roots are
  # not vendored, and their certificates expired long ago.
  def embedded_tsa_store(xml)
    node = Nokogiri::XML(xml).at_xpath("//*[local-name()='EncapsulatedTimeStamp']")
    token = OpenSSL::PKCS7.new(node.text.gsub(/\s/, "").unpack1("m"))
    OpenSSL::X509::Store.new.tap do |store|
      store.flags = OpenSSL::X509::V_FLAG_PARTIAL_CHAIN | OpenSSL::X509::V_FLAG_NO_CHECK_TIME
      token.certificates.each { |certificate| store.add_cert(certificate) }
    end
  end

  def embedded_certificate(xml)
    base64 = Nokogiri::XML(xml).at_xpath("//ds:X509Certificate", "ds" => HankoXml::NS["ds"]).text
    OpenSSL::X509::Certificate.new(base64.unpack1("m"))
  end
end

RSpec.describe "XAdES interop vectors (#58)" do
  it "has an expectation for every vendored XAdES file" do
    files = Dir.glob(XadesInteropVectors::ROOT.join("**", "*.xml").to_s)
               .reject { |f| f.include?("/corpus/") || f.include?("/signxml-produced/") }
    expect(XadesInteropVectors::EXPECTED.keys).to match_array(
      files.map { |f| f.delete_prefix("#{XadesInteropVectors::ROOT}/") }
    )
  end

  XadesInteropVectors::EXPECTED.each do |path, outcome|
    it "#{path}: #{outcome == :valid ? "valid" : outcome.first}" do
      result = XadesInteropVectors.verify(path)

      if outcome == :valid
        expect(result.errors).to be_empty
        expect(result.signed_properties.signing_time).to be_a(Time)
        next
      end

      kind, pattern = outcome
      error = result.errors.first
      expect(result.valid?).to be false
      expect(error).to be_a(kind == :policy ? HankoXml::PolicyError : HankoXml::VerificationError)
      expect(kind == :native ? Array(error.xmlsec_errors).join("\n") : error.message).to match(pattern)
    end
  end

  it "reads XAdES 1.2.2 signed properties under a versioned Reference Type once duplicate ids are allowed (#86)" do
    path = "dss/validation/Signature-X-FR_NOT-3.xml"
    result = XadesInteropVectors.verify(path, policy: HankoXml::Policy.interop.with(reject_duplicate_ids: false))

    expect(result.errors).to be_empty
    expect(result.signed_properties.signing_time).to eq(Time.utc(2014, 11, 7, 8, 48, 27.803r))
  end

  it "reads the signed properties of a legacy SigningCertificate (v1) signature" do
    properties = XadesInteropVectors.verify("signxml/Signature-X-UK_ASC-2.xml").signed_properties

    expect(properties.signing_time).to eq(Time.utc(2016, 4, 19, 8, 47, 49))
    expect(properties.claimed_roles).to eq(["Manager"])
  end

  # #163: the SignatureTimeStamps real implementations wrote, checked with
  # the TSA certificates their tokens carry.
  describe "SignatureTimeStamp (#163)" do
    it "verifies HU_POL-3's timestamp: the imprint over its exc-c14n SignatureValue matches" do
      path = "signxml/Signature-X-HU_POL-3.xml"
      store = XadesInteropVectors.embedded_tsa_store(XadesInteropVectors::ROOT.join(path).binread)
      result = XadesInteropVectors.verify(path, timestamps: :require, tsa_store: store)

      expect(result.errors).to be_empty
      expect(result.signature_timestamps.size).to eq(1)
      expect(result.timestamp_time).to be_a(Time).and(be > result.signed_properties.signing_time - 60)
    end

    it "fails closed on CZ_SEF's tokens, whose certificates OpenSSL's PKCS7 parser cannot read" do
      %w[signxml/Signature-X-CZ_SEF-4.xml signxml/Signature-X-CZ_SEF-5.xml].each do |path|
        result = XadesInteropVectors.verify(path, timestamps: :verify, tsa_store: OpenSSL::X509::Store.new)

        expect(result.valid?).to be false
        expect(result.errors.first.message).to match(/not an RFC 3161 TimeStampToken OpenSSL can read/)
      end
    end

    # #168: HU_POL-3 is a DSS-produced XAdES-LTA. Its CertificateValues
    # complete the chain (signer, GOV CA, root) and its two OCSP responses,
    # from delegated responders, cover the signer and the GOV CA. The root
    # it embeds is the test-only anchor here; the real one is not vendored.
    describe "XAdES-LT (#168)" do
      let(:xml) { XadesInteropVectors::ROOT.join("signxml/Signature-X-HU_POL-3.xml").binread }
      let(:root) do
        values = Nokogiri::XML(xml).xpath("//*[local-name()='UnsignedSignatureProperties']/*[local-name()='CertificateValues']/*")
        values.map { |node| OpenSSL::X509::Certificate.new(node.text.gsub(/\s/, "").unpack1("m")) }
              .find { |certificate| certificate.subject.to_der == certificate.issuer.to_der }
      end

      def verify_lt(**options)
        HankoXml::Xades::Verifier.new(store: OpenSSL::X509::Store.new.tap { |store| store.add_cert(root) },
                                      policy: HankoXml::Policy.interop, signature: :first,
                                      tsa_store: XadesInteropVectors.embedded_tsa_store(xml), **options).verify(xml)
      end

      it "validates the signer's chain at its timestamp's time with the embedded OCSP responses" do
        result = verify_lt(revocation_grace: 60)
        validation = result.long_term_validation

        expect(result.errors).to be_empty
        expect(validation.time).to eq(result.timestamp_time)
        expect(validation.certificate_chain.size).to eq(3)
        expect(validation.revocation.map { |status| [status.source, status.status] }).to eq([%i[ocsp good]] * 2)
      end

      it "is strict by default: the GOV CA's OCSP response predates the timestamp by a second" do
        result = verify_lt

        expect(result.valid?).to be false
        expect(result.errors.last.message).to match(/no embedded revocation data .* for chain certificate 1/)
        expect(verify_lt(revocation_grace: 1).errors).to be_empty
      end
    end

    it "fails closed when the signature has a timestamp and no TSA trust was given" do
      result = XadesInteropVectors.verify("signxml/Signature-X-HU_POL-3.xml", timestamps: :verify)

      expect(result.valid?).to be false
      expect(result.errors.first.message).to match(/pass tsa_store: or tsa_certificates:/)
    end
  end

  describe "what stays unsigned in the valid DSS attacks" do
    let(:ns) { { "ds" => HankoXml::NS["ds"] } }

    it "misplaced content: the root is not signed, and require_signed_root refuses it" do
      path = "dss/validation/xsw/XSW-enveloped-fake-content-misplaced.xml"
      result = XadesInteropVectors.verify(path)

      expect(result.signed?(result.document.root)).to be false
      expect(XadesInteropVectors.verify(path, policy: HankoXml::Policy.interop.with(require_signed_root: true))
               .errors.first.message).to match(/require_signed_root/)
    end

    it "fake enveloping <Object>: the one named evil is not signed" do
      result = XadesInteropVectors.verify("dss/validation/xsw/XSW-enveloping-fake-object.xml")
      evil = result.document.at_xpath("//ds:Object[@Id='evil']", ns)

      expect(result.signed?(evil)).to be false
      expect(result.signed?(result.document.at_xpath("//ds:Object[@Id='o-id-1']", ns))).to be true
    end

    it "fake <Manifest>: the one named evil is not signed" do
      result = XadesInteropVectors.verify("dss/validation/xsw/XSW-enveloping-fake-manifest.xml")
      expect(result.signed?(result.document.at_xpath("//ds:Manifest[@Id='evil']", ns))).to be false
    end
  end
end
