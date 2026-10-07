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

  def verify(path, policy: HankoXml::Policy.interop)
    xml = ROOT.join(path).binread
    certificate = embedded_certificate(xml)
    midpoint = Time.at((certificate.not_before.to_i + certificate.not_after.to_i) / 2)
    HankoXml::Xades::Verifier.new(certificate: certificate, policy: policy, verification_time: midpoint,
                                  signature: :first).verify(xml)
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
