# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require "pathname"
require_relative "../support/fake_tsa"

# #162: XAdES-T signing. After xmlsec signs, the timestamper: obtains an RFC
# 3161 token over the canonicalized <ds:SignatureValue>, embedded as a
# <xades:SignatureTimeStamp>. A local TSA answers; nothing uses the network.
RSpec.describe HankoXml::Xades::Signer, "timestamper:" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:key_pem) { fixtures.join("signer.key").read }
  let(:cert_pem) { fixtures.join("signer.crt").read }
  let(:xml) { %(<Invoice xmlns="urn:x"><Total Id="total">150.00</Total></Invoice>) }
  let(:ns) { { "ds" => HankoXml::NS["ds"], "xades" => HankoXml::Xades::NS } }
  let(:tsa) { FakeTsa.new }
  let(:schema) do
    path = fixtures.join("xades", "XAdES01903v132-202407.xsd")
    Nokogiri::XML::Schema.from_document(Nokogiri::XML(path.read, path.to_s))
  end

  def signer(timestamper: tsa.timestamper, **options)
    described_class.new(key: key_pem, certificate: cert_pem, timestamper: timestamper, **options)
  end

  def sign(source = xml, **options)
    signer(**options).sign(source).to_s
  end

  def timestamp_node(signed)
    Nokogiri::XML(signed).at_xpath("//xades:UnsignedSignatureProperties/xades:SignatureTimeStamp", ns)
  end

  def token(signed)
    OpenSSL::PKCS7.new(timestamp_node(signed).at_xpath("xades:EncapsulatedTimeStamp", ns).text.unpack1("m0"))
  end

  # Independent of the signer's path: Nokogiri's exclusive c14n.
  def expected_imprint(signed, digest = "SHA256")
    value = Nokogiri::XML(signed).at_xpath("//ds:SignatureValue", ns)
    OpenSSL::Digest.digest(digest, value.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0))
  end

  describe "the signature" do
    let(:signed) { sign }

    it "carries a SignatureTimeStamp with its CanonicalizationMethod and the TSA's token" do
      node = timestamp_node(signed)
      signature_id = Nokogiri::XML(signed).at_xpath("//ds:Signature", ns)["Id"]

      expect(node["Id"]).to eq("#{signature_id}-sigts")
      expect(node.at_xpath("ds:CanonicalizationMethod/@Algorithm", ns).value)
        .to eq("http://www.w3.org/2001/10/xml-exc-c14n#")
      expect(token(signed).verify([], tsa.store, nil, OpenSSL::PKCS7::NOVERIFY | OpenSSL::PKCS7::BINARY))
        .to be true
    end

    it "timestamps the canonicalized SignatureValue" do
      request = tsa.requests.tap { signed }.last

      expect(request.message_imprint).to eq(expected_imprint(signed))
      expect(request.algorithm.downcase).to eq("sha256")
      expect(request.nonce).to be_a(OpenSSL::BN).and(satisfy { |nonce| nonce > 0 })
      expect(request.cert_requested?).to be true
    end

    it "still verifies as XAdES-B under Policy.strict, and conforms to the XAdES 1.3.2 schema" do
      properties = Nokogiri::XML(signed).at_xpath("//xades:QualifyingProperties", ns)
      standalone = Nokogiri::XML::Document.new
      standalone.root = properties.dup(1, standalone)

      expect(HankoXml::Verifier.new(certificate: cert_pem).verify(signed)).to be_valid
      expect(HankoXml::Xades::Verifier.new(certificate: cert_pem, timestamps: :ignore).verify(signed)).to be_valid
      expect(schema.validate(Nokogiri::XML(standalone.to_xml)).map(&:message)).to be_empty
    end
  end

  it "digests with timestamp_digest_method:, else the Signer's digest_method:" do
    signed = sign(timestamp_digest_method: :sha512)
    expect(tsa.requests.last.algorithm.downcase).to eq("sha512")
    expect(tsa.requests.last.message_imprint).to eq(expected_imprint(signed, "SHA512"))

    sign(digest_method: :sha384)
    expect(tsa.requests.last.algorithm.downcase).to eq("sha384")
  end

  it "canonicalizes with timestamp_canonicalization_method:" do
    signed = sign(timestamp_canonicalization_method: :c14n)
    value = Nokogiri::XML(signed).at_xpath("//ds:SignatureValue", ns)

    expect(timestamp_node(signed).at_xpath("ds:CanonicalizationMethod/@Algorithm", ns).value)
      .to eq("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
    expect(tsa.requests.last.message_imprint)
      .to eq(OpenSSL::Digest.digest("SHA256", value.canonicalize(Nokogiri::XML::XML_C14N_1_0)))
  end

  it "writes the token into the caller's document with sign!" do
    doc = Nokogiri::XML(xml)
    signer.sign!(doc)

    expect(token(doc.to_xml)).to be_a(OpenSSL::PKCS7)
    expect(tsa.requests.last.message_imprint).to eq(expected_imprint(doc.to_xml))
  end

  it "keeps the timestamper when a node is signed by its Id (#96)" do
    doc = Nokogiri::XML(xml)
    signed = signer.sign(doc.root.at_xpath("*")).to_s

    expect(timestamp_node(signed)).not_to be_nil
    expect(tsa.requests.size).to eq(1)
  end

  it "writes no UnsignedProperties without a timestamper" do
    expect(timestamp_node(sign(timestamper: nil))).to be_nil
  end

  describe "a response that does not answer the request" do
    def expect_refused(message, &tamper)
      expect { sign(timestamper: tsa.timestamper(&tamper)) }.to raise_error(HankoXml::SigningError, message)
    end

    it "raises when the TSA refuses" do
      refusing = FakeTsa.new(allowed_digests: %w[sha512])
      expect { sign(timestamper: refusing.timestamper) }
        .to raise_error(HankoXml::SigningError, /did not grant the timestamp \(status 2: /)
    end

    it "raises for a token over another imprint" do
      expect_refused(/does not cover this signature's SignatureValue/) do |request|
        request.tap { |r| r.message_imprint = OpenSSL::Digest.digest("SHA256", "something else") }
      end
    end

    it "raises for a token over the right bytes with another digest" do
      expect_refused(/does not cover this signature's SignatureValue/) do |request|
        imprint = request.message_imprint
        request.tap do |r|
          r.algorithm = "sha512"
          r.message_imprint = imprint + ("\0" * 32)
        end
      end
    end

    it "raises for a token without the request's nonce" do
      expect_refused(/nonce/) { |request| request.tap { |r| r.nonce = r.nonce + 1 } }
      expect_refused(/nonce/) do |request|
        OpenSSL::Timestamp::Request.new.tap do |without_nonce|
          without_nonce.algorithm = request.algorithm
          without_nonce.message_imprint = request.message_imprint
        end
      end
    end

    it "raises for bytes that are not a TimeStampResp, or no bytes" do
      expect_refused(/not a DER TimeStampResp/) { "not DER" }
      expect { sign(timestamper: ->(_request) {}) }.to raise_error(HankoXml::SigningError, /returned NilClass/)
    end
  end

  describe "configuration" do
    it "needs a callable" do
      expect { signer(timestamper: "https://tsa.example") }
        .to raise_error(HankoXml::ConfigurationError, /timestamper: must respond to #call/)
    end

    it "checks the imprint algorithms against the registry and the Signer's policy" do
      expect { signer(timestamp_digest_method: :md5) }
        .to raise_error(HankoXml::ConfigurationError, /timestamp_digest_method: :md5 is not a registered/)
      expect { signer(timestamp_canonicalization_method: :sha256) }
        .to raise_error(HankoXml::ConfigurationError, /timestamp_canonicalization_method: :sha256/)
      expect { signer(timestamp_digest_method: :sha1) }.to raise_error(HankoXml::PolicyError, /sha1/)
      expect(signer(timestamp_digest_method: :sha1, policy: HankoXml::Policy.legacy_sha1).timestamp_digest_method)
        .to eq(:sha1)
    end
  end
end
