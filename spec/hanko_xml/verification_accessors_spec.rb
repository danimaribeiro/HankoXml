# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require "pathname"

# #104: Verification#signed_info, #certificate_chain and #key_info.
module VerificationAccessorsSpecHelpers
  module_function

  def issue_cert(subject:, key:, serial:, is_ca:, issuer_cert: nil, issuer_key: nil)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{subject}")
    cert.issuer = issuer_cert ? issuer_cert.subject : cert.subject
    cert.public_key = key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 86_400
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer_cert || cert
    cert.add_extension(factory.create_extension("basicConstraints", is_ca ? "CA:TRUE" : "CA:FALSE", true))
    cert.add_extension(factory.create_extension("keyUsage", is_ca ? "keyCertSign,cRLSign" : "digitalSignature", true))
    cert.add_extension(factory.create_extension("subjectKeyIdentifier", "hash", false))
    cert.add_extension(factory.create_extension("authorityKeyIdentifier", "keyid:always", false)) if issuer_cert
    cert.sign(issuer_key || key, OpenSSL::Digest.new("SHA256"))
    cert
  end
end

RSpec.describe "Verification#signed_info, #certificate_chain, #key_info (#104)" do
  before(:context) do
    helpers = VerificationAccessorsSpecHelpers
    @root_key = OpenSSL::PKey::RSA.new(2048)
    @inter_key = OpenSSL::PKey::RSA.new(2048)
    @leaf_key = OpenSSL::PKey::RSA.new(2048)
    @root = helpers.issue_cert(subject: "accessors-root", key: @root_key, serial: 1, is_ca: true)
    @inter = helpers.issue_cert(subject: "accessors-inter", key: @inter_key, serial: 2, is_ca: true,
                                issuer_cert: @root, issuer_key: @root_key)
    @leaf = helpers.issue_cert(subject: "accessors-leaf", key: @leaf_key, serial: 3, is_ca: false,
                               issuer_cert: @inter, issuer_key: @inter_key)
  end

  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:signer_cert) { OpenSSL::X509::Certificate.new(fixtures.join("signer.crt").read) }
  let(:xml) { %(<Envelope xmlns="urn:hanko_xml:example"><Data>Hello</Data></Envelope>) }
  let(:store) { OpenSSL::X509::Store.new.tap { |s| s.add_cert(@root) } }
  let(:chain_signed) do
    HankoXml.sign(xml, key: @leaf_key, certificate: @leaf, certificates: [@inter]).to_s
  end
  let(:pinned_signed) do
    HankoXml.sign(xml, key: fixtures.join("signer.key").read, certificate: signer_cert,
                       key_info: [{ key_name: "idp-1" }, :x509_certificate]).to_s
  end

  describe "#certificate_chain" do
    it "is the chain OpenSSL validated under store:, leaf first up to the anchor" do
      result = HankoXml::Verifier.new(store: store).verify(chain_signed)

      expect(result).to be_valid
      expect(result.certificate_chain.map(&:subject).map(&:to_s))
        .to eq(["/CN=accessors-leaf", "/CN=accessors-inter", "/CN=accessors-root"])
      expect(result.certificate_chain.first).to eq(result.certificate)
      expect(result.certificate_chain).to be_frozen
    end

    it "is the pinned certificate for certificate: and certificates:" do
      expect(HankoXml::Verifier.new(certificate: signer_cert).verify(pinned_signed).certificate_chain)
        .to eq([signer_cert])
      expect(HankoXml::Verifier.new(certificates: [@root, signer_cert]).verify(pinned_signed).certificate_chain)
        .to eq([signer_cert])
    end

    it "is empty for a bare public key" do
      result = HankoXml::Verifier.new(key: signer_cert.public_key).verify(pinned_signed)

      expect(result).to be_valid
      expect(result.certificate_chain).to eq([])
    end

    it "is empty when verification failed, even after the chain validated" do
      tampered = chain_signed.sub("Hello", "Bye")
      result = HankoXml::Verifier.new(store: store).verify(tampered)

      expect(result).not_to be_valid
      expect(result.certificate_chain).to eq([])
    end

    it "carries through Xades::Verifier" do
      signed = HankoXml::Xades::Signer.new(key: @leaf_key, certificate: @leaf, certificates: [@inter]).sign(xml).to_s
      result = HankoXml::Xades::Verifier.new(store: store).verify(signed)

      expect(result).to be_valid
      expect(result.certificate_chain.size).to eq(3)
    end
  end

  describe "#signed_info" do
    it "is the verified <SignedInfo> once the signature held" do
      result = HankoXml::Verifier.new(certificate: signer_cert).verify(pinned_signed)

      expect(result.signed_info).to equal(result.signature_info)
      expect(result.signed_info.references.size).to eq(1)
      expect(result.signed_info).to be_frozen
    end

    it "is nil when it did not, so it never stands for unauthenticated claims" do
      result = HankoXml::Verifier.new(certificate: signer_cert).verify(pinned_signed.sub("Hello", "Bye"))

      expect(result.signature_info).not_to be_nil
      expect(result.signed_info).to be_nil
    end
  end

  describe "#key_info" do
    it "reports what <KeyInfo> claimed, whether or not it held" do
      [pinned_signed, pinned_signed.sub("Hello", "Bye")].each do |doc|
        key_info = HankoXml::Verifier.new(certificate: signer_cert).verify(doc).key_info

        expect(key_info).to be_a(HankoXml::KeyInfo::Parsed)
        expect(key_info.key_names).to eq(["idp-1"])
        expect(key_info.certificates.map { |pem| OpenSSL::X509::Certificate.new(pem) }).to eq([signer_cert])
        expect(key_info).to be_frozen
      end
    end

    it "is never the trust decision: a forged <KeyInfo> does not change the pinned key" do
      # <KeyInfo> is outside the enveloped Reference, so adding a certificate
      # to it leaves the signature intact.
      body = @leaf.to_pem.gsub(/-----[A-Z ]+-----|\s/, "")
      forged = pinned_signed.sub(%r{</(\w+:)?X509Certificate>}) do |close|
        prefix = Regexp.last_match(1)
        "#{close}<#{prefix}X509Certificate>#{body}</#{prefix}X509Certificate>"
      end
      result = HankoXml::Verifier.new(certificate: signer_cert).verify(forged)

      expect(result.key_info.certificates.size).to eq(2)
      expect(result.certificate_chain).to eq([signer_cert])
    end

    it "is nil when <SignedInfo> was never read" do
      expect(HankoXml::Verifier.new(certificate: signer_cert).verify("<doc/>").key_info).to be_nil
    end
  end
end
