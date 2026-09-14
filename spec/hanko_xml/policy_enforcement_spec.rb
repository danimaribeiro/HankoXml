# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require "pathname"

# S-06: Policy fields that were documented as enforced but never checked --
# require_signed_root, reject_duplicate_ids, max_document_size,
# min_rsa_key_bits, min_ec_key_bits, clock_skew, schema, and the
# allow_hmac + certificate-trust confusion-attack guard.
RSpec.describe "S-06 Policy enforcement" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:signer_key_pem) { fixtures.join("signer.key").read }
  let(:signer_cert_pem) { fixtures.join("signer.crt").read }
  let(:unsigned_xml) { %(<Envelope xmlns="urn:hanko_xml:example"><Data Id="a">A</Data></Envelope>) }

  def weak_rsa_cert
    key = OpenSSL::PKey::RSA.new(1024)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=weak")
    cert.public_key = key.public_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 3600
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    [key, cert]
  end

  def cert_expiring_in(seconds_from_now, key: OpenSSL::PKey::RSA.new(2048))
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=expiring")
    cert.public_key = key.public_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + seconds_from_now
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    [key, cert]
  end

  describe "require_signed_root" do
    it "rejects a fragment-only signature under strict by default" do
      signed = HankoXml.sign(unsigned_xml, key: signer_key_pem, certificate: signer_cert_pem, references: ["#a"])
      result = HankoXml.verify(signed.to_s, certificate: signer_cert_pem)

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::PolicyError)
      expect(result.errors.first.message).to match(/require_signed_root/)
    end

    it "accepts the same document under Policy.fragment" do
      signed = HankoXml.sign(unsigned_xml, key: signer_key_pem, certificate: signer_cert_pem, references: ["#a"])
      result = HankoXml.verify(signed.to_s, certificate: signer_cert_pem, policy: HankoXml::Policy.fragment)

      expect(result.valid?).to be true
    end

    it "accepts a whole-document (URI=\"\") signature under strict" do
      signed = HankoXml.sign(unsigned_xml, key: signer_key_pem, certificate: signer_cert_pem)

      expect(HankoXml.verify(signed.to_s, certificate: signer_cert_pem).valid?).to be true
    end
  end

  describe "reject_duplicate_ids" do
    let(:duplicate_id_xml) do
      %(<Envelope xmlns="urn:hanko_xml:example"><A Id="dup">1</A><B Id="dup">2</B></Envelope>)
    end

    it "rejects signing a document with duplicate ID attribute values under strict" do
      expect do
        HankoXml.sign(duplicate_id_xml, key: signer_key_pem, certificate: signer_cert_pem)
      end.to raise_error(HankoXml::PolicyError, /reject_duplicate_ids/)
    end

    it "allows it when reject_duplicate_ids is false" do
      policy = HankoXml::Policy.strict.with(reject_duplicate_ids: false)

      expect do
        HankoXml.sign(duplicate_id_xml, key: signer_key_pem, certificate: signer_cert_pem, policy: policy)
      end.not_to raise_error
    end
  end

  describe "max_document_size" do
    it "rejects signing a document over the configured limit" do
      policy = HankoXml::Policy.strict.with(max_document_size: 16)

      expect do
        HankoXml.sign(unsigned_xml, key: signer_key_pem, certificate: signer_cert_pem, policy: policy)
      end.to raise_error(HankoXml::PolicyError, /max_document_size/)
    end
  end

  describe "min_rsa_key_bits" do
    it "rejects signing with a weaker-than-policy RSA key" do
      key, cert = weak_rsa_cert

      expect do
        HankoXml.sign(unsigned_xml, key: key, certificate: cert)
      end.to raise_error(HankoXml::PolicyError, /min_rsa_key_bits/)
    end

    it "rejects verifying against a weaker-than-policy trusted RSA certificate" do
      key, cert = weak_rsa_cert
      permissive_key_size = HankoXml::Policy.strict.with(min_rsa_key_bits: 0)
      signed = HankoXml.sign(unsigned_xml, key: key, certificate: cert, policy: permissive_key_size)

      result = HankoXml.verify(signed.to_s, certificate: cert)

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::PolicyError)
      expect(result.errors.first.message).to match(/min_rsa_key_bits/)
    end

    it "signs and verifies normally with a 2048-bit key" do
      signed = HankoXml.sign(unsigned_xml, key: signer_key_pem, certificate: signer_cert_pem)

      expect(HankoXml.verify(signed.to_s, certificate: signer_cert_pem).valid?).to be true
    end
  end

  describe "clock_skew" do
    it "rejects a cert that expired outside the skew window" do
      key, cert = cert_expiring_in(-1800) # expired 30 minutes ago
      policy = HankoXml::Policy.strict.with(min_rsa_key_bits: 0, clock_skew: 60)
      signed = HankoXml.sign(unsigned_xml, key: key, certificate: cert, policy: policy)

      result = HankoXml.verify(signed.to_s, certificate: cert, policy: policy, verification_time: Time.now)

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::CertificateExpired)
    end

    it "accepts a cert that expired within the skew window" do
      key, cert = cert_expiring_in(-30) # expired 30 seconds ago
      policy = HankoXml::Policy.strict.with(min_rsa_key_bits: 0, clock_skew: 60)
      signed = HankoXml.sign(unsigned_xml, key: key, certificate: cert, policy: policy)

      result = HankoXml.verify(signed.to_s, certificate: cert, policy: policy, verification_time: Time.now)

      expect(result.valid?).to be true
    end
  end

  describe "schema (Policy.strict.schema == :default wired to Verifier)" do
    it "defaults Verifier#schema from the policy without an explicit schema:" do
      verifier = HankoXml::Verifier.new(certificate: signer_cert_pem)

      expect(verifier.schema).to eq(:default)
    end

    it "still honors an explicit schema: nil override" do
      verifier = HankoXml::Verifier.new(certificate: signer_cert_pem, schema: nil)

      expect(verifier.schema).to be_nil
    end

    it "defaults to nil under Policy.permissive" do
      verifier = HankoXml::Verifier.new(certificate: signer_cert_pem, policy: HankoXml::Policy.permissive)

      expect(verifier.schema).to be_nil
    end
  end
end
