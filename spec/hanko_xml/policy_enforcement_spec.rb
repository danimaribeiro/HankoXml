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
      result = HankoXml::Verifier.new(certificate: signer_cert_pem).verify(signed.to_s)

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::PolicyError)
      expect(result.errors.first.message).to match(/require_signed_root/)
    end

    it "accepts the same document under Policy.fragment" do
      signed = HankoXml.sign(unsigned_xml, key: signer_key_pem, certificate: signer_cert_pem, references: ["#a"])
      result = HankoXml::Verifier
        .new(certificate: signer_cert_pem, policy: HankoXml::Policy.fragment)
        .verify(signed.to_s)

      expect(result.valid?).to be true
    end

    it "accepts a whole-document (URI=\"\") signature under strict" do
      signed = HankoXml.sign(unsigned_xml, key: signer_key_pem, certificate: signer_cert_pem)

      expect(HankoXml.valid?(signed.to_s, certificate: signer_cert_pem)).to be true
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

  # #76: before this field, any DSA key passed once a policy allowed dsa_sha1.
  describe "min_dsa_key_bits" do
    let(:dsa_key) { OpenSSL::PKey::DSA.generate(1024) }
    let(:dsa_policy) { HankoXml::Policy.interop.with(min_dsa_key_bits: 2048) }

    def sign_with_dsa(policy)
      HankoXml.sign(
        unsigned_xml,
        key: dsa_key.to_pem,
        signature_method: :dsa_sha1,
        digest_method: :sha1,
        key_info: [],
        policy: policy
      )
    end

    it "rejects signing with a weaker-than-policy DSA key" do
      expect { sign_with_dsa(dsa_policy) }.to raise_error(
        HankoXml::PolicyError,
        /dsa key is 1024 bits, less than this policy's min_dsa_key_bits/
      )
    end

    it "rejects verifying against a weaker-than-policy trusted DSA key" do
      signed = sign_with_dsa(HankoXml::Policy.interop).to_s
      public_key = dsa_key.public_to_pem

      expect(HankoXml.valid?(signed, key: public_key, policy: HankoXml::Policy.interop)).to be true
      result = HankoXml::Verifier.new(key: public_key, policy: dsa_policy).verify(signed)
      expect(result.errors.first).to be_a(HankoXml::PolicyError)
      expect(result.errors.first.message).to match(/min_dsa_key_bits/)
    end

    it "is 2048 in strict" do
      expect(HankoXml::Policy.strict.min_dsa_key_bits).to eq(2048)
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

      result = HankoXml::Verifier.new(certificate: cert).verify(signed.to_s)

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::PolicyError)
      expect(result.errors.first.message).to match(/min_rsa_key_bits/)
    end

    it "signs and verifies normally with a 2048-bit key" do
      signed = HankoXml.sign(unsigned_xml, key: signer_key_pem, certificate: signer_cert_pem)

      expect(HankoXml.valid?(signed.to_s, certificate: signer_cert_pem)).to be true
    end
  end

  describe "clock_skew" do
    it "rejects a cert that expired outside the skew window" do
      key, cert = cert_expiring_in(-1800) # expired 30 minutes ago
      policy = HankoXml::Policy.strict.with(min_rsa_key_bits: 0, clock_skew: 60)
      signed = HankoXml.sign(unsigned_xml, key: key, certificate: cert, policy: policy)

      result = HankoXml::Verifier
        .new(certificate: cert, policy: policy, verification_time: Time.now)
        .verify(signed.to_s)

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::CertificateExpired)
    end

    it "accepts a cert that expired within the skew window" do
      key, cert = cert_expiring_in(-30) # expired 30 seconds ago
      policy = HankoXml::Policy.strict.with(min_rsa_key_bits: 0, clock_skew: 60)
      signed = HankoXml.sign(unsigned_xml, key: key, certificate: cert, policy: policy)

      result = HankoXml::Verifier
        .new(certificate: cert, policy: policy, verification_time: Time.now)
        .verify(signed.to_s)

      expect(result.valid?).to be true
    end
  end

  # S-07: check_certificate_validity on the certificate:/certificates: trust
  # path. signKey pinning (S-01) means xmlsec never reads KeyInfo to verify
  # the embedded certificate's dates, so this Ruby-side check is the only
  # one that runs here -- store: gets an equivalent, independent check via
  # OpenSSL::X509::StoreContext (#30).
  describe "check_certificate_validity on certificate:" do
    it "rejects an already-expired signing certificate by default, with no verification_time given" do
      key, cert = cert_expiring_in(-3600) # expired an hour ago
      policy = HankoXml::Policy.strict.with(min_rsa_key_bits: 0)
      signed = HankoXml.sign(unsigned_xml, key: key, certificate: cert, policy: policy)

      result = HankoXml::Verifier.new(certificate: cert).verify(signed.to_s)

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::CertificateExpired)
    end

    it "accepts it when verification_time falls inside its original validity window" do
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=expired")
      cert.public_key = key.public_key
      cert.not_before = Time.now - 7200
      cert.not_after = Time.now - 3600 # valid 2h-1h ago, expired since
      cert.sign(key, OpenSSL::Digest.new("SHA256"))
      policy = HankoXml::Policy.strict.with(min_rsa_key_bits: 0)
      signed = HankoXml.sign(unsigned_xml, key: key, certificate: cert, policy: policy)

      result = HankoXml::Verifier.new(certificate: cert, verification_time: Time.now - 5400).verify(signed.to_s)

      expect(result.valid?).to be true
    end

    it "accepts an expired certificate when check_certificate_validity is false" do
      key, cert = cert_expiring_in(-3600)
      policy = HankoXml::Policy.strict.with(min_rsa_key_bits: 0, check_certificate_validity: false)
      signed = HankoXml.sign(unsigned_xml, key: key, certificate: cert, policy: policy)

      result = HankoXml::Verifier.new(certificate: cert, policy: policy).verify(signed.to_s)

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

    # libxml2 before 2.12 caps xs:integer at 24 digits; a 20-octet serial is 49.
    it "accepts a 49-digit X509SerialNumber whatever libxml2 Nokogiri runs on, and still rejects a non-integer" do
      signature = lambda do |serial|
        Nokogiri::XML(<<~XML)
          <Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI=""><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <DigestValue>AA==</DigestValue></Reference></SignedInfo><SignatureValue>AA==</SignatureValue>
            <KeyInfo><X509Data><X509IssuerSerial><X509IssuerName>CN=ca</X509IssuerName>
            <X509SerialNumber>#{serial}</X509SerialNumber></X509IssuerSerial></X509Data></KeyInfo></Signature>
        XML
      end
      schema = HankoXml::Verifier.default_schema

      expect(schema.validate(signature.call("9" * 49))).to be_empty
      expect(schema.validate(signature.call(" -12 "))).to be_empty
      expect(schema.validate(signature.call("12a"))).not_to be_empty
    end

    it "defaults to nil under Policy.permissive" do
      verifier = HankoXml::Verifier.new(certificate: signer_cert_pem, policy: HankoXml::Policy.permissive)

      expect(verifier.schema).to be_nil
    end
  end
end
