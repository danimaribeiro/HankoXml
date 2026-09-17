# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require "pathname"

# #52 / SIGNING_TEST_COVERAGE.md group B: every algorithm choice made
# through the Ruby Signer, checked in <SignedInfo> and verified both
# natively and through HankoXml.verify.
RSpec.describe "HankoXml::Signer algorithms" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:key_pem) { fixtures.join("signer.key").read }
  let(:cert_pem) { fixtures.join("signer.crt").read }
  let(:xml) { %(<Envelope xmlns="urn:x"><Data>A</Data></Envelope>) }
  let(:ds) { { "ds" => HankoXml::NS["ds"] } }
  let(:id_attrs) { %w[Id ID id] }

  def algorithms(signed)
    doc = Nokogiri::XML(signed)
    {
      canonicalization: doc.at_xpath("//ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm", ds).value,
      signature: doc.at_xpath("//ds:SignedInfo/ds:SignatureMethod/@Algorithm", ds).value,
      digest: doc.at_xpath("//ds:Reference/ds:DigestMethod/@Algorithm", ds).value
    }
  end

  def self_signed(key)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=ec signer")
    cert.public_key = OpenSSL::PKey::EC.new(key.public_to_der)
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 3600
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert
  end

  {
    "B1 rsa_sha256 / sha256 / exc_c14n (defaults)" => [:rsa_sha256, :sha256, :exc_c14n, nil],
    "B2 rsa_sha1 / sha1 / c14n under Policy.legacy_sha1" => %i[rsa_sha1 sha1 c14n legacy_sha1],
    "B3 rsa_sha384 / sha384 / c14n11" => [:rsa_sha384, :sha384, :c14n11, nil],
    "B4 rsa_sha512 / sha512 / c14n_with_comments" => [:rsa_sha512, :sha512, :c14n_with_comments, nil]
  }.each do |description, (signature_method, digest_method, canonicalization_method, preset)|
    it "signs and verifies #{description}" do
      policy = preset ? HankoXml::Policy.public_send(preset) : HankoXml::Policy.strict
      signed = HankoXml::Signer.new(
        key: key_pem, certificate: cert_pem, policy: policy,
        signature_method: signature_method, digest_method: digest_method,
        canonicalization_method: canonicalization_method
      ).sign(xml).to_s

      expect(algorithms(signed)).to eq(
        canonicalization: HankoXml::Algorithms.uri_for(:canonicalization, canonicalization_method),
        signature: HankoXml::Algorithms.uri_for(:signature, signature_method),
        digest: HankoXml::Algorithms.uri_for(:digest, digest_method)
      )
      expect(HankoXml::Native.verify(signed, [cert_pem], [], id_attrs, 0, [])[:status]).to eq(:succeeded)
      expect(HankoXml.verify(signed, certificate: cert_pem, policy: policy).valid?).to be true
    end
  end

  it "B5 refuses rsa_sha224 / sha224 under Policy.strict" do
    expect do
      HankoXml::Signer.new(key: key_pem, certificate: cert_pem, signature_method: :rsa_sha224,
                           digest_method: :sha224, canonicalization_method: :exc_c14n_with_comments).sign(xml)
    end.to raise_error(HankoXml::PolicyError, /rsa-sha224/)
  end

  it "B5 signs rsa_sha224 under a policy that allows it" do
    policy = HankoXml::Policy.strict.with(signature_methods: [:rsa_sha224], digest_methods: [:sha224])
    signed = HankoXml::Signer.new(key: key_pem, certificate: cert_pem, policy: policy, signature_method: :rsa_sha224,
                                  digest_method: :sha224).sign(xml).to_s

    expect(HankoXml.verify(signed, certificate: cert_pem, policy: policy).valid?).to be true
    expect(HankoXml.verify(signed, certificate: cert_pem).valid?).to be false
  end

  {
    "B6 ecdsa_sha256 with a P-256 key" => ["prime256v1", :ecdsa_sha256, :sha256, :exc_c14n],
    "B7 ecdsa_sha384 with a P-384 key" => ["secp384r1", :ecdsa_sha384, :sha384, :c14n]
  }.each do |description, (curve, signature_method, digest_method, canonicalization_method)|
    it "signs and verifies #{description}" do
      key = OpenSSL::PKey::EC.generate(curve)
      cert = self_signed(key)
      signed = HankoXml::Signer.new(
        key: key.to_pem, certificate: cert.to_pem, signature_method: signature_method,
        digest_method: digest_method, canonicalization_method: canonicalization_method
      ).sign(xml).to_s

      expect(algorithms(signed)[:signature]).to eq(HankoXml::Algorithms.uri_for(:signature, signature_method))
      expect(HankoXml.verify(signed, certificate: cert.to_pem).valid?).to be true
      expect(HankoXml.verify(signed, key: key.public_to_pem).valid?).to be true
    end
  end

  it "B6 explains an EC key used with the default rsa_sha256 (#70)" do
    key = OpenSSL::PKey::EC.generate("prime256v1")
    expect(HankoXml::Native).not_to receive(:sign)
    expect { HankoXml::Signer.new(key: key.to_pem, certificate: self_signed(key).to_pem).sign(xml) }
      .to raise_error(HankoXml::ConfigurationError, /needs an RSA key, but key: is an EC key; .*:ecdsa_sha256/)
  end

  it "B6 explains an RSA key used with an adopted ecdsa template (#70)" do
    template = HankoXml::Signer.new(key: key_pem, signature_method: :ecdsa_sha256).template(xml)
    doc = Nokogiri::XML(xml)
    doc.root.add_child(template)

    expect { HankoXml::Signer.new(key: key_pem, certificate: cert_pem).sign(doc) }
      .to raise_error(HankoXml::ConfigurationError, /:ecdsa_sha256 needs an EC key, .*:rsa_sha256/)
  end

  it "B8 refuses hmac_sha256 under Policy.strict, and cannot sign it at all without an HMAC key API" do
    expect { HankoXml::Signer.new(key: key_pem, certificate: cert_pem, signature_method: :hmac_sha256).sign(xml) }
      .to raise_error(HankoXml::PolicyError, /hmac/)
    expect do
      HankoXml::Signer.new(key: key_pem, certificate: cert_pem, signature_method: :hmac_sha256,
                           policy: HankoXml::Policy.permissive).sign(xml)
    end.to raise_error(HankoXml::SigningError)
  end

  it "B9 refuses dsa_sha1 under Policy.strict, and explains it needs a DSA key" do
    expect { HankoXml::Signer.new(key: key_pem, certificate: cert_pem, signature_method: :dsa_sha1).sign(xml) }
      .to raise_error(HankoXml::PolicyError)
    expect do
      HankoXml::Signer.new(key: key_pem, certificate: cert_pem, signature_method: :dsa_sha1,
                           policy: HankoXml::Policy.permissive).sign(xml)
    end.to raise_error(HankoXml::ConfigurationError, /needs a DSA key/)
  end

  it "B10 rejects an unknown signature method before reaching xmlsec" do
    expect(HankoXml::Native).not_to receive(:sign)
    expect { HankoXml::Signer.new(key: key_pem, certificate: cert_pem, signature_method: :nope).sign(xml) }
      .to raise_error(HankoXml::PolicyError)
    expect do
      HankoXml::Signer.new(key: key_pem, certificate: cert_pem, signature_method: "urn:nope",
                           policy: HankoXml::Policy.permissive).sign(xml)
    end.to raise_error(HankoXml::PolicyError, /urn:nope/)
  end

  it "B11 fails cleanly when signing with a registered transform xmlsec does not know" do
    name = :"spec_b11_transform_#{Process.pid}"
    HankoXml::Algorithms.register(:transform, name, "urn:hanko-xml:spec:#{name}", secure: true)
    policy = HankoXml::Policy.strict.with(transforms: [:enveloped_signature, name])
    signer = HankoXml::Signer.new(
      key: key_pem, certificate: cert_pem, policy: policy,
      references: [HankoXml::Reference.new(uri: "", transforms: [:enveloped_signature, name])]
    )

    expect { signer.sign(xml) }.to raise_error(HankoXml::SigningError)
  end
end
