# frozen_string_literal: true

require "nokogiri"
require "openssl"
require "pathname"

RSpec.describe HankoXml::Signer do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:key_pem) { fixtures.join("signer.key").read }
  let(:cert_pem) { fixtures.join("signer.crt").read }

  it "coerces key: / certificate: into HankoXml::Key" do
    signer = described_class.new(key: key_pem, certificate: cert_pem)
    expect(signer.key).to be_a(HankoXml::Key)
    expect(signer.certificate).to be_a(HankoXml::Key)
  end

  it "applies the documented defaults" do
    signer = described_class.new(key: key_pem)
    expect(signer.signature_method).to eq(:rsa_sha256)
    expect(signer.canonicalization_method).to eq(:exc_c14n)
    expect(signer.digest_method).to eq(:sha256)
    expect(signer.key_info.map(&:name)).to eq([:x509_certificate])
    expect(signer.placement).to be_a(HankoXml::Placement)
    expect(signer.placement.mode).to eq(:append_to_root)
    expect(signer.id_attributes).to eq(%w[Id ID id])
    expect(signer.policy).to equal(HankoXml::Policy.strict)
    expect(signer.template_mode).to eq(:adopt)
  end

  it "is frozen after construction" do
    expect(described_class.new(key: key_pem)).to be_frozen
  end

  it "runs the configuration block before freezing, mutating via the builder" do
    signer = described_class.new(key: key_pem) do |s|
      s.signature_method = :rsa_sha1
      s.canonicalization_method = :c14n
      s.reference "#NFe1", transforms: %i[enveloped_signature c14n], digest_method: :sha1
      s.key_info :x509_certificate
      s.placement = HankoXml::Placement.detached
    end

    expect(signer.signature_method).to eq(:rsa_sha1)
    expect(signer.canonicalization_method).to eq(:c14n)
    expect(signer.references.size).to eq(1)
    expect(signer.references.first.uri).to eq("#NFe1")
    expect(signer.key_info.map(&:name)).to eq([:x509_certificate])
    expect(signer.placement).to be_detached
  end

  it "raises HankoXml::ConfigurationError when key: is not key material or a Key" do
    expect { described_class.new(key: 42) }.to raise_error(HankoXml::ConfigurationError, /external signers/)
  end

  it "raises HankoXml::ConfigurationError for an unknown template: mode" do
    expect { described_class.new(key: key_pem, template: :nonsense) }.to raise_error(HankoXml::ConfigurationError)
  end

  describe "key:/certificate: pairing (S-14)" do
    let(:other_key_pem) { fixtures.join("other.key").read }
    let(:other_cert_pem) { fixtures.join("other.crt").read }

    it "raises HankoXml::ConfigurationError when key: does not match certificate:" do
      expect { described_class.new(key: other_key_pem, certificate: cert_pem) }
        .to raise_error(HankoXml::ConfigurationError, /does not match certificate/)
    end

    it "checks OpenSSL objects and HankoXml::Key the same as PEM Strings" do
      expect do
        described_class.new(key: HankoXml::Key.coerce(OpenSSL::PKey::RSA.new(other_key_pem)),
                            certificate: OpenSSL::X509::Certificate.new(cert_pem))
      end.to raise_error(HankoXml::ConfigurationError)
    end

    it "checks the pair after the configuration block reassigns it" do
      expect do
        described_class.new(key: key_pem, certificate: cert_pem) do |s|
          s.certificate = HankoXml::Key.coerce(other_cert_pem)
        end
      end.to raise_error(HankoXml::ConfigurationError, /does not match certificate/)
    end

    it "rejects the mismatch through HankoXml.sign before any signature is produced" do
      xml = "<root><a>1</a></root>"
      expect { HankoXml.sign(xml, key: other_key_pem, certificate: cert_pem) }
        .to raise_error(HankoXml::ConfigurationError)
    end

    it "never puts key material in the error message" do
      expect { described_class.new(key: other_key_pem, certificate: cert_pem) }.to raise_error do |error|
        expect(error.message).not_to include(other_key_pem)
        expect(error.message).not_to include("PRIVATE KEY")
      end
    end

    it "accepts matching pairs and a key: with no certificate:" do
      expect { described_class.new(key: key_pem, certificate: cert_pem) }.not_to raise_error
      expect { described_class.new(key: other_key_pem, certificate: other_cert_pem) }.not_to raise_error
      expect { described_class.new(key: other_key_pem) }.not_to raise_error
    end
  end

  describe "#to_h" do
    it "reflects the resolved configuration" do
      signer = described_class.new(key: key_pem, certificate: cert_pem)
      h = signer.to_h
      expect(h[:signature_method]).to eq(:rsa_sha256)
      expect(h[:template]).to eq(:adopt)
    end
  end

  describe "#inspect" do
    it "never includes key material" do
      signer = described_class.new(key: key_pem)
      expect(signer.inspect).to include("FILTERED")
      expect(signer.inspect).not_to include(key_pem)
    end
  end
end
