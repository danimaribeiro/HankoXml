# frozen_string_literal: true

require "pathname"

RSpec.describe HankoXml::Key do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:key_pem) { fixtures.join("signer.key").read }
  let(:cert_pem) { fixtures.join("signer.crt").read }

  describe ".from_pem" do
    it "loads a private key" do
      key = described_class.from_pem(key_pem)
      expect(key.private_key?).to be true
      expect(key.to_openssl).to be_a(OpenSSL::PKey::PKey)
    end

    it "loads a certificate" do
      key = described_class.from_pem(cert_pem)
      expect(key.certificate?).to be true
      expect(key.to_openssl).to be_a(OpenSSL::X509::Certificate)
    end

    it "raises HankoXml::KeyLoadError for garbage input" do
      expect { described_class.from_pem("not a key") }.to raise_error(HankoXml::KeyLoadError)
    end

    # S-15: classification by PEM block label, not substring.
    it "raises instead of silently dropping the certificate from a key + certificate bundle" do
      [key_pem + cert_pem, cert_pem + key_pem].each do |bundle|
        expect { described_class.from_pem(bundle) }
          .to raise_error(HankoXml::KeyLoadError, /both a certificate and a key/) do |error|
            expect(error.message).not_to include("-----BEGIN")
          end
      end
    end

    it "loads a key whose surrounding text mentions CERTIFICATE" do
      key = described_class.from_pem("Bag Attributes: see CERTIFICATE below\n#{key_pem}")
      expect(key.private_key?).to be true
    end

    it "loads a public key PEM as a public, non-private key" do
      public_pem = OpenSSL::PKey::RSA.new(key_pem).public_to_pem
      key = described_class.from_pem(public_pem)

      expect(key.certificate?).to be false
      expect(key.private_key?).to be false
    end
  end

  describe "#private_key?" do
    it "is false for public-only keys of every type, true for their private halves" do
      rsa = OpenSSL::PKey::RSA.new(key_pem)
      ec = OpenSSL::PKey::EC.generate("prime256v1")
      ed25519 = OpenSSL::PKey.generate_key("ED25519")

      [rsa, ec, ed25519].each do |pkey|
        expect(described_class.new(pkey).private_key?).to be(true), pkey.class.name
        expect(described_class.new(OpenSSL::PKey.read(pkey.public_to_pem)).private_key?).to be(false), pkey.class.name
      end
    end

    it "is false for a certificate" do
      expect(described_class.from_pem(cert_pem).private_key?).to be false
    end
  end

  describe ".from_file" do
    it "reads and parses a PEM file from a Pathname" do
      key = described_class.from_file(fixtures.join("signer.key"))
      expect(key.private_key?).to be true
    end
  end

  describe ".coerce" do
    it "wraps an OpenSSL::PKey::PKey directly" do
      pkey = OpenSSL::PKey::RSA.new(key_pem)
      key = described_class.coerce(pkey)
      expect(key.to_openssl).to eq(pkey)
    end

    it "returns an existing Key unchanged" do
      key = described_class.from_pem(key_pem)
      expect(described_class.coerce(key)).to equal(key)
    end

    it "parses a PEM String" do
      expect(described_class.coerce(key_pem)).to be_private_key
    end

    it "reads a path-like object" do
      expect(described_class.coerce(fixtures.join("signer.key"))).to be_private_key
    end

    it "raises ArgumentError for an unsupported type" do
      expect { described_class.coerce(42) }.to raise_error(ArgumentError)
    end
  end

  describe "#to_pem" do
    it "round-trips through OpenSSL" do
      key = described_class.from_pem(key_pem)
      expect(OpenSSL::PKey::RSA.new(key.to_pem).to_pem).to eq(OpenSSL::PKey::RSA.new(key_pem).to_pem)
    end
  end

  describe "#dispose!" do
    it "marks the key unusable" do
      key = described_class.from_pem(key_pem)
      key.dispose!

      expect(key.disposed?).to be true
      expect { key.to_pem }.to raise_error(HankoXml::KeyLoadError)
      expect { key.to_openssl }.to raise_error(HankoXml::KeyLoadError)
    end
  end

  describe "#inspect / #to_s" do
    it "never includes key material" do
      key = described_class.from_pem(key_pem)
      expect(key.inspect).not_to include(key.to_pem)
      expect(key.inspect).to include("FILTERED")
      expect(key.to_s).to include("FILTERED")
    end
  end
end
