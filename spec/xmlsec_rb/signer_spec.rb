# frozen_string_literal: true

require "nokogiri"
require "openssl"
require "pathname"

RSpec.describe XmlsecRb::Signer do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:key_pem) { fixtures.join("signer.key").read }
  let(:cert_pem) { fixtures.join("signer.crt").read }

  it "coerces key: / certificate: into XmlsecRb::Key" do
    signer = described_class.new(key: key_pem, certificate: cert_pem)
    expect(signer.key).to be_a(XmlsecRb::Key)
    expect(signer.certificate).to be_a(XmlsecRb::Key)
  end

  it "applies the documented defaults" do
    signer = described_class.new(key: key_pem)
    expect(signer.signature_method).to eq(:rsa_sha256)
    expect(signer.canonicalization_method).to eq(:exc_c14n)
    expect(signer.digest_method).to eq(:sha256)
    expect(signer.key_info.map(&:name)).to eq([:x509_certificate])
    expect(signer.placement).to be_a(XmlsecRb::Placement)
    expect(signer.placement.mode).to eq(:append_to_root)
    expect(signer.id_attributes).to eq(%w[Id ID id])
    expect(signer.policy).to equal(XmlsecRb::Policy.strict)
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
      s.placement = XmlsecRb::Placement.detached
    end

    expect(signer.signature_method).to eq(:rsa_sha1)
    expect(signer.canonicalization_method).to eq(:c14n)
    expect(signer.references.size).to eq(1)
    expect(signer.references.first.uri).to eq("#NFe1")
    expect(signer.key_info.map(&:name)).to eq([:x509_certificate])
    expect(signer.placement).to be_detached
  end

  it "raises XmlsecRb::ConfigurationError when key: is not key material or a Key" do
    expect { described_class.new(key: 42) }.to raise_error(XmlsecRb::ConfigurationError, /external signers/)
  end

  it "raises XmlsecRb::ConfigurationError for an unknown template: mode" do
    expect { described_class.new(key: key_pem, template: :nonsense) }.to raise_error(XmlsecRb::ConfigurationError)
  end

  describe "#to_h" do
    it "reflects the resolved configuration" do
      signer = described_class.new(key: key_pem, certificate: cert_pem)
      h = signer.to_h
      expect(h[:signature_method]).to eq(:rsa_sha256)
      expect(h[:template]).to eq(:adopt)
    end
  end

  describe "#sign / #sign!" do
    it "are not implemented yet (Phase 2/3)" do
      signer = described_class.new(key: key_pem)
      expect { signer.sign("<a/>") }.to raise_error(NotImplementedError, %r{Phase 2/3})
      expect { signer.sign!(Nokogiri::XML("<a/>")) }.to raise_error(NotImplementedError, %r{Phase 2/3})
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
