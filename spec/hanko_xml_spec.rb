# frozen_string_literal: true

require "nokogiri"
require "openssl"
require "pathname"

RSpec.describe HankoXml do
  let(:fixtures) { Pathname.new(__dir__).join("fixtures") }
  let(:signed_xml_path) { fixtures.join("signed.xml") }
  let(:signed_xml) { signed_xml_path.read }
  let(:signer_cert_pem) { fixtures.join("signer.crt").read }
  let(:other_cert_pem) { fixtures.join("other.crt").read }

  it "has a version number" do
    expect(HankoXml::VERSION).not_to be nil
  end

  it "confirms the linked libxmlsec1 matches the version bindgen ran against" do
    expect(HankoXml::Native.check_version).to be true
  end

  describe ".verify" do
    it "validates a signed XML String against a PEM cert String" do
      expect(described_class.verify(signed_xml, certificate: signer_cert_pem).valid?).to be true
    end

    it "validates from a Pathname to the signed file, cert as a Pathname" do
      expect(described_class.verify(signed_xml_path, certificate: fixtures.join("signer.crt")).valid?).to be true
    end

    it "validates a Nokogiri::XML::Document via its #pointer_id, cert as OpenSSL::X509::Certificate" do
      doc = Nokogiri::XML(signed_xml)
      cert = OpenSSL::X509::Certificate.new(signer_cert_pem)

      expect(described_class.verify(doc, certificate: cert).valid?).to be true
    end

    it "returns false when the signature doesn't chain to the given certificate" do
      expect(described_class.verify(signed_xml, certificate: other_cert_pem).valid?).to be false
    end

    it "validates with a trust store using the certificate embedded in KeyInfo" do
      store = OpenSSL::X509::Store.new
      store.add_cert(OpenSSL::X509::Certificate.new(signer_cert_pem))

      expect(described_class.verify(signed_xml, store: store).valid?).to be true
    end

    it "validates with a trusted public key by matching KeyInfo certificate public key" do
      signer_key = OpenSSL::X509::Certificate.new(signer_cert_pem).public_key
      other_key = OpenSSL::X509::Certificate.new(other_cert_pem).public_key

      expect(described_class.verify(signed_xml, key: signer_key).valid?).to be true
      expect(described_class.verify(signed_xml, key: other_key).valid?).to be false
    end

    it "raises HankoXml::SignatureMissing when the document has no <Signature> element (using verify!)" do
      unsigned_xml = "<Envelope xmlns=\"urn:hanko_xml:example\"><Data>Hello, world!</Data></Envelope>"

      expect do
        described_class.verify!(unsigned_xml, certificate: signer_cert_pem)
      end.to raise_error(HankoXml::SignatureMissing)
    end

    it "raises HankoXml::ParseError for unparseable XML (using verify!)" do
      expect do
        described_class.verify!("not xml", certificate: signer_cert_pem)
      end.to raise_error(HankoXml::ParseError)
    end

    it "raises ArgumentError for an unsupported xml argument type" do
      expect { described_class.verify(42, certificate: signer_cert_pem) }.to raise_error(ArgumentError)
    end

    it "raises ArgumentError for an unsupported certificate argument type" do
      expect { described_class.verify(signed_xml, certificate: 42) }.to raise_error(ArgumentError)
    end

    describe "different signature formats" do
      {
        "signed_exc_c14n.xml" => "enveloped, Exclusive C14N (SignedInfo canon + digest transform)",
        "signed_sha512.xml" => "enveloped, plain C14N, SHA-512 digest + RSA-SHA512 signature",
        "signed_enveloping.xml" => "enveloping: signed data lives inside <Object> under <Signature>, " \
                                    "Reference URI=\"#object-1\" resolved by ID",
        "signed_detached.xml" => "detached: <Signature> and the signed element are siblings, connected " \
                                  "only by Reference URI=\"#payload-1\" resolved by ID",
        "signed_nfe.xml" => "Brazilian NFe shape: detached (like signed_detached.xml above) with " \
                             "SHA-1 digest + RSA-SHA1 signature, which the NFe technical spec mandates"
      }.each do |filename, description|
        it "validates a #{description} signature" do
          xml = fixtures.join(filename).read

          # NFe uses SHA-1, which strict policy rejects
          policy = filename == "signed_nfe.xml" ? HankoXml::Policy.legacy_sha1 : HankoXml::Policy.strict

          expect(described_class.verify(xml, certificate: signer_cert_pem, policy: policy).valid?).to be true
          expect(described_class.verify(xml, certificate: other_cert_pem, policy: policy).valid?).to be false
        end
      end
    end
  end
end
