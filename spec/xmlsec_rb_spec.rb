# frozen_string_literal: true

require "nokogiri"
require "openssl"
require "pathname"

RSpec.describe XmlsecRb do
  let(:fixtures) { Pathname.new(__dir__).join("fixtures") }
  let(:signed_xml_path) { fixtures.join("signed.xml") }
  let(:signed_xml) { signed_xml_path.read }
  let(:signer_cert_pem) { fixtures.join("signer.crt").read }
  let(:other_cert_pem) { fixtures.join("other.crt").read }

  it "has a version number" do
    expect(XmlsecRb::VERSION).not_to be nil
  end

  it "confirms the linked libxmlsec1 matches the version bindgen ran against" do
    expect(XmlsecRb::Native.check_version).to be true
  end

  describe ".validate" do
    it "validates a signed XML String against a PEM cert String" do
      expect(described_class.validate(signed_xml, signer_cert_pem)).to be true
    end

    it "validates from a Pathname to the signed file, cert as a Pathname" do
      expect(described_class.validate(signed_xml_path, fixtures.join("signer.crt"))).to be true
    end

    it "validates a Nokogiri::XML::Document via its #pointer_id, cert as OpenSSL::X509::Certificate" do
      doc = Nokogiri::XML(signed_xml)
      cert = OpenSSL::X509::Certificate.new(signer_cert_pem)

      expect(described_class.validate(doc, cert)).to be true
    end

    it "returns false when the signature doesn't chain to the given certificate" do
      expect(described_class.validate(signed_xml, other_cert_pem)).to be false
    end

    it "raises XmlsecRb::Error when the document has no <Signature> element" do
      unsigned_xml = "<Envelope xmlns=\"urn:xmlsec_rb:example\"><Data>Hello, world!</Data></Envelope>"

      expect do
        described_class.validate(unsigned_xml, signer_cert_pem)
      end.to raise_error(XmlsecRb::Error, /Signature/)
    end

    it "raises XmlsecRb::Error for unparseable XML" do
      expect do
        described_class.validate("not xml", signer_cert_pem)
      end.to raise_error(XmlsecRb::Error)
    end

    it "raises ArgumentError for an unsupported xml argument type" do
      expect { described_class.validate(42, signer_cert_pem) }.to raise_error(ArgumentError)
    end

    it "raises ArgumentError for an unsupported certificate argument type" do
      expect { described_class.validate(signed_xml, 42) }.to raise_error(ArgumentError)
    end

    describe "different signature formats" do
      # Each fixture was built by hand (Nokogiri C14N + OpenSSL::PKey::RSA#sign,
      # not xmlsec) and cross-checked against the independent `xmlsec1 verify`
      # CLI oracle before being committed -- see spec/fixtures and its git log.
      #
      # signed_detached.xml is the important one: its Reference URI="#payload-1"
      # points at a *sibling* of <Signature>, outside its subtree. Resolving
      # that requires registering ID attributes first (see
      # dsig.rs#register_common_id_attributes) -- unlike signed_enveloping.xml,
      # whose Reference target lives *inside* <Signature>, which xmlsec
      # resolves via a plain subtree search even without registered IDs. This
      # is the "#id" class of bug: two structurally similar references that
      # take different code paths to resolve.
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

          expect(described_class.validate(xml, signer_cert_pem)).to be true
          expect(described_class.validate(xml, other_cert_pem)).to be false
        end
      end
    end
  end
end
