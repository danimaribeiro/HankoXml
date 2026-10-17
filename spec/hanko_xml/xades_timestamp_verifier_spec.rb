# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require "pathname"
require_relative "../support/fake_tsa"

# #163: XAdES-T verification. A SignatureTimeStamp lies outside everything the
# signature covers, so each one must verify (TSA signature and chain through
# OpenSSL, imprint over the xmlsec-canonicalized SignatureValue) or the
# signature fails: fail closed.
RSpec.describe HankoXml::Xades::Verifier, "SignatureTimeStamp" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:key_pem) { fixtures.join("signer.key").read }
  let(:cert_pem) { fixtures.join("signer.crt").read }
  # The extra prefix makes inclusive and exclusive c14n of SignatureValue differ.
  let(:xml) { %(<Invoice xmlns="urn:x" xmlns:extra="urn:extra"><Total Id="total">150.00</Total></Invoice>) }
  let(:ns) { { "ds" => HankoXml::NS["ds"], "xades" => HankoXml::Xades::NS } }
  let(:tsa) { FakeTsa.new }
  let(:signed) { sign }

  def sign(source = xml, timestamper: tsa.timestamper, **options)
    HankoXml::Xades::Signer.new(key: key_pem, certificate: cert_pem, timestamper: timestamper, **options)
                           .sign(source).to_s
  end

  def verifier(**options)
    described_class.new(certificate: cert_pem, **{ tsa_certificates: [tsa.ca_certificate] }.merge(options))
  end

  def verify(document, **options)
    verifier(**options).verify(document)
  end

  # The signed document with its SignatureTimeStamp changed by the block.
  # Nothing signed covers it, so XML-DSig and the signed properties still verify.
  def tampered(document = signed)
    doc = Nokogiri::XML(document)
    yield doc.at_xpath("//xades:SignatureTimeStamp", ns), doc
    HankoXml.serialize(doc)
  end

  def expect_invalid(document, message, **options)
    result = verify(document, **options)
    expect(result.valid?).to be false
    expect(result.signature_timestamps).to be_nil
    expect(result.errors.first).to be_a(HankoXml::VerificationError)
    expect(result.errors.first.message).to match(message)
  end

  describe "a timestamped signature" do
    it "verifies, and reports the TSA's time, serial, certificate and digest" do
      result = verify(signed)
      timestamp = result.signature_timestamps.first

      expect(result.errors).to be_empty
      expect(result.signature_timestamps.size).to eq(1)
      expect(timestamp).to be_frozen
      expect(timestamp.id).to end_with("-sigts")
      expect(timestamp.time).to eq(Time.utc(2026, 9, 17, 14, 33, 0))
      expect(timestamp.serial_number).to eq(1)
      expect(timestamp.tsa_certificate.subject.to_s).to eq("/CN=HankoXml Test TSA")
      expect(timestamp.digest_method).to eq(HankoXml::Algorithms.uri_for(:digest, :sha256))
      expect(timestamp.policy_id).to eq("1.2.3.4.1")
      expect(result.timestamp_time).to eq(timestamp.time)
    end

    it "takes the TSA trust as tsa_store: too" do
      expect(verify(signed, tsa_certificates: nil, tsa_store: tsa.store)).to be_valid
    end

    it "verifies with timestamps: :require" do
      expect(verify(signed, timestamps: :require)).to be_valid
    end

    it "verifies inclusive c14n and SHA-512 imprints" do
      document = sign(timestamp_canonicalization_method: :c14n, timestamp_digest_method: :sha512)
      result = verify(document)

      expect(result.errors).to be_empty
      expect(result.signature_timestamps.first.digest_method).to eq(HankoXml::Algorithms.uri_for(:digest, :sha512))
    end

    it "verifies every SignatureTimeStamp, and #timestamp_time is the earliest" do
      earlier = FakeTsa.new(name: "Earlier TSA", gen_time: Time.utc(2026, 9, 17, 14, 32, 30), serial: 7)
      document = tampered do |timestamp, _doc|
        second = timestamp.dup(1)
        second["Id"] = "second-ts"
        token = earlier.respond(tsa.requests.last).token.to_der
        second.at_xpath("xades:EncapsulatedTimeStamp", ns).content = [token].pack("m0")
        timestamp.add_next_sibling(second)
      end
      store = tsa.store.tap { |s| s.add_cert(earlier.ca_certificate) }
      result = verify(document, tsa_certificates: nil, tsa_store: store)

      expect(result.errors).to be_empty
      expect(result.signature_timestamps.map(&:serial_number)).to eq([1, 7])
      expect(result.timestamp_time).to eq(Time.utc(2026, 9, 17, 14, 32, 30))
    end

    it "is verified by verify_all too" do
      expect(verifier.verify_all(signed).map(&:signature_timestamps).map(&:size)).to eq([1])
    end
  end

  describe "fail closed" do
    it "fails without TSA trust, naming the options" do
      expect_invalid(signed, /pass tsa_store: or tsa_certificates:/, tsa_certificates: nil)
    end

    it "fails for a TSA the caller does not trust, even one with the same names" do
      expect_invalid(signed, /does not verify/, tsa_certificates: [FakeTsa.new.ca_certificate])
      expect_invalid(signed, /does not verify/, tsa_certificates: [FakeTsa.new(name: "Other TSA").ca_certificate])
    end

    it "fails for a token over another signature's SignatureValue" do
      other = Nokogiri::XML(sign).at_xpath("//xades:EncapsulatedTimeStamp", ns).text
      document = tampered { |timestamp, _doc| timestamp.at_xpath("xades:EncapsulatedTimeStamp", ns).content = other }

      expect_invalid(document, /does not cover this signature's SignatureValue/)
    end

    it "fails when the CanonicalizationMethod is changed, since the imprint is over other bytes" do
      document = tampered do |timestamp, _doc|
        timestamp.at_xpath("ds:CanonicalizationMethod", ns)["Algorithm"] =
          HankoXml::Algorithms.uri_for(:canonicalization, :c14n)
      end

      expect_invalid(document, /does not verify/)
    end

    it "fails for a CanonicalizationMethod the policy or xmlsec does not accept" do
      document = tampered do |timestamp, _doc|
        timestamp.at_xpath("ds:CanonicalizationMethod", ns)["Algorithm"] = "http://www.w3.org/TR/1999/REC-xslt-19991116"
      end
      result = verify(document)

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::PolicyError)
    end

    it "fails without a CanonicalizationMethod" do
      document = tampered { |timestamp, _doc| timestamp.at_xpath("ds:CanonicalizationMethod", ns).unlink }
      expect_invalid(document, /without a CanonicalizationMethod/)
    end

    it "fails for a SHA-1 imprint under Policy.strict, and accepts it under Policy.legacy_sha1" do
      document = sign(timestamp_digest_method: :sha1, policy: HankoXml::Policy.legacy_sha1)
      result = verify(document)

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::PolicyError)
      expect(verify(document, policy: HankoXml::Policy.legacy_sha1)).to be_valid
    end

    it "fails for a token that is not Base64 or not a TimeStampToken" do
      ["not base64!", ["not a token"].pack("m0")].each do |content|
        document = tampered do |timestamp, _doc|
          timestamp.at_xpath("xades:EncapsulatedTimeStamp", ns).content = content
        end
        expect_invalid(document, /EncapsulatedTimeStamp> is not/)
      end
    end

    it "fails for children a SignatureTimeStamp may not hold here" do
      %w[Include ReferenceInfo XMLTimeStamp].each do |name|
        document = tampered do |timestamp, doc|
          node = doc.create_element(name)
          node.namespace = timestamp.namespace
          timestamp.add_child(node)
        end
        expect_invalid(document, /holds only CanonicalizationMethod and EncapsulatedTimeStamp/)
      end

      document = tampered do |timestamp, _doc|
        timestamp.add_child(timestamp.at_xpath("xades:EncapsulatedTimeStamp", ns).dup(1))
      end
      expect_invalid(document, /exactly one <xades:EncapsulatedTimeStamp>/)
    end

    it "fails for a second UnsignedProperties or UnsignedSignatureProperties" do
      %w[.. ../..].each do |up|
        document = tampered do |timestamp, _doc|
          copy = timestamp.at_xpath(up).dup(1)
          copy.xpath(".//@Id").each(&:unlink)
          timestamp.at_xpath(up).add_next_sibling(copy)
        end
        expect_invalid(document, /at most one <xades:Unsigned/)
      end
    end

    it "reads SignatureTimeStamps only inside this signature's QualifyingProperties" do
      document = tampered do |timestamp, doc|
        unsigned = timestamp.at_xpath("../..")
        decoy = doc.create_element("Object")
        decoy.namespace = doc.at_xpath("//ds:Signature", ns).namespace
        decoy.add_namespace_definition("xades", HankoXml::Xades::NS)
        decoy.add_child(unsigned.unlink)
        doc.at_xpath("//ds:Signature", ns).add_child(decoy)
      end

      expect(verify(document).signature_timestamps).to eq([])
      expect_invalid(document, /timestamps: :require, but the signature has no/, timestamps: :require)
    end
  end

  describe "timestamps:" do
    let(:untimestamped) { sign(timestamper: nil) }

    it ":verify (the default) accepts a signature without timestamps" do
      result = verify(untimestamped, tsa_certificates: nil)

      expect(result).to be_valid
      expect(result.signature_timestamps).to eq([])
      expect(result.timestamp_time).to be_nil
    end

    it ":require fails a signature without one" do
      expect_invalid(untimestamped, /timestamps: :require, but the signature has no/, timestamps: :require)
    end

    it ":ignore does not read them, the XAdES-B behavior" do
      garbled = tampered { |timestamp, _doc| timestamp.content = "garbage" }
      result = verify(garbled, timestamps: :ignore, tsa_certificates: nil)

      expect(result).to be_valid
      expect(result.signature_timestamps).to be_nil
    end
  end

  it "keeps a missing signature a Xades::Verification" do
    expect(verifier.verify("<a/>")).to be_a(HankoXml::Xades::Verification)
  end

  describe "configuration" do
    it "refuses unknown modes and inconsistent TSA trust" do
      expect { verifier(timestamps: :maybe) }.to raise_error(HankoXml::ConfigurationError, /timestamps: must be one of/)
      expect { verifier(timestamps: :require, tsa_certificates: nil) }
        .to raise_error(HankoXml::ConfigurationError, /:require needs tsa_store: or tsa_certificates:/)
      expect { verifier(tsa_store: tsa.store) }.to raise_error(HankoXml::ConfigurationError, /not both/)
      expect { verifier(tsa_certificates: nil, tsa_store: [tsa.ca_certificate]) }
        .to raise_error(HankoXml::ConfigurationError, /must be an OpenSSL::X509::Store/)
      expect { verifier(tsa_certificates: []) }.to raise_error(HankoXml::ConfigurationError, /must not be empty/)
      expect { verifier(tsa_certificates: [key_pem]) }
        .to raise_error(HankoXml::ConfigurationError, /must be X.509 certificates/)
    end

    it "takes TSA certificates as PEM" do
      expect(verify(signed, tsa_certificates: [tsa.ca_certificate.to_pem])).to be_valid
    end
  end
end
