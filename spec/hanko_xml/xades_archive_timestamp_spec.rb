# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require_relative "../support/fake_tsa"
require_relative "../support/fake_pki"

# #169: XAdES-LTA. Xades::Augmenter adds a <xades141:ArchiveTimeStamp> over
# the signature and everything embedded before it (EN 319 132-1 §5.5.2.2),
# and Xades::Verifier verifies every one, failing closed. The input
# algorithm itself is pinned against a real DSS signature in the interop
# suite (SignXML's HU_POL-3).
RSpec.describe HankoXml::Xades::Augmenter, "archive_timestamp:" do
  let(:hour) { 3600 }
  let(:time) { Time.at((Time.now.utc - (30 * 86_400)).to_i).utc }
  let(:pki) { FakePki.new(leaf_from: time - (200 * 86_400), leaf_to: Time.now.utc + (365 * 86_400)) }
  let(:tsa) { FakeTsa.new(gen_time: time) }
  let(:xml) { %(<Invoice xmlns="urn:x"><Total Id="total">150.00</Total></Invoice>) }
  let(:ns) { { "ds" => HankoXml::NS["ds"], "xades" => HankoXml::Xades::NS, "xades141" => HankoXml::Xades::NS141 } }
  let(:validation_data) { { certificates: [pki.leaf, pki.root], ocsp_responses: [pki.ocsp(this_update: time + hour)] } }
  let(:lt) { sign(timestamper: tsa.timestamper, validation_data: validation_data) }
  let(:lta) { described_class.new(timestamper: tsa.timestamper, archive_timestamp: true).augment(lt).to_s }

  def sign(**options, &block)
    HankoXml::Xades::Signer.new(key: pki.leaf_key, certificate: pki.leaf, signing_time: time, **options, &block)
                           .sign(xml).to_s
  end

  def verify(document, **options)
    HankoXml::Xades::Verifier.new(store: pki.store, tsa_certificates: [tsa.ca_certificate], **options).verify(document)
  end

  def properties(document)
    Nokogiri::XML(document).at_xpath("//xades:UnsignedSignatureProperties", ns)
  end

  def tampered(document)
    doc = Nokogiri::XML(document)
    yield doc
    HankoXml.serialize(doc)
  end

  def expect_invalid(document, message, **options)
    result = verify(document, **options)
    expect(result.valid?).to be false
    expect(result.archive_timestamps).to be_nil
    expect(result.errors.last.message).to match(message)
  end

  describe "an archived signature" do
    it "carries the ArchiveTimeStamp last, and verifies with it, as LT too" do
      archive = properties(lta).at_xpath("xades141:ArchiveTimeStamp", ns)
      result = verify(lta)

      expect(properties(lta).element_children.map(&:name))
        .to eq(%w[SignatureTimeStamp CertificateValues RevocationValues ArchiveTimeStamp])
      expect(archive.at_xpath("ds:CanonicalizationMethod/@Algorithm", ns).value)
        .to eq(HankoXml::Algorithms.uri_for(:canonicalization, :c14n))
      expect(result.errors).to be_empty
      expect(result.archive_timestamps.map(&:id)).to eq([archive["Id"]])
      expect(result.archive_timestamps.first).to be_frozen
      expect(result.long_term_validation).not_to be_nil
    end

    it "is renewed by a second one, which covers the first" do
      renewed = described_class.new(timestamper: tsa.timestamper, archive_timestamp: true).augment(lta).to_s
      result = verify(renewed)

      expect(result.errors).to be_empty
      expect(result.archive_timestamps.map(&:id).last).to end_with("-ats-2")
      expect(properties(renewed).xpath("xades:SignatureTimeStamp", ns).size).to eq(1)
    end

    it "goes from B to LTA in one call" do
      result = verify(described_class.new(timestamper: tsa.timestamper, validation_data: validation_data,
                                          archive_timestamp: true).augment(sign).to_s)

      expect(result.errors).to be_empty
      expect(result.signature_timestamps.size).to eq(1)
      expect(result.archive_timestamps.size).to eq(1)
    end

    it "still verifies when values are added after it, as a renewal would" do
      later = described_class.new(validation_data: { crls: [pki.crl(last_update: time + hour)] }).augment(lta).to_s

      expect(verify(later).errors).to be_empty
    end

    it "takes exc-c14n for a signature whose References all end in octets" do
      exclusive = sign(timestamper: tsa.timestamper, validation_data: validation_data) do |signer|
        signer.reference(uri: "", transforms: %i[enveloped_signature exc_c14n])
      end
      archived = described_class.new(timestamper: tsa.timestamper, archive_timestamp: true,
                                     archive_canonicalization_method: :exc_c14n).augment(exclusive).to_s

      expect(verify(archived).errors).to be_empty
    end
  end

  describe "fail closed" do
    it "fails when anything it covers changes" do
      changes = {
        "an embedded OCSP response" => lambda do |doc|
          doc.at_xpath("//xades:EncapsulatedOCSPValue", ns).content = [pki.ocsp(this_update: time + (2 * hour)).to_der]
                                                                      .pack("m0")
        end,
        "the KeyInfo" => ->(doc) { doc.at_xpath("//ds:KeyInfo", ns).add_child(doc.create_element("KeyName")) },
        "an unsigned Object" => lambda do |doc|
          doc.at_xpath("//ds:Signature", ns).add_child(doc.create_element("Object")).tap do |object|
            object.namespace = doc.at_xpath("//ds:Signature", ns).namespace
          end
        end
      }
      changes.each do |what, change|
        expect_invalid(tampered(lta, &change), /ArchiveTimeStamp does not verify/, long_term: :ignore)
      rescue RSpec::Expectations::ExpectationNotMetError => e
        raise e.exception("#{what}: #{e.message}")
      end
    end

    it "refuses a CanonicalizationMethod other than inclusive c14n over a node-set Reference" do
      document = tampered(lta) do |doc|
        doc.at_xpath("//xades141:ArchiveTimeStamp/ds:CanonicalizationMethod", ns)["Algorithm"] =
          HankoXml::Algorithms.uri_for(:canonicalization, :exc_c14n)
      end

      expect_invalid(document, /node set needs inclusive c14n/)
    end

    it "fails for an ArchiveTimeStamp from a TSA the caller does not trust" do
      other = FakeTsa.new(name: "Other TSA", gen_time: time)
      archived = described_class.new(timestamper: other.timestamper, archive_timestamp: true).augment(lt).to_s

      expect_invalid(archived, /ArchiveTimeStamp does not verify/)
    end

    it "fails for an ArchiveTimeStamp when no TSA trust is configured" do
      untimestamped = tampered(lta) { |doc| doc.at_xpath("//xades:SignatureTimeStamp", ns).unlink }

      expect_invalid(untimestamped, /xades141:ArchiveTimeStamp>; pass tsa_store:/, tsa_certificates: nil,
                                                                                   long_term: :ignore)
    end

    it "is not read with timestamps: :ignore" do
      garbled = tampered(lta) { |doc| doc.at_xpath("//xades141:ArchiveTimeStamp", ns).content = "garbage" }
      result = verify(garbled, timestamps: :ignore, tsa_certificates: nil)

      expect(result.archive_timestamps).to be_nil
      expect(result.errors).to be_empty
    end
  end

  describe "configuration" do
    it "needs timestamper: and LT values" do
      expect { described_class.new(validation_data: validation_data, archive_timestamp: true) }
        .to raise_error(HankoXml::ConfigurationError, /archive_timestamp: needs timestamper:/)
      expect do
        described_class.new(timestamper: tsa.timestamper,
                            archive_timestamp: true).augment(sign(timestamper: tsa.timestamper))
      end
        .to raise_error(HankoXml::ConfigurationError, /XAdES-LTA builds on XAdES-LT/)
    end

    it "checks archive_canonicalization_method:, and refuses exc-c14n over a node-set Reference" do
      expect do
        described_class.new(timestamper: tsa.timestamper, archive_timestamp: true,
                            archive_canonicalization_method: :sha256)
      end
        .to raise_error(HankoXml::ConfigurationError, /archive_canonicalization_method: :sha256/)
      expect do
        described_class.new(timestamper: tsa.timestamper, archive_timestamp: true,
                            archive_canonicalization_method: :exc_c14n).augment(lt)
      end.to raise_error(HankoXml::ConfigurationError, /pass archive_canonicalization_method: :c14n/)
    end

    it "refuses a signature that does not verify with its own KeyInfo certificate" do
      broken = tampered(lt) { |doc| doc.at_xpath("//*[local-name()='Total']").content = "999.00" }

      expect { described_class.new(timestamper: tsa.timestamper, archive_timestamp: true).augment(broken) }
        .to raise_error(HankoXml::XadesError, /needs the signature to verify/)
    end
  end
end
