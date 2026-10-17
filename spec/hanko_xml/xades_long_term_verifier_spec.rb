# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require_relative "../support/fake_tsa"
require_relative "../support/fake_pki"

# #168: XAdES-LT verification. With embedded CertificateValues /
# RevocationValues, the signing certificate is validated at the time of the
# earliest verified SignatureTimeStamp, with the embedded CRLs and OCSP
# responses, so a certificate that has expired since still verifies. Fail
# closed: embedded data that does not hold fails the signature.
RSpec.describe HankoXml::Xades::Verifier, "XAdES-LT" do
  let(:hour) { 3600 }
  # The validation time: the TSA's genTime, a month ago. The signing
  # certificate was valid then and has expired since.
  let(:time) { Time.at((Time.now.utc - (30 * 86_400)).to_i).utc }
  let(:pki) { FakePki.new(leaf_from: time - (200 * 86_400), leaf_to: time + (10 * 86_400)) }
  let(:tsa) { FakeTsa.new(gen_time: time) }
  let(:xml) { %(<Invoice xmlns="urn:x"><Total Id="total">150.00</Total></Invoice>) }
  let(:ns) { { "ds" => HankoXml::NS["ds"], "xades" => HankoXml::Xades::NS } }
  let(:fresh_ocsp) { pki.ocsp(this_update: time + hour) }

  def sign(validation_data = { certificates: [pki.leaf, pki.root], ocsp_responses: [fresh_ocsp] }, pki: self.pki)
    HankoXml::Xades::Signer.new(key: pki.leaf_key, certificate: pki.leaf, signing_time: time,
                                timestamper: tsa.timestamper, validation_data: validation_data).sign(xml).to_s
  end

  def verify(document, pki: self.pki, **options)
    trust = options.key?(:certificate) ? {} : { store: pki.store }
    described_class.new(**trust, tsa_certificates: [tsa.ca_certificate], **options).verify(document)
  end

  def expect_invalid(document, message, **options)
    result = verify(document, **options)
    expect(result.valid?).to be false
    expect(result.long_term_validation).to be_nil
    expect(result.errors.last).to be_a(HankoXml::XadesError)
    expect(result.errors.last.message).to match(message)
  end

  describe "a signature whose certificate has expired since" do
    it "verifies at the timestamp's time with an embedded OCSP response, and reports it" do
      result = verify(sign)
      validation = result.long_term_validation

      expect(result.errors).to be_empty
      expect(validation).to be_frozen
      expect(validation.time).to eq(time)
      expect(validation.certificate_chain.map(&:to_der)).to eq([pki.leaf.to_der, pki.root.to_der])
      expect(validation.revocation.map { |status| [status.source, status.status, status.issued_at] })
        .to eq([[:ocsp, :good, time + hour]])
      expect(validation.revocation.first.certificate.to_der).to eq(pki.leaf.to_der)
    end

    it "verifies with an embedded CRL, added later by Xades::Augmenter" do
      t_only = HankoXml::Xades::Signer.new(key: pki.leaf_key, certificate: pki.leaf, signing_time: time,
                                           timestamper: tsa.timestamper).sign(xml).to_s
      lt = HankoXml::Xades::Augmenter.new(validation_data: { crls: [pki.crl(last_update: time + hour)] })
                                     .augment(t_only)
      result = verify(lt.to_s)

      expect(result.errors).to be_empty
      expect(result.long_term_validation.revocation.map(&:source)).to eq([:crl])
    end

    it "fails without LT values, as before: the certificate is checked now" do
      t_only = HankoXml::Xades::Signer.new(key: pki.leaf_key, certificate: pki.leaf, signing_time: time,
                                           timestamper: tsa.timestamper).sign(xml).to_s
      result = verify(t_only)

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::UntrustedCertificate)
      expect(result.long_term_validation).to be_nil
    end

    it "verifies a pinned certificate: (the anchor itself) at that time, with nothing to revoke" do
      result = verify(sign, certificate: pki.leaf)

      expect(result.errors).to be_empty
      expect(result.long_term_validation.revocation).to eq([])
    end

    it "accepts a certificate revoked after the validation time" do
      document = sign({ ocsp_responses: [pki.ocsp(this_update: time + (2 * hour), revoked_at: time + hour)] })

      expect(verify(document).long_term_validation.revocation.map(&:status)).to eq([:revoked_later])
    end
  end

  describe "fail closed" do
    it "fails for an OCSP response issued before the validation time, unless revocation_grace: covers it" do
      document = sign({ ocsp_responses: [pki.ocsp(this_update: time - hour)] })

      expect_invalid(document, /no embedded revocation data verifies and is fresh for the signing certificate/)
      expect(verify(document, revocation_grace: 2 * hour).errors).to be_empty
    end

    it "fails for a revocation at or before the validation time, by OCSP or CRL, even beside good evidence" do
      revoked = pki.ocsp(this_update: time + hour, revoked_at: time - hour)
      expect_invalid(sign({ ocsp_responses: [revoked] }), /OCSP shows the signing certificate revoked/)

      crl = pki.crl(last_update: time + hour, revoked: { pki.leaf => time - hour })
      expect_invalid(sign({ ocsp_responses: [fresh_ocsp], crls: [crl] }), /CRL shows the signing certificate revoked/)
    end

    it "fails for evidence the caller's anchor does not vouch for" do
      other = FakePki.new(leaf_from: time - 86_400, leaf_to: time + 86_400, name: "Other")
      unauthorized = pki.ocsp(this_update: time + hour, signer: pki.leaf, signer_key: pki.leaf_key)
      foreign_crl = pki.crl(last_update: time + hour, key: other.root_key)

      [{ ocsp_responses: [unauthorized] }, { crls: [foreign_crl] },
       { ocsp_responses: [pki.ocsp(this_update: time + hour, subject: pki.responder)] }].each do |data|
        expect_invalid(sign(data), /no embedded revocation data verifies/)
      end
    end

    it "fails for an OCSP responder that was not valid when it answered" do
      late = FakePki.new(leaf_from: time - (200 * 86_400), leaf_to: time + (10 * 86_400),
                         responder_from: Time.now.utc + 86_400)
      document = sign({ ocsp_responses: [late.ocsp(this_update: time + hour)] }, pki: late)

      expect_invalid(document, /no embedded revocation data verifies/, pki: late)
    end

    it "fails for embedded values that do not parse" do
      document = Nokogiri::XML(sign)
      document.at_xpath("//xades:EncapsulatedOCSPValue", ns).content = ["not der"].pack("m0")

      expect_invalid(HankoXml.serialize(document), /not Base64 DER of its type \(ocsp_responses\)/)
    end

    it "fails for LT values without a SignatureTimeStamp" do
      document = Nokogiri::XML(sign)
      document.at_xpath("//xades:SignatureTimeStamp", ns).unlink

      expect_invalid(HankoXml.serialize(document), /need a verified <xades:SignatureTimeStamp>/)
    end
  end

  describe "long_term:" do
    let(:current) { FakePki.new(leaf_from: time - 86_400, leaf_to: Time.now.utc + (365 * 86_400)) }

    it ":ignore does not read the values, so the expired certificate fails now" do
      result = verify(sign, long_term: :ignore)

      expect(result.valid?).to be false
      expect(result.long_term_validation).to be_nil
    end

    it "defaults to :ignore with timestamps: :ignore" do
      document = sign({ ocsp_responses: [current.ocsp(this_update: time + hour)] }, pki: current)
      result = verify(document, pki: current, timestamps: :ignore, tsa_certificates: nil)

      expect(result.errors).to be_empty
      expect(result.long_term_validation).to be_nil
    end

    it ":require fails a signature without LT values" do
      t_only = HankoXml::Xades::Signer.new(key: current.leaf_key, certificate: current.leaf, signing_time: time,
                                           timestamper: tsa.timestamper).sign(xml).to_s

      expect(verify(t_only, pki: current)).to be_valid
      expect_invalid(t_only, /long_term: :require, but the signature has no/, pki: current, long_term: :require)
    end

    it "refuses inconsistent configuration" do
      expect { verify(sign, long_term: :verify, timestamps: :ignore) }
        .to raise_error(HankoXml::ConfigurationError, /cannot go with timestamps: :ignore/)
      expect { verify(sign, long_term: :maybe) }.to raise_error(HankoXml::ConfigurationError, /long_term: must be/)
      expect { verify(sign, long_term: :require, tsa_certificates: nil) }
        .to raise_error(HankoXml::ConfigurationError, /:require needs tsa_store:/)
      expect { verify(sign, revocation_grace: -1) }
        .to raise_error(HankoXml::ConfigurationError, /revocation_grace: must be/)
    end
  end
end
