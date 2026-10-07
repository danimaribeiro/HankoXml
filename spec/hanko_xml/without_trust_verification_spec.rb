# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require "pathname"

# #103: an explicit, two-step integrity-only mode. It proves the document was
# not changed since the key in its own <X509Certificate> signed it, and
# nothing about who that was (API_CONTRACT.md §5.6).
RSpec.describe "HankoXml::Verifier.without_trust_verification (#103)" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:signer_cert) { OpenSSL::X509::Certificate.new(fixtures.join("signer.crt").read) }
  let(:signed) do
    HankoXml.sign(%(<doc><a>1</a></doc>), key: fixtures.join("signer.key").read, certificate: signer_cert).to_s
  end
  let(:verifier) { HankoXml::Verifier.without_trust_verification }

  it "checks integrity against the document's own certificate" do
    result = verifier.verify(signed)

    expect(result).to be_valid
    expect(result.certificate).to eq(signer_cert)
  end

  it "never reports trust, so #valid? alone can't be mistaken for it" do
    result = verifier.verify(signed)

    expect(result.trusted?).to be false
    expect(result.certificate_chain).to eq([])
    expect(HankoXml::Verifier.new(certificate: signer_cert).verify(signed).trusted?).to be true
  end

  it "fails on a modified document" do
    result = verifier.verify(signed.sub("<a>1</a>", "<a>2</a>"))

    expect(result).not_to be_valid
    expect(result.trusted?).to be false
  end

  describe "#verify!" do
    it "raises UntrustedCertificate for a valid result unless allow_untrusted: true" do
      expect { verifier.verify!(signed) }.to raise_error(HankoXml::UntrustedCertificate, /allow_untrusted/)
      expect(verifier.verify!(signed, allow_untrusted: true)).to be_valid
    end

    it "still raises the verification error for a modified document, allowed or not" do
      expect { verifier.verify!(signed.sub("<a>1</a>", "<a>2</a>"), allow_untrusted: true) }
        .to raise_error(HankoXml::VerificationError)
    end

    it "changes nothing for a Verifier with a trust source" do
      expect(HankoXml::Verifier.new(certificate: signer_cert).verify!(signed)).to be_trusted
    end
  end

  it "pins the embedded key, so a document with no certificate does not verify (S-01)" do
    bare = HankoXml.sign(%(<doc/>), key: fixtures.join("signer.key").read, key_info: []).to_s
    result = verifier.verify(bare)

    expect(result).not_to be_valid
    expect(result.errors.first).to be_a(HankoXml::UntrustedCertificate)
  end

  it "refuses an ambiguous <KeyInfo> with two end-entity certificates" do
    other = fixtures.join("other.crt").read.gsub(/-----[A-Z ]+-----|\s/, "")
    ambiguous = signed.sub(%r{</(\w+:)?X509Certificate>}) do |close|
      prefix = Regexp.last_match(1)
      "#{close}<#{prefix}X509Certificate>#{other}</#{prefix}X509Certificate>"
    end

    expect(verifier.verify(ambiguous).errors.first.message).to match(/exactly one end-entity/)
  end

  it "still applies the policy" do
    sha1 = HankoXml.sign(%(<doc/>), key: fixtures.join("signer.key").read, certificate: signer_cert,
                                    signature_method: :rsa_sha1, digest_method: :sha1,
                                    policy: HankoXml::Policy.legacy_sha1).to_s

    expect(verifier.verify(sha1).errors.first).to be_a(HankoXml::PolicyError)
  end

  describe "construction" do
    it "takes no trust source: that is Verifier.new's job" do
      %i[certificate certificates store key keys certificate_subject].each do |keyword|
        expect { HankoXml::Verifier.without_trust_verification(keyword => "x") }
          .to raise_error(HankoXml::ConfigurationError, /no trust source/)
      end
    end

    it "is not a keyword on Verifier.new, which still needs exactly one trust source" do
      expect { HankoXml::Verifier.new }.to raise_error(HankoXml::ConfigurationError, /exactly one trust source/)
    end

    it "takes the other Verifier keywords" do
      expect(HankoXml::Verifier.without_trust_verification(policy: HankoXml::Policy.strict, signature: :first))
        .to be_without_trust
    end

    it "is not available for XAdES, whose signed properties commit to a trusted certificate" do
      expect { HankoXml::Xades::Verifier.without_trust_verification }
        .to raise_error(HankoXml::ConfigurationError, /XAdES/)
    end
  end
end
