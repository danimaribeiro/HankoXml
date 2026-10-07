# frozen_string_literal: true

require_relative "helper"

# Verification on bytes, with Nokogiri hidden (#102). Every check that runs
# with Nokogiri runs here too; what needs a DOM raises NokogiriRequired.
RSpec.describe "HankoXml without Nokogiri" do
  let(:signed) { WithoutNokogiri::FIXTURES.join("signed.xml").read }
  let(:certificate) { WithoutNokogiri::FIXTURES.join("signer.crt").read }
  let(:verifier) { HankoXml::Verifier.new(certificate: certificate) }
  let(:body) { signed.sub(/\A<\?xml[^>]*\?>\s*/, "") }

  it "really runs without Nokogiri" do
    expect(defined?(Nokogiri)).to be_nil
    expect { require "nokogiri" }.to raise_error(LoadError, /hidden/)
    expect(HankoXml.nokogiri?).to be false
  end

  it "reports verification available and DOM capabilities unavailable" do
    caps = HankoXml.capabilities
    expect(caps.slice(:verify, :sign_existing_template).values).to all(be true)
    expect(caps.except(:verify, :sign_existing_template).values).to all(be false)
  end

  describe "verification" do
    it "verifies a String under Policy.strict, schema included" do
      expect(HankoXml.valid?(signed, certificate: certificate)).to be true
    end

    it "verifies a path and an IO" do
      path = WithoutNokogiri::FIXTURES.join("signed.xml")
      expect(verifier.valid?(path)).to be true
      expect(verifier.valid?(StringIO.new(signed))).to be true
    end

    it "returns a Verification that answers everything that needs no DOM" do
      result = HankoXml.verify!(signed, certificate: certificate)

      expect(result.document).to be_nil
      expect(result.signature_node).to be_nil
      expect(result.signature_method).to eq(:rsa_sha256)
      expect(result.covers_root?).to be true
      expect(result.partial?).to be false
      expect(result.certificate).to be_a(OpenSSL::X509::Certificate)
      expect(result.references.map(&:uri)).to eq([""])
    end

    it "raises NokogiriRequired for coverage questions about nodes" do
      result = verifier.verify(signed)

      expect { result.signed_nodes }.to raise_error(HankoXml::NokogiriRequired)
      expect { result.at_signed("//Data") }.to raise_error(HankoXml::NokogiriRequired)
    end

    it "rejects a tampered document" do
      result = verifier.verify(signed.sub("Hello, world!", "Hello, there!"))

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::VerificationError)
    end

    it "rejects malformed XML, as the strict Nokogiri parse did" do
      expect { verifier.verify("<a><x:b/></a>") }.to raise_error(HankoXml::ParseError)
      expect { verifier.verify("<a><b></a>") }.to raise_error(HankoXml::ParseError)
    end

    it "applies max_document_size before reading the input (S-12)" do
      policy = HankoXml::Policy.strict.with(max_document_size: 10)
      tight = HankoXml::Verifier.new(certificate: certificate, policy: policy)

      expect { tight.verify(signed) }.to raise_error(HankoXml::PolicyError, /max_document_size/)
    end

    it "runs schema: :default natively" do
      broken = signed.sub(%r{<SignatureValue>.*?</SignatureValue>}m, "")
      result = verifier.verify(broken)

      expect(result.errors.first).to be_a(HankoXml::SchemaError)
      expect(result.errors.first.xmlsec_errors.join).to match(/SignatureValue/)
    end

    it "rejects duplicate IDs (S-06)" do
      result = verifier.verify(signed.sub("<Data>", %(<Data Id="a"><x Id="a"/>)))

      expect(result.errors.first).to be_a(HankoXml::PolicyError)
      expect(result.errors.first.message).to match(/reject_duplicate_ids/)
    end

    it "enforces require_signed_root (S-06)" do
      fragment = signed.sub("<Data>", %(<Data Id="d">)).sub('URI=""', 'URI="#d"')
      result = verifier.verify(fragment)

      expect(result.errors.first).to be_a(HankoXml::PolicyError)
      expect(result.errors.first.message).to match(/require_signed_root/)
    end

    it "does not fetch anything a Reference names" do
      external = signed.sub('URI=""', 'URI="http://example.invalid/doc.xml"')
      result = verifier.verify(external)

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::PolicyError)
    end
  end

  describe "signature selection" do
    let(:two) { "<Wrap>#{body}#{body}</Wrap>" }

    it "fails closed on several signatures without a selection (S-11)" do
      expect { verifier.verify(two) }.to raise_error(HankoXml::MultipleSignatures)
    end

    it "selects by index, and verify_all returns one Verification per signature" do
      expect(HankoXml::Verifier.new(certificate: certificate, signature: 1).verify(two).valid?).to be false
      expect(verifier.verify_all(two).size).to eq(2)
    end

    it "reports a missing signature as a failed Verification" do
      result = verifier.verify("<a/>")

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::SignatureMissing)
    end

    it "raises NokogiriRequired for XPath selection" do
      xpath = HankoXml::Verifier.new(certificate: certificate, signature: "//ds:Signature")

      expect { xpath.verify(signed) }.to raise_error(HankoXml::NokogiriRequired, /XPath/)
    end
  end

  describe "signature_present?" do
    it "answers from the bytes" do
      expect(HankoXml.signature_present?(signed)).to be true
      expect(HankoXml.signature_present?(WithoutNokogiri::FIXTURES.join("template.xml").read)).to be false
      expect(HankoXml.signature_present?("<a/>")).to be false
    end
  end

  describe "what needs a DOM" do
    let(:key) { WithoutNokogiri::FIXTURES.join("signer.key").read }

    it "raises NokogiriRequired, naming the capability" do
      expect { HankoXml.sign("<doc/>", key: key, certificate: certificate) }
        .to raise_error(HankoXml::NokogiriRequired, /Building a <Signature> template.*needs a DOM/)
      expect { HankoXml.parse(signed) }.to raise_error(HankoXml::NokogiriRequired, /HankoXml.parse/)
      expect { HankoXml::Xades::Verifier.new(certificate: certificate) }
        .to raise_error(HankoXml::NokogiriRequired, /Xades/)
      expect { HankoXml::Verifier.new(certificate: certificate, resolver: ->(_doc, _id) {}) }
        .to raise_error(HankoXml::NokogiriRequired, /resolver/)
    end
  end
end
