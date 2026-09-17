# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "pathname"

# S-11: safer multi-signature defaults, and Signer/Verifier index agreement.
RSpec.describe "S-11 multiple signatures" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:signer_key_pem) { fixtures.join("signer.key").read }
  let(:signer_cert_pem) { fixtures.join("signer.crt").read }
  let(:two_targets_xml) do
    %(<Envelope xmlns="urn:hanko_xml:example"><Data Id="a">A</Data><Data Id="b">B</Data></Envelope>)
  end
  # Neither signature covers the document root (each is a detached-style
  # fragment signature over #a/#b); require_signed_root (S-06) is not what
  # these specs are about, so it is explicitly off.
  let(:fragment_policy) { HankoXml::Policy.strict.with(require_signed_root: false) }

  # Builds a document with two independent, detached-style signatures: one
  # over #a, one over #b. Each is a separate Signer#sign call so the two
  # <Signature> elements are true siblings in document order.
  def two_signature_doc
    signer_a = HankoXml::Signer.new(key: signer_key_pem, certificate: signer_cert_pem,
                                    references: ["#a"], template: :build)
    doc = signer_a.sign(two_targets_xml).document

    unsigned_signer_b = HankoXml::Signer.new(key: signer_key_pem, certificate: signer_cert_pem,
                                             references: ["#b"])
    template = unsigned_signer_b.template(doc)
    HankoXml::Placement.append_to_root.insert(doc, template)

    signer_b = HankoXml::Signer.new(key: signer_key_pem, certificate: signer_cert_pem,
                                    references: ["#b"], template: :require)
    signer_b.sign!(doc)
    doc
  end

  describe "M1/M2: default `signature:` requires an explicit choice with more than one signature" do
    it "raises MultipleSignatures rather than silently verifying only the first" do
      doc = two_signature_doc
      verifier = HankoXml::Verifier.new(certificate: signer_cert_pem)

      expect { verifier.verify(doc) }.to raise_error(HankoXml::MultipleSignatures)
    end

    it "still verifies the single signature in a normal, single-signature document" do
      signed = HankoXml.sign(%(<Envelope xmlns="urn:hanko_xml:example"><Data>Hello</Data></Envelope>),
                             key: signer_key_pem, certificate: signer_cert_pem)
      verifier = HankoXml::Verifier.new(certificate: signer_cert_pem)

      expect(verifier.verify(signed.to_s).valid?).to be true
    end

    it "raises MultipleSignatures for signature: :only with two signatures (M2)" do
      doc = two_signature_doc
      verifier = HankoXml::Verifier.new(certificate: signer_cert_pem, signature: :only)

      expect { verifier.verify(doc) }.to raise_error(HankoXml::MultipleSignatures)
    end

    it "signature: :first is still available as an explicit, unsafe opt-in" do
      doc = two_signature_doc
      verifier = HankoXml::Verifier.new(certificate: signer_cert_pem, signature: :first, policy: fragment_policy)

      expect(verifier.verify(doc).valid?).to be true
    end
  end

  # #95: API_CONTRACT §5.3. A String `signature:` is an XPath that must pick
  # exactly one <ds:Signature>.
  describe "signature: XPath" do
    def verifier(xpath, **kwargs)
      HankoXml::Verifier.new(certificate: signer_cert_pem, signature: xpath, policy: fragment_policy, **kwargs)
    end

    it "selects the one signature it matches, with the ds: prefix already bound" do
      doc = two_signature_doc
      result = verifier("(//ds:Signature)[2]").verify(doc)

      expect(result.valid?).to be true
      expect(result.signature_node).to eq(doc.xpath(".//ds:Signature", HankoXml::NS)[1])
      expect(result).to be_signed(doc.at_xpath("//*[@Id='b']"))
      expect(result).not_to be_signed(doc.at_xpath("//*[@Id='a']"))
    end

    it "raises MultipleSignatures when it matches more than one, instead of taking the first" do
      expect { verifier("//ds:Signature").verify(two_signature_doc) }
        .to raise_error(HankoXml::MultipleSignatures, /selected 2/)
    end

    it "honors the caller's namespaces: map" do
      doc = two_signature_doc
      result = verifier("//ex:Envelope/sig:Signature[1]",
                        namespaces: { "ex" => "urn:hanko_xml:example", "sig" => HankoXml::NS["ds"] }).verify(doc)

      expect(result.valid?).to be true
      expect(result.signature_node).to eq(doc.xpath(".//ds:Signature", HankoXml::NS)[0])
    end

    it "reports SignatureMissing when it matches nothing, or something that is not a <Signature>" do
      ["//ds:Signature[99]", "//*[@Id='a']"].each do |xpath|
        result = verifier(xpath).verify(two_signature_doc)
        expect(result.valid?).to be false
        expect(result.errors).to all(be_a(HankoXml::SignatureMissing))
      end
    end
  end

  describe "M3/M4: selecting a specific signature" do
    it "signature: 1 (Integer, document order) selects the second signature" do
      doc = two_signature_doc
      verifier = HankoXml::Verifier.new(certificate: signer_cert_pem, signature: 1, policy: fragment_policy)
      result = verifier.verify(doc)

      expect(result.valid?).to be true
      expect(result.signature_node).to eq(doc.xpath(".//ds:Signature", HankoXml::NS)[1])
    end

    it "verify_all returns one Verification per signature, in document order (M4)" do
      doc = two_signature_doc
      verifier = HankoXml::Verifier.new(certificate: signer_cert_pem, policy: fragment_policy)
      results = verifier.verify_all(doc)

      expect(results.size).to eq(2)
      expect(results.map(&:valid?)).to eq([true, true])
      expect(results.map(&:signature_node)).to eq(doc.xpath(".//ds:Signature", HankoXml::NS).to_a)
    end
  end

  describe "M5/D7: Signer#sign! `signature:` and Verifier `signature:` agree on document order" do
    it "Signer signature: 0 signs the first (outermost/document-order) template, matching Verifier signature: 0" do
      doc = Nokogiri::XML(two_targets_xml)
      signer_a = HankoXml::Signer.new(key: signer_key_pem, certificate: signer_cert_pem, references: ["#a"])
      signer_b = HankoXml::Signer.new(key: signer_key_pem, certificate: signer_cert_pem, references: ["#b"])

      template_a = signer_a.template(doc)
      HankoXml::Placement.append_to_root.insert(doc, template_a)
      template_b = signer_b.template(doc)
      HankoXml::Placement.append_to_root.insert(doc, template_b)

      # Sign only the first-in-document-order template via its Integer index.
      signer_a.sign!(doc, signature: 0)

      sigs = doc.xpath(".//ds:Signature", HankoXml::NS)
      expect(sigs[0].at_xpath("./ds:SignatureValue", HankoXml::NS).content.strip).not_to be_empty
      expect(sigs[1].at_xpath("./ds:SignatureValue", HankoXml::NS).content.strip).to be_empty

      verifier = HankoXml::Verifier.new(certificate: signer_cert_pem, signature: 0)
      expect(verifier.verify(doc).signature_node).to eq(sigs[0])
    end
  end

  describe "D8: Signer signature: out of range" do
    it "raises ConfigurationError instead of silently returning the document unchanged" do
      signer = HankoXml::Signer.new(key: signer_key_pem, certificate: signer_cert_pem)
      doc = Nokogiri::XML(two_targets_xml)

      expect { signer.sign!(doc, signature: 99) }.to raise_error(HankoXml::ConfigurationError, /signature:/)
    end
  end
end
