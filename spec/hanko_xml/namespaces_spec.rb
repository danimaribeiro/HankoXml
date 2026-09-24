# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "pathname"

# #96: `namespaces:` is merged over HankoXml::NS for every caller-supplied
# XPath (API_CONTRACT.md §6.8), not only for Verifier's `signature:`.
RSpec.describe "namespaces: (#96)" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:key_pem) { fixtures.join("signer.key").read }
  let(:cert_pem) { fixtures.join("signer.crt").read }
  let(:xml) { %(<x:Envelope xmlns:x="urn:x"><x:Data Id="d1">A</x:Data><x:Other>B</x:Other></x:Envelope>) }
  let(:ns) { { "x" => "urn:x" } }

  describe "Signer" do
    it "resolves a placement XPath with the Signer's namespaces:" do
      signed = HankoXml::Signer
        .new(
          key: key_pem,
          certificate: cert_pem,
          namespaces: ns,
          placement: HankoXml::Placement.append_to("/x:Envelope/x:Other")
        )
        .sign(xml)

      doc = Nokogiri::XML(signed.to_s)
      expect(doc.at_xpath("/x:Envelope/x:Other/ds:Signature", ns.merge("ds" => HankoXml::NS["ds"]))).not_to be_nil
    end

    it "lets Placement's own namespaces: win over the Signer's" do
      signer = HankoXml::Signer.new(
        key: key_pem,
        certificate: cert_pem,
        namespaces: { "x" => "urn:wrong" },
        placement: HankoXml::Placement.append_to("/x:Envelope/x:Other", namespaces: ns)
      )

      expect(HankoXml.valid?(signer.sign(xml).to_s, certificate: cert_pem)).to be true
    end

    it "raises PlacementError when the prefix is bound nowhere" do
      signer = HankoXml::Signer.new(
        key: key_pem,
        certificate: cert_pem,
        placement: HankoXml::Placement.append_to("/y:Envelope")
      )

      expect { signer.sign(xml) }.to raise_error(HankoXml::PlacementError, /bind every prefix/)
    end
  end

  describe "Verification#at_signed and #signed" do
    let(:signed) do
      HankoXml::Signer.new(key: key_pem, certificate: cert_pem, references: ["#d1"]).sign(xml).to_s
    end
    let(:verification) do
      HankoXml::Verifier.new(certificate: cert_pem, namespaces: ns, policy: HankoXml::Policy.fragment).verify(signed)
    end

    it "resolves the Verifier's prefixes" do
      expect(verification.valid?).to be true
      expect(verification.at_signed("//x:Data").text).to eq("A")
      expect(verification.signed("//x:Data").size).to eq(1)
    end

    it "always binds ds:" do
      expect { verification.at_signed("//ds:SignedInfo") }.to raise_error(HankoXml::NotSignedError)
    end

    it "still refuses an unsigned node" do
      expect { verification.at_signed("//x:Other") }.to raise_error(HankoXml::NotSignedError)
      expect { verification.signed("//x:*") }.to raise_error(HankoXml::NotSignedError)
    end

    it "merges the per-call map over the Verifier's" do
      expect(verification.at_signed("//y:Data", { "y" => "urn:x" }).text).to eq("A")
    end
  end
end
