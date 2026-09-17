# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "pathname"

# S-09: Verification#references[].valid? surfaces xmlsec's real per-Reference
# digest status instead of approximating it from the overall signature result.
RSpec.describe "S-09 per-reference validity" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:signer_key_pem) { fixtures.join("signer.key").read }
  let(:signer_cert_pem) { fixtures.join("signer.crt").read }
  let(:two_targets_xml) do
    %(<Envelope xmlns="urn:hanko_xml:example"><Data Id="a">A</Data><Data Id="b">B</Data></Envelope>)
  end
  # Neither reference covers the document root; require_signed_root (S-06) is
  # not what this file is about; disabling it lets verification actually
  # reach Native.verify so the per-reference divergence below is real.
  let(:fragment_policy) { HankoXml::Policy.strict.with(require_signed_root: false) }

  def tamper_digest!(doc, reference_index)
    digest_value = doc.xpath(".//ds:Reference", HankoXml::NS)[reference_index]
                      .at_xpath("./ds:DigestValue", HankoXml::NS)
    digest_value.content = ["\x00" * 32].pack("m0")
  end

  it "reports the tampered reference invalid, the untouched one valid, though the signature as a whole is invalid" do
    signed = HankoXml.sign(two_targets_xml, key: signer_key_pem, certificate: signer_cert_pem,
                                            references: ["#a", "#b"])
    doc = signed.document
    tamper_digest!(doc, 1)

    result = HankoXml::Verifier.new(certificate: signer_cert_pem,
                                    policy: fragment_policy).verify(HankoXml.serialize(doc))

    expect(result.valid?).to be false
    expect(result.references[0]).to be_valid
    expect(result.references[1]).not_to be_valid
  end

  it "reports every reference valid when the signature genuinely verifies" do
    signed = HankoXml.sign(two_targets_xml, key: signer_key_pem, certificate: signer_cert_pem,
                                            references: ["#a", "#b"])

    result = HankoXml::Verifier.new(certificate: signer_cert_pem, policy: fragment_policy).verify(signed.to_s)

    expect(result.valid?).to be true
    expect(result.references.map(&:valid?)).to eq([true, true])
  end
end
