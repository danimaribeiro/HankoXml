# frozen_string_literal: true

require "spec_helper"
require "pathname"

# S-13: native errors are classified by where they happened, not by
# substring-matching a message that can contain attacker-controlled text,
# and xmlsec's log is exposed as #xmlsec_errors instead of being appended to
# #message.
RSpec.describe "S-13 native error classification and messages" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:signer_key_pem) { fixtures.join("signer.key").read }
  let(:signer_cert_pem) { fixtures.join("signer.crt").read }
  let(:template_xml) { fixtures.join("template.xml").read }
  let(:id_attrs) { %w[Id ID id] }
  # An algorithm URI xmlsec does not know, chosen to contain the words the
  # old classifier looked for ("parse", "key", "certificate").
  let(:hostile_href) { "urn:parse-key-certificate:attacker" }
  let(:hostile_template) do
    template_xml.sub(/SignatureMethod Algorithm="[^"]*"/, %(SignatureMethod Algorithm="#{hostile_href}"))
  end

  describe "Native.sign" do
    def sign_failure
      HankoXml::Native.sign(hostile_template, signer_key_pem, [signer_cert_pem], id_attrs, 0)
      raise "expected Native.sign to fail"
    rescue HankoXml::Error => e
      e
    end

    it "raises SigningError for an xmlsec signing failure, whatever the document says" do
      expect(sign_failure).to be_a(HankoXml::SigningError)
    end

    it "keeps attacker-controlled document text out of the message" do
      expect(sign_failure.message).not_to include(hostile_href)
      expect(sign_failure.message).not_to match(/func=|file=/)
    end

    it "exposes the captured xmlsec log as #xmlsec_errors" do
      expect(sign_failure.xmlsec_errors).not_to be_empty
      expect(sign_failure.xmlsec_errors.join("\n")).to include(hostile_href)
    end

    it "raises KeyLoadError for an unreadable key" do
      expect do
        HankoXml::Native.sign(template_xml, "not a key", [signer_cert_pem], id_attrs, 0)
      end.to raise_error(HankoXml::KeyLoadError) { |e| expect(e.message).not_to match(/func=/) }
    end

    it "raises ParseError for malformed XML" do
      expect do
        HankoXml::Native.sign("<unclosed", signer_key_pem, [signer_cert_pem], id_attrs, 0)
      end.to raise_error(HankoXml::ParseError)
    end
  end

  describe "Native.inspect_sig" do
    it "raises ParseError for malformed XML and NativeError for a missing <Signature>" do
      expect { HankoXml::Native.inspect_sig("<unclosed", 0) }.to raise_error(HankoXml::ParseError)
      expect { HankoXml::Native.inspect_sig("<root/>", 0) }.to raise_error(HankoXml::NativeError)
    end
  end

  describe "Verifier" do
    let(:unsigned_xml) { %(<Envelope xmlns="urn:hanko_xml:example"><Data Id="a">A</Data></Envelope>) }
    let(:tampered_xml) do
      HankoXml.sign(unsigned_xml, key: signer_key_pem, certificate: signer_cert_pem).to_s.sub(">A<", ">B<")
    end

    it "does not use xmlsec log lines as the VerificationError message" do
      result = HankoXml.verify(tampered_xml, certificate: signer_cert_pem)
      error = result.errors.first

      expect(result.valid?).to be false
      expect(error.message).not_to match(/func=|file=/)
      expect(error.xmlsec_errors.join).to match(/func=/)
    end
  end
end
