# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require "pathname"

# #96: #message is a fixed string from this library; libxml2/xmlsec text,
# which can quote the document, lives only in #xmlsec_errors. No error ever
# carries key material (API_CONTRACT.md §5.10).
RSpec.describe "error messages (#96)" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:key_pem) { fixtures.join("signer.key").read }
  let(:cert_pem) { fixtures.join("signer.crt").read }
  let!(:signed) { HankoXml::Signer.new(key: key_pem, certificate: cert_pem).sign("<doc><a>1</a></doc>").to_s }

  describe "ParseError" do
    it "keeps libxml2's diagnostics, which quote the document, out of #message" do
      expect { HankoXml.parse("<doc><secret-tag></doc>") }.to raise_error(HankoXml::ParseError) do |error|
        expect(error.message).to eq("the document is not well-formed XML")
        expect(error.xmlsec_errors.join).to include("secret-tag")
      end
    end
  end

  describe "SchemaError" do
    it "keeps the XSD diagnostics out of #message" do
      doc = Nokogiri::XML(signed)
      doc.at_xpath("//ds:SignatureValue", "ds" => HankoXml::NS["ds"]).remove
      error = HankoXml::Verifier.new(certificate: cert_pem, schema: :default).verify(doc.to_xml).errors.first

      expect(error).to be_a(HankoXml::SchemaError)
      expect(error.message).to eq("<Signature> does not validate against the XML-DSig schema")
      expect(error.xmlsec_errors).not_to be_empty
    end
  end

  describe "native failures during verification" do
    let(:verifier) { HankoXml::Verifier.new(certificate: cert_pem) }

    it "keeps the class and log the native layer chose" do
      native = HankoXml::SigningError.new("fixed", xmlsec_errors: ["log line"])
      allow(HankoXml::Native).to receive(:verify).and_raise(native)

      expect(verifier.verify(signed).errors).to eq([native])
    end

    it "replaces any other exception's message with a fixed one" do
      allow(HankoXml::Native).to receive(:verify).and_raise(RuntimeError, "<doc> text")
      error = verifier.verify(signed).errors.first

      expect(error).to be_a(HankoXml::NativeError)
      expect(error.message).not_to include("<doc>")
    end

    it "does the same for Native.inspect_sig" do
      allow(HankoXml::Native).to receive(:inspect_sig).and_raise(RuntimeError, "<doc> text")
      error = verifier.verify(signed).errors.first

      expect(error).to be_a(HankoXml::NativeError)
      expect(error.message).not_to include("<doc>")
    end
  end

  describe "key material" do
    let(:pkey) { OpenSSL::PKey.read(key_pem) }

    it "filters a HankoXml::Key or OpenSSL::PKey passed as the message" do
      expect(HankoXml::Error.new(HankoXml::Key.coerce(key_pem)).message).to eq("[FILTERED]")
      expect(HankoXml::SigningError.new(pkey).message).to eq("[FILTERED]")
    end

    it "redacts private-key PEM text, including a truncated block, from #message and #xmlsec_errors" do
      error = HankoXml::NativeError.new("before #{key_pem.strip} after", xmlsec_errors: ["x #{key_pem[0, 80]}"])

      expect(error.message).to eq("before [FILTERED] after")
      expect(error.message).not_to include("PRIVATE KEY")
      expect(error.xmlsec_errors).to eq(["x [FILTERED]"])
    end

    it "leaves certificates alone" do
      expect(HankoXml::Error.new(cert_pem).message).to eq(cert_pem)
    end
  end
end
