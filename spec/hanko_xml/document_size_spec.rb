# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "pathname"
require "stringio"
require "tempfile"

# S-12: max_document_size is applied before the document is read or parsed,
# and before any native call. The native side separately rejects documents
# too long for libxml2's int length instead of truncating them (covered by
# the ffi_len unit test in ext/hanko_xml/src/dsig.rs -- a >2 GiB String is
# not practical in a spec).
RSpec.describe "S-12 document size limits" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:signer_key_pem) { fixtures.join("signer.key").read }
  let(:signer_cert_pem) { fixtures.join("signer.crt").read }
  let(:unsigned_xml) { %(<Envelope xmlns="urn:hanko_xml:example"><Data Id="a">A</Data></Envelope>) }
  let(:signed_xml) do
    HankoXml.sign(unsigned_xml, key: signer_key_pem, certificate: signer_cert_pem).to_s
  end
  let(:limit) { 64 }
  let(:policy) { HankoXml::Policy.strict.with(max_document_size: limit) }
  # Malformed on purpose: a PolicyError (not ParseError) proves the size
  # check ran before parsing.
  let(:oversized_garbage) { "<" * (limit + 1) }

  describe "Verifier" do
    let(:verifier) { HankoXml::Verifier.new(certificate: signer_cert_pem, policy: policy) }

    it "rejects an oversized String before parsing it" do
      expect { verifier.verify(oversized_garbage) }.to raise_error(HankoXml::PolicyError, /max_document_size/)
    end

    it "rejects an oversized file by size before reading it" do
      Tempfile.create(["oversized", ".xml"]) do |file|
        file.write(oversized_garbage)
        file.flush
        expect(File).not_to receive(:binread)

        expect { verifier.verify(Pathname.new(file.path)) }
          .to raise_error(HankoXml::PolicyError, /max_document_size/)
      end
    end

    it "reads at most one byte past the limit from an IO" do
      io = StringIO.new(oversized_garbage * 1000)

      expect { verifier.verify(io) }.to raise_error(HankoXml::PolicyError, /#{limit + 1} bytes/)
      expect(io.pos).to eq(limit + 1)
    end

    it "checks an already-parsed Document before any native call" do
      doc = Nokogiri::XML(signed_xml)
      expect(HankoXml::Native).not_to receive(:inspect_sig)
      expect(HankoXml::Native).not_to receive(:verify)

      result = verifier.verify(doc)

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::PolicyError)
      expect(result.errors.first.message).to match(/max_document_size/)
    end

    it "applies the limit to verify_all" do
      expect { verifier.verify_all(oversized_garbage) }.to raise_error(HankoXml::PolicyError)
    end

    it "still verifies a document within the limit" do
      roomy = HankoXml::Policy.strict.with(max_document_size: signed_xml.bytesize * 2)

      expect(HankoXml.valid?(StringIO.new(signed_xml), certificate: signer_cert_pem, policy: roomy))
        .to be true
    end

    it "reads an IO in full under a policy with no size limit" do
      result = HankoXml::Verifier.new(certificate: signer_cert_pem,
                                      policy: HankoXml::Policy.permissive).verify(StringIO.new(signed_xml))
      expect(result.valid?).to be true
    end
  end

  describe "native length check" do
    # Needs several GiB of RAM (the String plus the native copy), so opt-in.
    it "rejects a document longer than libxml2's int length instead of truncating it",
       skip: (ENV["HANKO_BIG"] ? false : "set HANKO_BIG=1 to allocate a 2 GiB String") do
      huge = "<a/>".ljust(2**31, " ")

      expect { HankoXml::Native.inspect_sig(huge, 0) }.to raise_error(HankoXml::ParseError, /2 GiB/)
    end
  end

  describe "Signer" do
    it "rejects an oversized String before parsing it" do
      expect do
        HankoXml.sign(oversized_garbage, key: signer_key_pem, certificate: signer_cert_pem, policy: policy)
      end.to raise_error(HankoXml::PolicyError, /max_document_size/)
    end

    it "checks an already-parsed Document before any native call" do
      doc = Nokogiri::XML(unsigned_xml + (" " * limit))
      expect(HankoXml::Native).not_to receive(:inspect_sig)
      expect(HankoXml::Native).not_to receive(:sign)

      expect do
        HankoXml.sign!(doc, key: signer_key_pem, certificate: signer_cert_pem, policy: policy)
      end.to raise_error(HankoXml::PolicyError, /max_document_size/)
    end
  end
end
