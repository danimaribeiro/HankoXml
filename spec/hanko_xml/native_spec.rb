# frozen_string_literal: true

require "pathname"

RSpec.describe "HankoXml::Native" do
  let(:fixtures) { Pathname.new(__dir__).join("../fixtures") }
  let(:signer_key_pem) { fixtures.join("signer.key").read }
  let(:signer_cert_pem) { fixtures.join("signer.crt").read }
  let(:other_cert_pem) { fixtures.join("other.crt").read }
  let(:id_attrs) { %w[Id ID id] }

  describe ".check_version" do
    it "returns true when the linked xmlsec matches the generated bindings" do
      expect(HankoXml::Native.check_version).to be true
    end
  end

  describe ".abi_compatible?" do
    it "returns true when the loaded xmlsec is ABI compatible with the bindings" do
      expect(HankoXml::Native.abi_compatible?).to be true
    end
  end

  describe ".versions" do
    it "returns a Hash with xmlsec, libxml2, and crypto versions" do
      versions = HankoXml::Native.versions

      expect(versions).to be_a(Hash)
      expect(versions[:xmlsec]).to match(/\A\d+\.\d+\.\d+/)
      expect(versions[:libxml2]).to match(/\A\d+\.\d+\.\d+/)
      expect(versions[:crypto]).to eq("openssl")
    end
  end

  describe ".inspect_sig" do
    it "extracts metadata from a signed document without verifying" do
      xml = fixtures.join("signed_exc_c14n.xml").read
      info = HankoXml::Native.inspect_sig(xml, 0)

      expect(info[:signature_method]).to eq("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
      expect(info[:canonicalization_method]).to eq("http://www.w3.org/2001/10/xml-exc-c14n#")
      expect(info[:signature_count]).to eq(1)
      expect(info[:references]).to be_an(Array)
      expect(info[:references].size).to eq(1)

      ref = info[:references].first
      expect(ref[:uri]).to eq("")
      expect(ref[:digest_method]).to eq("http://www.w3.org/2001/04/xmlenc#sha256")
      expect(ref[:transforms]).to include("http://www.w3.org/2000/09/xmldsig#enveloped-signature")
      expect(ref[:transforms]).to include("http://www.w3.org/2001/10/xml-exc-c14n#")
    end

    it "extracts metadata from a template XML" do
      xml = fixtures.join("template_detached.xml").read
      info = HankoXml::Native.inspect_sig(xml, 0)

      expect(info[:signature_count]).to eq(1)
      ref = info[:references].first
      expect(ref[:uri]).to eq("#payload-1")
    end

    it "raises ParseError for invalid XML" do
      expect do
        HankoXml::Native.inspect_sig("not xml", 0)
      end.to raise_error(HankoXml::ParseError)
    end

    it "raises NativeError for signature index out of range" do
      xml = fixtures.join("signed_exc_c14n.xml").read
      expect do
        HankoXml::Native.inspect_sig(xml, 5)
      end.to raise_error(HankoXml::NativeError, /out of range/)
    end
  end

  describe ".verify" do
    it "returns :succeeded for a valid signature" do
      xml = fixtures.join("signed_exc_c14n.xml").read
      result = HankoXml::Native.verify(xml, [signer_cert_pem], [], id_attrs, 0)

      expect(result[:status]).to eq(:succeeded)
      expect(result[:errors]).to be_empty
    end

    it "verifies against a public key PEM and ignores KeyInfo" do
      xml = fixtures.join("signed_exc_c14n.xml").read
      pubkey = OpenSSL::X509::Certificate.new(signer_cert_pem).public_key.to_pem
      result = HankoXml::Native.verify(xml, [pubkey], [], id_attrs, 0)

      expect(result[:status]).to eq(:succeeded)
    end

    it "returns :invalid when the public key PEM does not match the signature" do
      xml = fixtures.join("signed_exc_c14n.xml").read
      other_key = OpenSSL::X509::Certificate.new(other_cert_pem).public_key.to_pem
      result = HankoXml::Native.verify(xml, [other_key], [], id_attrs, 0)

      expect(result[:status]).to eq(:invalid).or eq(:unknown)
      expect(result[:errors]).not_to be_empty
    end

    it "returns :invalid with captured error messages when the certificate does not match" do
      xml = fixtures.join("signed_exc_c14n.xml").read
      result = HankoXml::Native.verify(xml, [other_cert_pem], [], id_attrs, 0)

      expect(result[:status]).to eq(:invalid).or eq(:unknown)
      expect(result[:errors]).not_to be_empty
      expect(result[:errors].first).to match(/func=|error=/)
    end

    it "verifies all fixture formats" do
      %w[
        signed_exc_c14n.xml
        signed_sha512.xml
        signed_enveloping.xml
        signed_detached.xml
        signed_nfe.xml
      ].each do |filename|
        xml = fixtures.join(filename).read
        result = HankoXml::Native.verify(xml, [signer_cert_pem], [], id_attrs, 0)
        expect(result[:status]).to eq(:succeeded), "Expected #{filename} to verify as :succeeded, got #{result.inspect}"
      end
    end

    it "raises ParseError for unparseable XML" do
      expect do
        HankoXml::Native.verify("not xml", [signer_cert_pem], [], id_attrs, 0)
      end.to raise_error(HankoXml::ParseError)
    end

    it "raises NativeError when document has no signature" do
      unsigned_xml = "<Envelope><Data>Hello</Data></Envelope>"
      expect do
        HankoXml::Native.verify(unsigned_xml, [signer_cert_pem], [], id_attrs, 0)
      end.to raise_error(HankoXml::NativeError, /no <Signature>/)
    end
  end

  describe ".sign" do
    it "signs a template document and produces XML that verifies" do
      template_xml = fixtures.join("template.xml").read
      signed_xml = HankoXml::Native.sign(template_xml, signer_key_pem, [signer_cert_pem], id_attrs, 0)

      expect(signed_xml).to be_a(String)
      expect(signed_xml).not_to eq(template_xml)
      expect(signed_xml).to include("<SignatureValue>")
      expect(signed_xml).not_to include("<SignatureValue/>")

      # Verify the produced signature
      verify_result = HankoXml::Native.verify(signed_xml, [signer_cert_pem], [], id_attrs, 0)
      expect(verify_result[:status]).to eq(:succeeded)
    end

    it "signs all template fixtures and produces valid signatures" do
      %w[
        template.xml
        template_detached.xml
        template_enveloping.xml
        template_exc_c14n.xml
        template_sha512.xml
        template_nfe.xml
      ].each do |filename|
        template_xml = fixtures.join(filename).read
        signed_xml = HankoXml::Native.sign(template_xml, signer_key_pem, [signer_cert_pem], id_attrs, 0)

        verify_result = HankoXml::Native.verify(signed_xml, [signer_cert_pem], [], id_attrs, 0)
        msg = "Expected signed #{filename} to verify, got #{verify_result.inspect}"
        expect(verify_result[:status]).to eq(:succeeded), msg
      end
    end

    it "raises ParseError for unparseable XML" do
      expect do
        HankoXml::Native.sign("not xml", signer_key_pem, [signer_cert_pem], id_attrs, 0)
      end.to raise_error(HankoXml::ParseError)
    end

    it "raises KeyLoadError for an invalid private key" do
      template_xml = fixtures.join("template.xml").read
      expect do
        HankoXml::Native.sign(template_xml, "bad key data", [signer_cert_pem], id_attrs, 0)
      end.to raise_error(HankoXml::KeyLoadError)
    end
  end

  describe "safety budget" do
    it "keeps unsafe blocks contained in dsig.rs and errors.rs" do
      src_dir = Pathname.new(__dir__).join("../../ext/hanko_xml/src")
      rust_files = Dir.glob(src_dir.join("*.rs"))

      unsafe_counts = {}
      rust_files.each do |file|
        content = File.read(file)
        lines = content.lines.reject do |l|
          s = l.strip
          s.start_with?("//") || s.start_with?("/*") || s.start_with?("*")
        end
        count = lines.count { |l| l.include?("unsafe") }
        unsafe_counts[File.basename(file)] = count
      end

      # lib.rs should only have 1 unsafe block for converting RString to byte slice
      expect(unsafe_counts["lib.rs"]).to be <= 1
    end
  end
end
