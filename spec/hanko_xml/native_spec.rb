# frozen_string_literal: true

require "nokogiri"
require "openssl"
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
    it "reports the KeyInfo a Signer without a DOM can't prepare (#67, #72, #102)" do
      template = fixtures.join("template.xml").read
      flags = lambda do |xml|
        HankoXml::Native.inspect_sig(xml, 0).slice(:empty_key_names, :key_derived_values)
      end

      expect(flags.call(template)).to eq(empty_key_names: false, key_derived_values: false)
      expect(flags.call(template.sub("<X509Data/>", "<KeyName> </KeyName><X509Data/>")))
        .to eq(empty_key_names: true, key_derived_values: false)
      %w[<X509Data><X509SKI>AA==</X509SKI></X509Data> <KeyValue><x/></KeyValue>].each do |leaf|
        expect(flags.call(template.sub("<X509Data/>", leaf))).to eq(empty_key_names: false, key_derived_values: true)
      end
      expect(flags.call(fixtures.join("signed.xml").read)[:key_derived_values]).to be true
    end

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
      result = HankoXml::Native.verify(xml, [signer_cert_pem], [], id_attrs, 0, [], false)

      expect(result[:status]).to eq(:succeeded)
      expect(result[:errors]).to be_empty
    end

    it "verifies against a public key PEM and ignores KeyInfo" do
      xml = fixtures.join("signed_exc_c14n.xml").read
      pubkey = OpenSSL::X509::Certificate.new(signer_cert_pem).public_key.to_pem
      result = HankoXml::Native.verify(xml, [pubkey], [], id_attrs, 0, [], false)

      expect(result[:status]).to eq(:succeeded)
    end

    it "returns :invalid when the public key PEM does not match the signature" do
      xml = fixtures.join("signed_exc_c14n.xml").read
      other_key = OpenSSL::X509::Certificate.new(other_cert_pem).public_key.to_pem
      result = HankoXml::Native.verify(xml, [other_key], [], id_attrs, 0, [], false)

      expect(result[:status]).to eq(:invalid).or eq(:unknown)
      expect(result[:errors]).not_to be_empty
    end

    it "returns :invalid with captured error messages when the certificate does not match" do
      xml = fixtures.join("signed_exc_c14n.xml").read
      result = HankoXml::Native.verify(xml, [other_cert_pem], [], id_attrs, 0, [], false)

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
        result = HankoXml::Native.verify(xml, [signer_cert_pem], [], id_attrs, 0, [], false)
        expect(result[:status]).to eq(:succeeded), "Expected #{filename} to verify as :succeeded, got #{result.inspect}"
      end
    end

    it "raises ParseError for unparseable XML" do
      expect do
        HankoXml::Native.verify("not xml", [signer_cert_pem], [], id_attrs, 0, [], false)
      end.to raise_error(HankoXml::ParseError)
    end

    it "raises NativeError when document has no signature" do
      unsigned_xml = "<Envelope><Data>Hello</Data></Envelope>"
      expect do
        HankoXml::Native.verify(unsigned_xml, [signer_cert_pem], [], id_attrs, 0, [], false)
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
      verify_result = HankoXml::Native.verify(signed_xml, [signer_cert_pem], [], id_attrs, 0, [], false)
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
        template_saml_inclusive_namespaces.xml
      ].each do |filename|
        template_xml = fixtures.join(filename).read
        signed_xml = HankoXml::Native.sign(template_xml, signer_key_pem, [signer_cert_pem], id_attrs, 0)

        verify_result = HankoXml::Native.verify(signed_xml, [signer_cert_pem], [], id_attrs, 0, [], false)
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

  # #161: one element of a signature, canonicalized by xmlsec's own C14N
  # transforms, as the XAdES-T timestamp imprint needs it (#81).
  describe ".canonicalize" do
    let(:ds) { HankoXml::NS["ds"] }
    let(:exc) { "http://www.w3.org/2001/10/xml-exc-c14n#" }
    let(:xml) do
      <<~XML
        <root xmlns="urn:r" xmlns:a="urn:a"><ds:Signature xmlns:ds="#{ds}">
          <ds:SignatureValue a:n="1">QUJD<!-- c --></ds:SignatureValue>
          <ds:Object>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
            <ds:CanonicalizationMethod Algorithm="#{exc}"/>
            <ds:CanonicalizationMethod Algorithm="#{exc}">
              <ec:InclusiveNamespaces xmlns:ec="#{exc}" PrefixList="#default"/>
            </ds:CanonicalizationMethod>
            <ds:CanonicalizationMethod Algorithm="#{exc}WithComments"/>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
          </ds:Object>
        </ds:Signature></root>
      XML
    end
    let(:signature_value) { [[ds, "SignatureValue", nil]] }

    def canonicalize(method_index, target = signature_value, source = xml)
      method = [[ds, "Object", nil], [ds, "CanonicalizationMethod", method_index]]
      HankoXml::Native.canonicalize(source, 0, target, method)
    end

    it "renders the element with the namespaces each algorithm keeps" do
      expect(canonicalize(0)).to eq(
        %(<ds:SignatureValue xmlns="urn:r" xmlns:a="urn:a" xmlns:ds="#{ds}" a:n="1">QUJD</ds:SignatureValue>)
      )
      expect(canonicalize(1))
        .to eq(%(<ds:SignatureValue xmlns:a="urn:a" xmlns:ds="#{ds}" a:n="1">QUJD</ds:SignatureValue>))
      expect(canonicalize(3))
        .to eq(%(<ds:SignatureValue xmlns:a="urn:a" xmlns:ds="#{ds}" a:n="1">QUJD<!-- c --></ds:SignatureValue>))
      expect(canonicalize(1).encoding).to eq(Encoding::BINARY)
    end

    it "reads InclusiveNamespaces from the CanonicalizationMethod, as xmlsec does for SignedInfo" do
      expect(canonicalize(2)).to eq(
        %(<ds:SignatureValue xmlns="urn:r" xmlns:a="urn:a" xmlns:ds="#{ds}" a:n="1">QUJD</ds:SignatureValue>)
      )
    end

    it "gives the bytes xmlsec digested for a Reference over the same element" do
      signed = HankoXml::Xades::Signer.new(key: signer_key_pem, certificate: signer_cert_pem)
                                      .sign(%(<Invoice xmlns="urn:x"><Total>1</Total></Invoice>)).to_s
      xades = HankoXml::Xades::NS
      references = HankoXml::Native.inspect_sig(signed, 0)[:references]
      index = references.index { |ref| ref[:type] == HankoXml::Xades::SIGNED_PROPERTIES_TYPE }
      bytes = HankoXml::Native.canonicalize(
        signed, 0,
        [[ds, "Object", nil], [xades, "QualifyingProperties", nil], [xades, "SignedProperties", nil]],
        [[ds, "SignedInfo", nil], [ds, "Reference", index], [ds, "Transforms", nil], [ds, "Transform", 0]]
      )
      reference = Nokogiri::XML(signed).xpath("//ds:Reference", "ds" => ds)[index]
      digest_value = reference.at_xpath("ds:DigestValue", "ds" => ds)

      expect(bytes).to start_with("<xades:SignedProperties")
      expect(OpenSSL::Digest::SHA256.base64digest(bytes)).to eq(digest_value.text)
    end

    it "refuses an algorithm that is not canonicalization (S-10)" do
      expect { canonicalize(4) }.to raise_error(HankoXml::NativeError, /not a supported c14n algorithm/) { |error|
        expect(error.xmlsec_errors).not_to be_empty
      }
    end

    it "refuses an ambiguous or missing path step instead of taking the first match" do
      expect { canonicalize(nil) }.to raise_error(HankoXml::NativeError, /exactly one element/)
      expect { canonicalize(5) }.to raise_error(HankoXml::NativeError, /out of range/)
      expect { canonicalize(1, [[ds, "KeyInfo", nil]]) }.to raise_error(HankoXml::NativeError, /exactly one element/)
      expect { canonicalize(1, [["urn:other", "SignatureValue", nil]]) }
        .to raise_error(HankoXml::NativeError, /exactly one element/)
    end

    it "canonicalizes the signature itself for an empty path" do
      expect(canonicalize(1, [])).to start_with(%(<ds:Signature xmlns:ds="#{ds}">))
    end

    it "raises for malformed steps, bad input and a missing signature" do
      expect { canonicalize(1, [[ds, "SignatureValue"]]) }.to raise_error(HankoXml::NativeError, /path step/)
      expect { canonicalize(1, ["SignatureValue"]) }.to raise_error(HankoXml::NativeError, /path step/)
      expect { canonicalize(1, signature_value, "<root") }.to raise_error(HankoXml::ParseError)
      expect { HankoXml::Native.canonicalize(xml, 1, signature_value, []) }
        .to raise_error(HankoXml::NativeError, /index out of range/)
    end
  end

  # #169: what xmlsec digested for each SignedInfo Reference, for the
  # ArchiveTimeStamp input; only from a signature that verifies.
  describe ".reference_data" do
    let(:ds) { HankoXml::NS["ds"] }
    let(:xml) do
      HankoXml::Signer.new(key: signer_key_pem, certificate: signer_cert_pem) do |signer|
        signer.reference(uri: "")
        signer.reference(uri: "#total", transforms: [:exc_c14n], digest_method: :sha512)
      end.sign(%(<Invoice xmlns="urn:x"><Total Id="total">150.00</Total></Invoice>)).to_s
    end

    it "returns each Reference's digested octets, in SignedInfo order" do
      octets = HankoXml::Native.reference_data(xml, [signer_cert_pem], id_attrs, 0, [], false)
      references = Nokogiri::XML(xml).xpath("//ds:SignedInfo/ds:Reference", "ds" => ds)

      expect(octets.size).to eq(2)
      expect(octets.map(&:encoding).uniq).to eq([Encoding::BINARY])
      expect(octets.last).to eq(%(<Total xmlns="urn:x" Id="total">150.00</Total>).b)
      octets.zip(references, %w[SHA256 SHA512]).each do |bytes, reference, digest|
        expect([OpenSSL::Digest.digest(digest, bytes)].pack("m0"))
          .to eq(reference.at_xpath("ds:DigestValue", "ds" => ds).text.gsub(/\s/, ""))
      end
    end

    it "raises for a signature that does not verify with the given key" do
      expect { HankoXml::Native.reference_data(xml, [other_cert_pem], id_attrs, 0, [], false) }
        .to raise_error(HankoXml::NativeError, /does not verify/)
    end
  end

  # rustc and clippy enforce these rules; this spec keeps anyone from
  # quietly switching them off (ASSURANCE.md §4).
  describe "safety budget" do
    let(:src_dir) { Pathname.new(__dir__).join("../../ext/hanko_xml/src") }
    let(:lib_rs) { src_dir.join("lib.rs").read(encoding: "UTF-8") }

    it "denies unsafe crate-wide and requires a SAFETY comment on every block" do
      expect(lib_rs).to include("#![deny(unsafe_code)]")
      expect(lib_rs).to include("#![warn(clippy::undocumented_unsafe_blocks)]")
    end

    it "allows unsafe only on the FFI modules and the one RString copy in lib.rs" do
      allowed = lib_rs.scan(/#\[allow\(unsafe_code\)\]\s*\n\s*(?:mod|fn) (\w+)/).flatten

      expect(allowed).to contain_exactly("dsig", "errors", "sys", "rstring_to_bytes")
    end

    it "keeps every other Rust file free of crate-level unsafe overrides" do
      Dir.glob(src_dir.join("*.rs")).each do |file|
        content = File.read(file, encoding: "UTF-8")

        expect(content).not_to match(/#!\[(allow|warn|expect)\(unsafe_code\)\]/), file
        expect(content).not_to match(/#!\[allow\(clippy::undocumented_unsafe_blocks\)\]/), file
      end
    end
  end
end
