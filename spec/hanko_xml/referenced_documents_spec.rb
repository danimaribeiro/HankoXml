# frozen_string_literal: true

require "spec_helper"
require "digest"
require "nokogiri"
require "pathname"
require "tempfile"

# #74: referenced_documents: is the only source an external Reference is read
# from. xmlsec's file/HTTP/FTP readers are replaced at init by one that serves
# nothing but the map of the verification in progress.
RSpec.describe "referenced_documents: (#74)" do
  let(:vectors) { Pathname.new(__dir__).join("../interop/vectors") }
  let(:stylesheet_uri) { "http://www.w3.org/TR/xml-stylesheet" }
  let(:stylesheet) { vectors.join("external-data/xml-stylesheet-2005").binread }
  let(:signed_xml) { vectors.join("merlin-xmldsig-twenty-three/signature-x509-sn.xml").binread }
  let(:cert) { OpenSSL::X509::Certificate.new(vectors.join("merlin-xmldsig-twenty-three/certs/badb.pem").binread) }

  def verify(xml = signed_xml, policy: HankoXml::Policy.interop, **options)
    HankoXml::Verifier.new(certificate: cert, policy: policy, verification_time: Time.utc(2005, 1, 1), **options)
                      .verify(xml)
  end

  # A Signature whose only Reference points at +uri+ with the right SHA-256
  # digest of +content+. Its SignatureValue is garbage, so the result is always
  # invalid, but the Reference's own digest status shows whether xmlsec read
  # the content.
  def reference_only_signature(uri, content)
    <<~XML
      <Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>
        <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <Reference URI="#{uri}"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <DigestValue>#{Digest::SHA256.base64digest(content)}</DigestValue></Reference>
      </SignedInfo><SignatureValue>AAAA</SignatureValue></Signature>
    XML
  end

  # An RSA certificate, to match the signature method above: xmlsec checks
  # the key against it before it processes any Reference.
  def native_reference_valid(xml, referenced)
    rsa_cert = Pathname.new(__dir__).join("../fixtures/signer.crt").read
    HankoXml::Native.verify(xml, [rsa_cert], [], [], 0, referenced)[:reference_valid]
  end

  it "verifies an external reference from the map, with allow_external_references still false" do
    expect(HankoXml::Policy.interop.allow_external_references).to be false
    expect(verify(referenced_documents: { stylesheet_uri => stylesheet }).valid?).to be true
  end

  it "fails when the mapped bytes are not what was signed" do
    expect(verify(referenced_documents: { stylesheet_uri => "#{stylesheet} " }).valid?).to be false
  end

  it "accepts a key with a #fragment, and a Nokogiri document" do
    xml = %(<Envelope xmlns="urn:x"><Data>A</Data></Envelope>)
    verifier = HankoXml::Verifier.new(certificate: cert, referenced_documents: {
                                        "#{stylesheet_uri}#part" => stylesheet, "urn:doc" => Nokogiri::XML(xml)
                                      })

    expect(verifier.referenced_documents.keys).to eq([stylesheet_uri, "urn:doc"])
    expect(verifier.referenced_documents["urn:doc"]).to eq(HankoXml.serialize(Nokogiri::XML(xml)))
  end

  it "keeps PolicyError for an unmapped external reference the policy forbids" do
    expect(verify.errors.first).to be_a(HankoXml::PolicyError)
  end

  it "is a ReferenceError for an unmapped external reference the policy allows, and fetches nothing" do
    result = verify(policy: HankoXml::Policy.permissive, referenced_documents: { "urn:other" => "x" })

    expect(result.errors.first).to be_a(HankoXml::ReferenceError)
    expect(result.errors.first.reference_uri).to eq(stylesheet_uri)
  end

  it "rejects a map that is not URI => String or Document" do
    expect { HankoXml::Verifier.new(certificate: cert, referenced_documents: [[stylesheet_uri, stylesheet]]) }
      .to raise_error(HankoXml::ConfigurationError, /Hash/)
    expect { HankoXml::Verifier.new(certificate: cert, referenced_documents: { stylesheet_uri => 42 }) }
      .to raise_error(HankoXml::ConfigurationError, /Integer/)
  end

  describe "the native reader, below every Ruby check" do
    let(:file) do
      Tempfile.new("hanko-referenced").tap do |f|
        f.write("secret file content")
        f.flush
      end
    end
    let(:file_uri) { "file://#{file.path}" }

    after { file.close! }

    it "digests a mapped URI" do
      xml = reference_only_signature(file_uri, "mapped content")
      expect(native_reference_valid(xml, [[file_uri, "mapped content"]])).to eq([true])
    end

    # The file holds exactly the digested bytes, so any reader that served it
    # would report true. nil means xmlsec could not open the URI at all.
    it "never reads the filesystem, even with external URIs enabled by another mapped URI" do
      xml = reference_only_signature(file_uri, "secret file content")

      expect(native_reference_valid(xml, [[file_uri, "secret file content"]])).to eq([true])
      expect(native_reference_valid(xml, [["urn:other", "x"]])).to eq([nil])
      expect(native_reference_valid(xml, [])).to eq([nil])
    end

    it "does not serve one verification's documents to the next" do
      xml = reference_only_signature(file_uri, "mapped content")
      expect(native_reference_valid(xml, [[file_uri, "mapped content"]])).to eq([true])

      expect(native_reference_valid(xml, [["urn:other", "x"]])).to eq([nil])
    end
  end
end
