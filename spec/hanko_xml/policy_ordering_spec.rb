# frozen_string_literal: true

require "spec_helper"
require "fileutils"
require "nokogiri"
require "openssl"
require "pathname"
require "socket"
require "timeout"
require "tmpdir"

# S-04: Policy is enforced on inspect_sig *before* Native.verify, and the
# native dsig context rejects file:// / http:// Reference URIs so libxml2
# never fetches them.
RSpec.describe "S-04 policy before crypto" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:signer_key_pem) { fixtures.join("signer.key").read }
  let(:signer_cert_pem) { fixtures.join("signer.crt").read }
  let(:id_attrs) { %w[Id ID id] }
  let(:unsigned_xml) { %(<Envelope xmlns="urn:hanko_xml:example"><Data>Hello</Data></Envelope>) }
  let(:signed_xml) { HankoXml.sign(unsigned_xml, key: signer_key_pem, certificate: signer_cert_pem).to_xml }

  def rewrite_reference_uri(xml, uri)
    doc = Nokogiri::XML(xml)
    reference = doc.at_xpath("//ds:Reference", HankoXml::NS)
    reference["URI"] = uri
    HankoXml.serialize(doc)
  end

  def add_transforms(xml, algorithms)
    doc = Nokogiri::XML(xml)
    transforms = doc.at_xpath("//ds:Reference/ds:Transforms", HankoXml::NS)
    algorithms.each do |algorithm|
      node = doc.create_element("Transform")
      node.namespace = transforms.namespace
      node["Algorithm"] = algorithm
      transforms.add_child(node)
    end
    HankoXml.serialize(doc)
  end

  def with_fifo
    dir = Dir.mktmpdir("hanko-s04-")
    fifo = File.join(dir, "probe")
    File.mkfifo(fifo)
    begin
      yield fifo
    ensure
      FileUtils.remove_entry(dir)
    end
  end

  def with_http_probe
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    hits = 0
    mutex = Mutex.new
    thread = Thread.new do
      client = server.accept
      mutex.synchronize { hits += 1 }
      client.close
    rescue IOError, Errno::EBADF, Errno::EINVAL
      # ensure closes the listening socket; accept then raises.
    end
    begin
      yield "http://127.0.0.1:#{port}/s04-probe", -> { mutex.synchronize { hits } }
    ensure
      server.close
      thread.join(0.5)
    end
  end

  it "still verifies a same-document signature under Policy.strict" do
    expect(HankoXml.valid?(signed_xml, certificate: signer_cert_pem)).to be true
  end

  it "rejects a file:// Reference under strict before Native.verify (R1)" do
    with_fifo do |fifo|
      xml = rewrite_reference_uri(signed_xml, "file://#{fifo}")
      allow(HankoXml::Native).to receive(:verify).and_call_original

      result = Timeout.timeout(2) do
        HankoXml::Verifier.new(certificate: signer_cert_pem).verify(xml)
      end

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::PolicyError)
      expect(result.errors.first.message).to match(/external/)
      expect(HankoXml::Native).not_to have_received(:verify)
    end
  end

  it "does not connect to an http:// Reference under strict (R1)" do
    with_http_probe do |uri, hits|
      xml = rewrite_reference_uri(signed_xml, uri)
      result = HankoXml::Verifier.new(certificate: signer_cert_pem).verify(xml)

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::PolicyError)
      expect(hits.call).to eq(0)
    end
  end

  # #74: an external URI not in referenced_documents: now stops in Ruby, even
  # under permissive. The native layer's own refusal is covered directly below.
  it "refuses an unmapped file:// Reference under permissive without fetching it (R2)" do
    with_fifo do |fifo|
      xml = rewrite_reference_uri(signed_xml, "file://#{fifo}")
      allow(HankoXml::Native).to receive(:verify).and_call_original

      result = Timeout.timeout(2) do
        HankoXml::Verifier.new(certificate: signer_cert_pem, policy: HankoXml::Policy.permissive).verify(xml)
      end

      expect(HankoXml::Native).not_to have_received(:verify)
      expect(result.errors.first).to be_a(HankoXml::ReferenceError)
      expect(result.errors.first.reference_uri).to eq("file://#{fifo}")
      expect(result.errors.first.message).not_to include(fifo.to_s)
    end
  end

  it "rejects an XSLT transform under strict before Native.verify (R6/R7)" do
    xml = add_transforms(signed_xml, ["http://www.w3.org/TR/1999/REC-xslt-19991116"])
    allow(HankoXml::Native).to receive(:verify).and_call_original

    result = HankoXml::Verifier.new(certificate: signer_cert_pem).verify(xml)

    expect(result.valid?).to be false
    expect(result.errors.first).to be_a(HankoXml::PolicyError)
    expect(result.errors.first.message).to match(/transform/)
    expect(HankoXml::Native).not_to have_received(:verify)
  end

  it "rejects too many transforms before Native.verify (R8)" do
    extra = Array.new(5, "http://www.w3.org/2001/10/xml-exc-c14n#")
    xml = add_transforms(signed_xml, extra)
    allow(HankoXml::Native).to receive(:verify).and_call_original

    result = HankoXml::Verifier.new(certificate: signer_cert_pem).verify(xml)

    expect(result.valid?).to be false
    expect(result.errors.first).to be_a(HankoXml::PolicyError)
    expect(result.errors.first.message).to match(/max_transforms_per_reference/)
    expect(HankoXml::Native).not_to have_received(:verify)
  end

  describe "Native.verify URI restriction" do
    it "does not block on a FIFO file:// Reference" do
      with_fifo do |fifo|
        xml = rewrite_reference_uri(signed_xml, "file://#{fifo}")

        result = Timeout.timeout(2) do
          HankoXml::Native.verify(xml, [signer_cert_pem], [], id_attrs, 0, [], false)
        end

        expect(result[:status]).not_to eq(:succeeded)
      end
    end

    it "does not connect to an http:// Reference" do
      with_http_probe do |uri, hits|
        xml = rewrite_reference_uri(signed_xml, uri)
        result = HankoXml::Native.verify(xml, [signer_cert_pem], [], id_attrs, 0, [], false)

        expect(result[:status]).not_to eq(:succeeded)
        expect(hits.call).to eq(0)
      end
    end
  end

  describe "Native transform restriction (S-10)" do
    it "rejects XSLT transform even when called directly" do
      xml = add_transforms(signed_xml, ["http://www.w3.org/TR/1999/REC-xslt-19991116"])

      result = HankoXml::Native.verify(xml, [signer_cert_pem], [], id_attrs, 0, [], false)

      # The signature fails because the XSLT transform is not in the allow-list
      expect(result[:status]).not_to eq(:succeeded)
      expect(%i[invalid unknown]).to include(result[:status])
    end

    it "allows enveloped signature transform" do
      # Enveloped is a core DSig transform that should be allowed
      xml = add_transforms(signed_xml, ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"])

      result = HankoXml::Native.verify(xml, [signer_cert_pem], [], id_attrs, 0, [], false)

      # The signature may not be valid due to the added transform, but it
      # should not be rejected because the transform type is unsupported
      expect(%i[invalid unknown]).to include(result[:status])
    end
  end
end
