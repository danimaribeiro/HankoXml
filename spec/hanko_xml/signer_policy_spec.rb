# frozen_string_literal: true

require "spec_helper"
require "fileutils"
require "nokogiri"
require "openssl"
require "pathname"
require "socket"
require "timeout"
require "tmpdir"

# S-05: Signer enforces Policy and reference URIs before Native.sign, so an
# adopted/required <Signature> template cannot be a signing oracle.
RSpec.describe "S-05 Signer policy before Native.sign" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:signer_key_pem) { fixtures.join("signer.key").read }
  let(:signer_cert_pem) { fixtures.join("signer.crt").read }
  let(:unsigned_xml) { %(<Envelope xmlns="urn:hanko_xml:example"><Data>Hello</Data></Envelope>) }
  let(:enveloped_template) { fixtures.join("template.xml").read }

  def rewrite_reference_uri(xml, uri)
    doc = Nokogiri::XML(xml)
    reference = doc.at_xpath("//ds:Reference", HankoXml::NS)
    reference["URI"] = uri
    HankoXml.serialize(doc)
  end

  def rewrite_signature_method(xml, algorithm)
    doc = Nokogiri::XML(xml)
    method = doc.at_xpath("//ds:SignatureMethod", HankoXml::NS)
    method["Algorithm"] = algorithm
    HankoXml.serialize(doc)
  end

  def with_fifo
    dir = Dir.mktmpdir("hanko-s05-")
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
      yield "http://127.0.0.1:#{port}/s05-probe", -> { mutex.synchronize { hits } }
    ensure
      server.close
      thread.join(0.5)
    end
  end

  it "still signs a same-document template under Policy.strict" do
    signed = HankoXml.sign(enveloped_template, key: signer_key_pem, certificate: signer_cert_pem)
    expect(HankoXml.valid?(signed.to_xml, certificate: signer_cert_pem)).to be true
  end

  it "still builds and signs an unsigned document under Policy.strict" do
    signed = HankoXml.sign(unsigned_xml, key: signer_key_pem, certificate: signer_cert_pem)
    expect(HankoXml.valid?(signed.to_xml, certificate: signer_cert_pem)).to be true
  end

  it "rejects a file:// Reference under strict before Native.sign (R3)" do
    with_fifo do |fifo|
      xml = rewrite_reference_uri(enveloped_template, "file://#{fifo}")
      allow(HankoXml::Native).to receive(:sign).and_call_original

      expect do
        Timeout.timeout(2) do
          HankoXml.sign(xml, key: signer_key_pem, certificate: signer_cert_pem)
        end
      end.to raise_error(HankoXml::PolicyError, /external/)

      expect(HankoXml::Native).not_to have_received(:sign)
    end
  end

  it "does not connect to an http:// Reference under strict (R3)" do
    with_http_probe do |uri, hits|
      xml = rewrite_reference_uri(enveloped_template, uri)

      expect do
        HankoXml.sign(xml, key: signer_key_pem, certificate: signer_cert_pem)
      end.to raise_error(HankoXml::PolicyError, /external/)

      expect(hits.call).to eq(0)
    end
  end

  it "rejects rsa-sha1 on an adopted template under Policy.strict (R4)" do
    xml = rewrite_signature_method(enveloped_template, "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
    allow(HankoXml::Native).to receive(:sign).and_call_original

    expect do
      HankoXml.sign(xml, key: signer_key_pem, certificate: signer_cert_pem)
    end.to raise_error(HankoXml::PolicyError, /signature/)

    expect(HankoXml::Native).not_to have_received(:sign)
  end

  it "rejects an adopted fragment URI that is not in Signer#references (R5)" do
    xml = rewrite_reference_uri(enveloped_template, "#attacker-node")
    allow(HankoXml::Native).to receive(:sign).and_call_original

    expect do
      HankoXml.sign(xml, key: signer_key_pem, certificate: signer_cert_pem)
    end.to raise_error(HankoXml::ConfigurationError, /attacker-node/)

    expect(HankoXml::Native).not_to have_received(:sign)
  end

  it "signs an adopted fragment template when references: opts in (R5)" do
    xml = fixtures.join("template_detached.xml").read
    signed = HankoXml.sign(
      xml,
      key: signer_key_pem,
      certificate: signer_cert_pem,
      references: ["#payload-1"]
    )

    # A fragment signature does not cover the document root; require_signed_root
    # (a verification-time XSW defence, not a signing constraint -- S-06) does
    # not apply to Signer (that is the whole point of this test), but Verifier
    # still enforces it by default, so verifying it needs the explicit opt-out.
    policy = HankoXml::Policy.strict.with(require_signed_root: false)
    expect(HankoXml.valid?(signed.to_xml, certificate: signer_cert_pem, policy: policy)).to be true
  end

  it "rejects a Signer-configured file:// reference before Native.sign (H7/C15)" do
    allow(HankoXml::Native).to receive(:sign).and_call_original

    expect do
      HankoXml.sign(
        unsigned_xml,
        key: signer_key_pem,
        certificate: signer_cert_pem,
        references: [{ uri: "file:///tmp/s05-configured", transforms: [] }]
      )
    end.to raise_error(HankoXml::PolicyError, /external/)

    expect(HankoXml::Native).not_to have_received(:sign)
  end

  it "rejects rsa-sha1 from Signer configuration under Policy.strict (H7)" do
    allow(HankoXml::Native).to receive(:sign).and_call_original

    expect do
      HankoXml.sign(
        unsigned_xml,
        key: signer_key_pem,
        certificate: signer_cert_pem,
        signature_method: :rsa_sha1
      )
    end.to raise_error(HankoXml::PolicyError, /signature/)

    expect(HankoXml::Native).not_to have_received(:sign)
  end

  it "enforces the same checks under template: :require" do
    xml = rewrite_signature_method(enveloped_template, "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
    allow(HankoXml::Native).to receive(:sign).and_call_original

    expect do
      HankoXml.sign(xml, key: signer_key_pem, certificate: signer_cert_pem, template: :require)
    end.to raise_error(HankoXml::PolicyError, /signature/)

    expect(HankoXml::Native).not_to have_received(:sign)
  end

  it "calls Native.sign under permissive for a SHA-1 template but still does not fetch file://" do
    with_fifo do |fifo|
      xml = rewrite_reference_uri(enveloped_template, "file://#{fifo}")
      allow(HankoXml::Native).to receive(:sign).and_call_original

      expect do
        Timeout.timeout(2) do
          HankoXml.sign(
            xml,
            key: signer_key_pem,
            certificate: signer_cert_pem,
            policy: HankoXml::Policy.permissive,
            references: ["file://#{fifo}"]
          )
        end
      end.to raise_error(HankoXml::SigningError)

      expect(HankoXml::Native).to have_received(:sign)
    end
  end
end
