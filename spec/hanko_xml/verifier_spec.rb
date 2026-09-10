# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require "pathname"

module HankoXmlVerifierSpecHelpers
  module_function

  def pem_body(pem)
    pem.gsub(/-----(BEGIN|END) CERTIFICATE-----/, "").gsub(/\s+/, "")
  end

  def reverse_keyinfo_certificates(xml)
    doc = Nokogiri::XML(xml)
    x509 = doc.at_xpath("//ds:X509Data", HankoXml::NS)
    x509.element_children.reverse_each { |node| x509.add_child(node) }
    doc
  end

  def add_keyinfo_certificate(xml, cert)
    doc = Nokogiri::XML(xml)
    x509 = doc.at_xpath("//ds:X509Data", HankoXml::NS)
    node = doc.create_element("X509Certificate")
    node.namespace = x509.namespace
    node.content = pem_body(cert.to_pem)
    x509.add_child(node)
    doc
  end

  def issue_cert(subject:, key:, serial:, is_ca:, issuer_cert: nil, issuer_key: nil,
                 not_before: Time.now - 3600, not_after: Time.now + 86_400)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{subject}")
    cert.issuer = issuer_cert ? issuer_cert.subject : cert.subject
    cert.public_key = key
    cert.not_before = not_before
    cert.not_after = not_after
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer_cert || cert
    cert.add_extension(factory.create_extension("basicConstraints", is_ca ? "CA:TRUE" : "CA:FALSE", true))
    cert.add_extension(factory.create_extension("keyUsage", is_ca ? "keyCertSign,cRLSign" : "digitalSignature", true))
    cert.add_extension(factory.create_extension("subjectKeyIdentifier", "hash", false))
    cert.add_extension(factory.create_extension("authorityKeyIdentifier", "keyid:always", false)) if issuer_cert
    cert.sign(issuer_key || key, OpenSSL::Digest.new("SHA256"))
    cert
  end
end

RSpec.describe HankoXml::Verifier do
  include HankoXmlVerifierSpecHelpers
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:signer_key_pem) { fixtures.join("signer.key").read }
  let(:signer_cert_pem) { fixtures.join("signer.crt").read }
  let(:other_cert_pem) { fixtures.join("other.crt").read }
  let(:unsigned_xml) { %(<Envelope xmlns="urn:hanko_xml:example"><Data>Hello, world!</Data></Envelope>) }

  describe "#native_id_attributes" do
    it "passes plain string id_attributes through unchanged" do
      verifier = described_class.new(id_attributes: %w[Id ID id])

      expect(verifier.send(:native_id_attributes)).to eq(%w[Id ID id])
    end

    it "reduces namespace-qualified [ns, name] entries to their local name" do
      verifier = described_class.new(id_attributes: [["http://example.com/ns", "CustomId"], "Id"])

      expect(verifier.send(:native_id_attributes)).to eq(%w[CustomId Id])
    end
  end

  describe "key:" do
    let(:signer_key) { OpenSSL::PKey::RSA.new(signer_key_pem) }
    let(:other_key) { OpenSSL::PKey::RSA.new(fixtures.join("other.key").read) }

    it "validates against the signing public key" do
      signed = HankoXml.sign(unsigned_xml, key: signer_key_pem, certificate: signer_cert_pem)

      expect(HankoXml.verify(signed.to_s, key: signer_key.public_key).valid?).to be true
    end

    it "rejects a public key that did not produce the signature" do
      signed = HankoXml.sign(unsigned_xml, key: signer_key_pem, certificate: signer_cert_pem)
      result = HankoXml.verify(signed.to_s, key: other_key.public_key)

      expect(result.valid?).to be false
    end

    it "ignores KeyInfo certificates" do
      signed = HankoXml.sign(unsigned_xml, key: signer_key_pem, certificate: signer_cert_pem)
      doc = Nokogiri::XML(signed.to_s)
      cert_node = doc.at_xpath("//ds:X509Certificate", HankoXml::NS)
      cert_node.content = pem_body(other_cert_pem)

      expect(HankoXml.verify(doc, key: signer_key.public_key).valid?).to be true
    end

    it "validates a signature that has no KeyInfo at all" do
      signed = HankoXml.sign(unsigned_xml, key: signer_key_pem, key_info: [])

      expect(HankoXml.verify(signed.to_s, key: signer_key.public_key).valid?).to be true
    end
  end

  describe "store:" do
    # Generated once for the group: 2048-bit RSA is slow enough that per-example
    # generation would dominate this file.
    before(:context) do
      @root_key = OpenSSL::PKey::RSA.new(2048)
      @intermediate_key = OpenSSL::PKey::RSA.new(2048)
      @leaf_key = OpenSSL::PKey::RSA.new(2048)
      @other_leaf_key = OpenSSL::PKey::RSA.new(2048)

      @root_cert = HankoXmlVerifierSpecHelpers.issue_cert(subject: "test-root", key: @root_key, serial: 1, is_ca: true)
      @intermediate_cert = HankoXmlVerifierSpecHelpers.issue_cert(
        subject: "test-intermediate", key: @intermediate_key, serial: 2, is_ca: true,
        issuer_cert: @root_cert, issuer_key: @root_key
      )
      @leaf_cert = HankoXmlVerifierSpecHelpers.issue_cert(
        subject: "test-leaf", key: @leaf_key, serial: 3, is_ca: false,
        issuer_cert: @intermediate_cert, issuer_key: @intermediate_key
      )
      @other_leaf_cert = HankoXmlVerifierSpecHelpers.issue_cert(
        subject: "test-other-leaf", key: @other_leaf_key, serial: 4, is_ca: false,
        issuer_cert: @intermediate_cert, issuer_key: @intermediate_key
      )
      @expired_leaf_cert = HankoXmlVerifierSpecHelpers.issue_cert(
        subject: "test-expired-leaf", key: @leaf_key, serial: 5, is_ca: false,
        issuer_cert: @intermediate_cert, issuer_key: @intermediate_key,
        not_before: Time.now - 7200, not_after: Time.now - 60
      )
    end

    let(:root_cert) { @root_cert }
    let(:intermediate_cert) { @intermediate_cert }
    let(:leaf_cert) { @leaf_cert }
    let(:leaf_key) { @leaf_key }
    let(:root_store) do
      OpenSSL::X509::Store.new.tap { |store| store.add_cert(root_cert) }
    end

    def sign_chain(certs)
      HankoXml.sign(
        unsigned_xml,
        key: leaf_key,
        certificate: certs.first,
        certificates: certs.drop(1)
      ).to_s
    end

    it "validates a chain when only the root is in the store" do
      signed = sign_chain([leaf_cert, intermediate_cert])

      expect(HankoXml.verify(signed, store: root_store).valid?).to be true
    end

    it "validates when KeyInfo lists the intermediate before the leaf" do
      signed = reverse_keyinfo_certificates(sign_chain([leaf_cert, intermediate_cert]))

      expect(HankoXml.verify(signed, store: root_store).valid?).to be true
    end

    it "rejects a chain that does not reach the store" do
      store = OpenSSL::X509::Store.new
      store.add_cert(OpenSSL::X509::Certificate.new(other_cert_pem))
      signed = sign_chain([leaf_cert, intermediate_cert])
      result = HankoXml.verify(signed, store: store)

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::UntrustedCertificate)
    end

    it "rejects KeyInfo with no certificates" do
      signed = HankoXml.sign(unsigned_xml, key: leaf_key, key_info: []).to_s
      result = HankoXml.verify(signed, store: root_store)

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::UntrustedCertificate)
      expect(result.errors.first.message).to match(/No X509Certificate/)
    end

    it "applies verification_time to the signing cert, not an intermediate listed first" do
      signed = reverse_keyinfo_certificates(sign_chain([@expired_leaf_cert, intermediate_cert]))
      result = HankoXml.verify(signed, store: root_store, verification_time: Time.now)

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::UntrustedCertificate)
    end

    it "does not mutate the caller's store" do
      assigned = nil
      store = OpenSSL::X509::Store.new
      store.add_cert(root_cert)
      store.define_singleton_method(:time=) { |time| assigned = time }

      signed = sign_chain([leaf_cert, intermediate_cert])
      result = HankoXml.verify(signed, store: store, verification_time: Time.now)

      expect(result.valid?).to be true
      expect(assigned).to be_nil
    end

    it "fails closed when two end-entity certs in KeyInfo both chain to the store" do
      signed = add_keyinfo_certificate(
        sign_chain([leaf_cert, intermediate_cert]),
        @other_leaf_cert
      )
      result = HankoXml.verify(signed, store: root_store)

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::UntrustedCertificate)
      expect(result.errors.first.message).to match(/Ambiguous KeyInfo/)
    end

    it "threads id_attributes through a failed store check" do
      signed = HankoXml.sign(unsigned_xml, key: leaf_key, key_info: []).to_s
      result = HankoXml.verify(signed, store: root_store, id_attributes: ["CustomId"])

      expect(result.valid?).to be false
      expect(result.id_attributes).to eq(["CustomId"])
    end
  end

  describe "keys:" do
    let(:signer_key) { OpenSSL::PKey::RSA.new(signer_key_pem) }

    def sign_with_key_name(name)
      doc = Nokogiri::XML(unsigned_xml)
      signer = HankoXml::Signer.new(
        key: signer_key_pem,
        certificate: signer_cert_pem,
        key_info: %i[key_name x509_certificate],
        template: :require
      )
      sig = signer.template(doc)
      sig.at_xpath("ds:KeyInfo/ds:KeyName", HankoXml::NS).content = name
      HankoXml::Placement.append_to_root.insert(doc, sig)
      signer.sign!(doc)
      doc
    end

    it "selects a public-key entry by KeyName" do
      doc = sign_with_key_name("idp-1")

      expect(HankoXml.verify(doc, keys: { "idp-1" => signer_key.public_key }).valid?).to be true
    end

    it "selects a certificate entry by KeyName" do
      doc = sign_with_key_name("idp-1")

      expect(HankoXml.verify(doc, keys: { "idp-1" => signer_cert_pem }).valid?).to be true
    end

    it "fails closed when KeyName is missing from the map" do
      doc = sign_with_key_name("idp-1")
      result = HankoXml.verify(doc, keys: { "other-idp" => signer_key.public_key })

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::UntrustedCertificate)
    end
  end
end
