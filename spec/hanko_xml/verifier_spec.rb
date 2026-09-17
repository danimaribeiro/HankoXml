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

  # key_usage: nil uses the default for is_ca; :none omits the extension.
  def issue_cert(subject:, key:, serial:, is_ca:, issuer_cert: nil, issuer_key: nil,
                 not_before: Time.now - 3600, not_after: Time.now + 86_400, key_usage: nil)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = subject.is_a?(OpenSSL::X509::Name) ? subject : OpenSSL::X509::Name.parse("/CN=#{subject}")
    cert.issuer = issuer_cert ? issuer_cert.subject : cert.subject
    cert.public_key = key
    cert.not_before = not_before
    cert.not_after = not_after
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer_cert || cert
    cert.add_extension(factory.create_extension("basicConstraints", is_ca ? "CA:TRUE" : "CA:FALSE", true))
    key_usage ||= is_ca ? "keyCertSign,cRLSign" : "digitalSignature"
    cert.add_extension(factory.create_extension("keyUsage", key_usage, true)) unless key_usage == :none
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
      verifier = described_class.new(certificate: signer_cert_pem, id_attributes: %w[Id ID id])

      expect(verifier.send(:native_id_attributes)).to eq(%w[Id ID id])
    end

    it "reduces namespace-qualified [ns, name] entries to their local name" do
      verifier = described_class.new(
        certificate: signer_cert_pem,
        id_attributes: [["http://example.com/ns", "CustomId"], "Id"]
      )

      expect(verifier.send(:native_id_attributes)).to eq(%w[CustomId Id])
    end
  end

  describe "trust source selection" do
    it "rejects construction with no trust source" do
      expect { described_class.new }.to raise_error(
        HankoXml::ConfigurationError,
        /exactly one trust source/
      )
    end

    it "rejects construction with two trust sources" do
      expect do
        described_class.new(certificate: signer_cert_pem, key: signer_key_pem)
      end.to raise_error(HankoXml::ConfigurationError, /exactly one trust source/)
    end
  end

  # API_CONTRACT.md §5.4: the certificate whose key verified.
  describe "Verification#certificate" do
    let(:signed) { HankoXml.sign(unsigned_xml, key: signer_key_pem, certificate: signer_cert_pem).to_s }
    let(:signer_cert) { OpenSSL::X509::Certificate.new(signer_cert_pem) }

    it "is the pinned certificate, or the one in certificates: that verified" do
      expect(HankoXml.verify(signed, certificate: signer_cert_pem).certificate).to eq(signer_cert)
      expect(HankoXml.verify(signed, certificates: [other_cert_pem, signer_cert_pem]).certificate).to eq(signer_cert)
    end

    it "is the chain leaf under store:" do
      store = OpenSSL::X509::Store.new.tap { |s| s.add_cert(signer_cert) }
      expect(HankoXml.verify(signed, store: store).certificate).to eq(signer_cert)
    end

    it "is nil for a bare key, or when nothing verified" do
      expect(HankoXml.verify(signed, key: signer_cert.public_key).certificate).to be_nil
      expect(HankoXml.verify(signed, certificate: other_cert_pem).certificate).to be_nil
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

  # #63: certificate-usage policy on the store: signing certificate.
  describe "store: signing certificate policy" do
    before(:context) do
      @ca_key = OpenSSL::PKey::RSA.new(2048)
      @leaf_key = OpenSSL::PKey::RSA.new(2048)
      @ca_cert = HankoXmlVerifierSpecHelpers.issue_cert(subject: "usage-root", key: @ca_key, serial: 10, is_ca: true)
    end

    let(:store) { OpenSSL::X509::Store.new.tap { |s| s.add_cert(@ca_cert) } }

    def leaf(serial, key_usage: nil, subject: "usage-leaf")
      HankoXmlVerifierSpecHelpers.issue_cert(
        subject: subject, key: @leaf_key, serial: serial, is_ca: false,
        issuer_cert: @ca_cert, issuer_key: @ca_key, key_usage: key_usage
      )
    end

    def signed_by(cert)
      HankoXml.sign(unsigned_xml, key: @leaf_key, certificate: cert).to_s
    end

    it "accepts digitalSignature, nonRepudiation alone, or no KeyUsage extension" do
      [leaf(11), leaf(12, key_usage: "nonRepudiation"), leaf(13, key_usage: :none)].each do |cert|
        expect(HankoXml.verify(signed_by(cert), store: store).valid?).to be(true), cert.extensions.map(&:to_s).inspect
      end
    end

    it "rejects a KeyUsage without digitalSignature or nonRepudiation under Policy.strict" do
      result = HankoXml.verify(signed_by(leaf(14, key_usage: "keyEncipherment")), store: store)

      expect(result.valid?).to be false
      expect(result.errors.first).to be_a(HankoXml::UntrustedCertificate)
      expect(result.errors.first.message).to match(/require_signing_key_usage/)
    end

    it "skips the KeyUsage check when require_signing_key_usage is false" do
      policy = HankoXml::Policy.strict.with(require_signing_key_usage: false)
      result = HankoXml.verify(signed_by(leaf(15, key_usage: "keyEncipherment")), store: store, policy: policy)

      expect(result.valid?).to be true
    end

    it "does not apply the KeyUsage check to a pinned certificate:" do
      cert = leaf(16, key_usage: "keyEncipherment")
      expect(HankoXml.verify(signed_by(cert), certificate: cert).valid?).to be true
    end

    describe "certificate_subject:" do
      it "accepts a String equal to the only CN" do
        expect(HankoXml.verify(signed_by(leaf(20)), store: store, certificate_subject: "usage-leaf").valid?)
          .to be true
      end

      it "rejects a different CN, including a prefix or suffix match" do
        %w[usage-lea usage-leaf.evil other].each do |cn|
          result = HankoXml.verify(signed_by(leaf(21)), store: store, certificate_subject: cn)

          expect(result.valid?).to be false
          expect(result.errors.first).to be_a(HankoXml::UntrustedCertificate)
          expect(result.errors.first.message).to match(/certificate_subject/)
        end
      end

      it "rejects a String when the subject has more than one CN" do
        name = OpenSSL::X509::Name.parse("/CN=usage-leaf/CN=attacker")
        result = HankoXml.verify(signed_by(leaf(22, subject: name)), store: store, certificate_subject: "usage-leaf")

        expect(result.valid?).to be false
      end

      it "matches an OpenSSL::X509::Name against the whole subject" do
        name = OpenSSL::X509::Name.parse("/O=Example/CN=usage-leaf")
        cert = leaf(23, subject: name)

        expect(HankoXml.verify(signed_by(cert), store: store, certificate_subject: name).valid?).to be true
        expect(HankoXml.verify(signed_by(cert), store: store,
                                                certificate_subject: OpenSSL::X509::Name.parse("/CN=usage-leaf"))
          .valid?).to be false
      end

      it "is a ConfigurationError without store: or with an unsupported type" do
        expect { described_class.new(certificate: signer_cert_pem, certificate_subject: "x") }
          .to raise_error(HankoXml::ConfigurationError, /only applies to store:/)
        expect { described_class.new(store: store, certificate_subject: /usage/) }
          .to raise_error(HankoXml::ConfigurationError, /String .* or an OpenSSL::X509::Name/)
      end
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
