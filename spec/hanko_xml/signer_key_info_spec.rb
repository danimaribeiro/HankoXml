# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require "pathname"
require "tempfile"

# #52 / SIGNING_TEST_COVERAGE.md groups E (write_back_signature fidelity:
# the caller's document must match what xmlsec signed) and F (keys,
# certificates and key inputs). F5-F8, F10 and F12 live in signer_spec.rb;
# F2/F3 in key_spec.rb.
RSpec.describe "HankoXml::Signer KeyInfo and keys" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:key_pem) { fixtures.join("signer.key").read }
  let(:cert_pem) { fixtures.join("signer.crt").read }
  let(:other_cert_pem) { fixtures.join("other.crt").read }
  let(:xml) { %(<Envelope xmlns="urn:x"><Data Id="a">A</Data><Other Id="b">B</Other></Envelope>) }
  let(:ds) { { "ds" => HankoXml::NS["ds"] } }
  let(:dsig11) { ds.merge("dsig11" => "http://www.w3.org/2009/xmldsig11#") }

  def issue(subject, key:, issuer: nil, issuer_key: key, authority: false, not_after: Time.now + 3600)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = rand(1 << 32)
    cert.subject = OpenSSL::X509::Name.parse(subject)
    cert.issuer = issuer ? issuer.subject : cert.subject
    cert.public_key = key.is_a?(OpenSSL::PKey::EC) ? OpenSSL::PKey::EC.new(key.public_to_der) : key.public_key
    cert.not_before = Time.now - 7200
    cert.not_after = not_after
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer || cert
    cert.add_extension(factory.create_extension("basicConstraints", authority ? "CA:TRUE" : "CA:FALSE", true))
    cert.sign(issuer_key, OpenSSL::Digest.new("SHA256"))
    cert
  end

  # Signs in place and returns the caller's document serialized, so every
  # assertion below is about what write-back left in the caller's DOM.
  def sign_in_place(source = xml, **options)
    doc = Nokogiri::XML(source)
    HankoXml::Signer.new(**{ key: key_pem, certificate: cert_pem }.merge(options)).sign!(doc)
    HankoXml.serialize(doc)
  end

  def key_info(signed)
    Nokogiri::XML(signed).at_xpath("//ds:Signature/ds:KeyInfo", ds)
  end

  def pem_body(pem)
    pem.lines.reject { |line| line.start_with?("-----") }.join.gsub(/\s/, "")
  end

  def xmlsec_at_least_1_3?
    Gem::Version.new(HankoXml::NativeVersion.build_versions[:xmlsec]) >= Gem::Version.new("1.3")
  end

  describe "E: write-back fidelity" do
    it "E1/E2 fills every DigestValue and the SignatureValue" do
      signed = sign_in_place(references: ["#a", "#b"], policy: HankoXml::Policy.fragment)
      doc = Nokogiri::XML(signed)

      expect(doc.xpath("//ds:DigestValue", ds).map { |d| d.text.strip }).to all(match(%r{\A[A-Za-z0-9+/=]{40,}\z}))
      expect(doc.at_xpath("//ds:SignatureValue", ds).text.strip).not_to be_empty
      expect(HankoXml.valid?(signed, certificate: cert_pem, policy: HankoXml::Policy.fragment)).to be true
    end

    it "E3 writes the certificate into an adopted empty <X509Data/>" do
      signed = sign_in_place(fixtures.join("template_exc_c14n.xml").read)
      certificates = key_info(signed).xpath("ds:X509Data/ds:X509Certificate", ds)

      expect(certificates.map { |c| c.text.gsub(/\s/, "") }).to eq([pem_body(cert_pem)])
      expect(HankoXml.valid?(signed, certificate: cert_pem)).to be true
    end

    it "E4 replaces a stale certificate in an adopted template (#72)" do
      template = fixtures.join("template_exc_c14n.xml").read
      stale = "<X509Data><X509Certificate>#{pem_body(other_cert_pem)}</X509Certificate></X509Data>"
      template = template.sub("<X509Data/>", stale)
      signed = sign_in_place(template)
      certificates = key_info(signed).xpath("ds:X509Data/ds:X509Certificate", ds)

      expect(certificates.map { |c| c.text.gsub(/\s/, "") }).to eq([pem_body(cert_pem)])
    end

    it "E4 leaves a refused template's certificate alone (#72)" do
      template = fixtures.join("template_exc_c14n.xml").read
      stale = "<X509Data><X509Certificate>#{pem_body(other_cert_pem)}</X509Certificate></X509Data>"
      doc = Nokogiri::XML(template.sub("<X509Data/>", stale))

      expect do
        HankoXml::Signer.new(key: key_pem, certificate: cert_pem, references: ["#nope"]).sign!(doc)
      end.to raise_error(HankoXml::ConfigurationError)
      expect(key_info(doc.to_xml).at_xpath("ds:X509Data/ds:X509Certificate", ds).text).to eq(pem_body(other_cert_pem))
    end

    it "E5 writes the whole certificates: chain" do
      root_key = OpenSSL::PKey::RSA.new(2048)
      root = issue("/CN=root", key: root_key, authority: true)
      intermediate_key = OpenSSL::PKey::RSA.new(2048)
      intermediate = issue(
        "/CN=intermediate",
        key: intermediate_key,
        issuer: root,
        issuer_key: root_key,
        authority: true
      )
      leaf_key = OpenSSL::PKey::RSA.new(2048)
      leaf = issue("/CN=leaf", key: leaf_key, issuer: intermediate, issuer_key: intermediate_key)

      signed = sign_in_place(key: leaf_key.to_pem, certificate: leaf.to_pem, certificates: [intermediate.to_pem])
      written = key_info(signed).xpath("ds:X509Data/ds:X509Certificate", ds).map { |c| c.text.gsub(/\s/, "") }

      expect(written).to contain_exactly(pem_body(leaf.to_pem), pem_body(intermediate.to_pem))
      store = OpenSSL::X509::Store.new
      store.add_cert(root)
      expect(HankoXml.valid?(signed, store: store)).to be true
    end

    it "E6 writes an RSA <KeyValue>" do
      signed = sign_in_place(certificate: nil, key_info: [:key_value])
      rsa = key_info(signed).at_xpath("ds:KeyValue/ds:RSAKeyValue", ds)
      public_key = OpenSSL::PKey.read(key_pem)

      expect(rsa).not_to be_nil
      expect(rsa.at_xpath("ds:Modulus", ds).text.gsub(/\s/, "").unpack1("m").unpack1("H*").to_i(16)).to eq(
        public_key.n.to_i
      )
      expect(HankoXml.valid?(signed, key: public_key.public_to_pem)).to be true
    end

    it "E6 writes an EC <KeyValue>" do
      unless xmlsec_at_least_1_3?
        skip "xmlsec #{HankoXml::NativeVersion.build_versions[:xmlsec]} cannot write ECKeyValue"
      end

      ec = OpenSSL::PKey::EC.generate("prime256v1")
      signed = sign_in_place(key: ec.to_pem, certificate: nil, key_info: [:key_value], signature_method: :ecdsa_sha256)

      expect(key_info(signed).at_xpath("ds:KeyValue/dsig11:ECKeyValue", dsig11)).not_to be_nil
      expect(HankoXml.valid?(signed, key: ec.public_to_pem)).to be true
    end

    it "E6 writes both X509Data and KeyValue when asked for both" do
      signed = sign_in_place(key_info: %i[x509_certificate key_value])

      expect(key_info(signed).element_children.map(&:name)).to eq(%w[X509Data KeyValue])
      expect(key_info(signed).at_xpath("ds:KeyValue/ds:RSAKeyValue", ds)).not_to be_nil
      expect(HankoXml.valid?(signed, certificate: cert_pem)).to be true
    end

    it "E7 writes the key name into <KeyName> (#67)" do
      signed = sign_in_place(key_info: [{ key_name: "idp-1" }, :x509_certificate])
      expect(key_info(signed).at_xpath("ds:KeyName", ds).text).to eq("idp-1")
      expect(HankoXml.valid?(signed, keys: { "idp-1" => cert_pem })).to be true
    end

    it "E7 takes the key name in the block form (#67)" do
      signer = HankoXml::Signer.new(key: key_pem, certificate: cert_pem) { |s| s.key_info :key_name, name: "idp-1" }
      expect(key_info(signer.sign(xml).to_s).at_xpath("ds:KeyName", ds).text).to eq("idp-1")
    end

    it "E7 names an empty <KeyName/> in an adopted template (#67)" do
      template = HankoXml::Signer.new(key: key_pem, key_info: [:key_name]).template(xml)
      doc = Nokogiri::XML(xml)
      doc.root.add_child(template)
      signed = sign_in_place(doc.to_xml, key_info: [{ key_name: "idp-1" }])

      expect(key_info(signed).at_xpath("ds:KeyName", ds).text).to eq("idp-1")
    end

    it "E7 refuses to sign an empty <KeyName/> (#67)" do
      expect(HankoXml::Native).not_to receive(:sign)
      expect { sign_in_place(key_info: [:key_name]) }.to raise_error(HankoXml::ConfigurationError, /KeyName/)
    end

    it "E7 keeps a <KeyName> the adopted template already names" do
      template = HankoXml::Signer.new(key: key_pem, key_info: [{ key_name: "from-template" }]).template(xml)
      doc = Nokogiri::XML(xml)
      doc.root.add_child(template)

      expect(key_info(sign_in_place(doc.to_xml)).at_xpath("ds:KeyName", ds).text).to eq("from-template")
    end

    describe "E8 X509Data clauses" do
      let(:certificate) { OpenSSL::X509::Certificate.new(cert_pem) }

      it "writes X509SubjectName" do
        signed = sign_in_place(key_info: [:x509_subject_name])
        data = key_info(signed).at_xpath("ds:X509Data", ds)

        expect(data.element_children.map(&:name)).to eq(%w[X509SubjectName])
        expect(data.at_xpath("ds:X509SubjectName", ds).text).to include(certificate.subject.to_a.first[1])
      end

      it "writes X509IssuerSerial" do
        signed = sign_in_place(key_info: [:x509_issuer_serial])
        serial = key_info(signed).at_xpath("ds:X509Data/ds:X509IssuerSerial/ds:X509SerialNumber", ds)

        expect(serial.text.strip).to eq(certificate.serial.to_s)
      end

      it "writes X509SKI" do
        signed = sign_in_place(key_info: [:x509_ski])
        ski = key_info(signed).at_xpath("ds:X509Data/ds:X509SKI", ds)
        extension = certificate.extensions.find { |e| e.oid == "subjectKeyIdentifier" }

        expect(ski.text.gsub(/\s/, "").unpack1("m").unpack1("H*")).to eq(extension.value.delete(":").downcase)
      end

      it "writes every clause into one X509Data, and still verifies" do
        signed = sign_in_place(key_info: %i[x509_certificate x509_subject_name x509_issuer_serial x509_ski])

        expect(key_info(signed).xpath("ds:X509Data/*", ds).map(&:name)).to eq(
          %w[X509Certificate X509SubjectName X509IssuerSerial X509SKI]
        )
        expect(HankoXml.valid?(signed, certificate: cert_pem)).to be true
      end
    end

    it "E10 keeps signature_id: on the Signature" do
      signed = sign_in_place(signature_id: "sig-1")
      expect(Nokogiri::XML(signed).at_xpath("//ds:Signature", ds)["Id"]).to eq("sig-1")
      expect(HankoXml.valid?(signed, certificate: cert_pem)).to be true
    end
  end

  describe "F: keys and certificates" do
    it "F1 signs identically from an OpenSSL key, a PEM String, a Pathname and a Key" do
      inputs = [OpenSSL::PKey.read(key_pem), key_pem, fixtures.join("signer.key"), HankoXml::Key.from_pem(key_pem)]
      values = inputs.map do |input|
        signed = HankoXml::Signer.new(key: input, certificate: cert_pem).sign(xml).to_s
        Nokogiri::XML(signed).at_xpath("//ds:SignatureValue", ds).text
      end

      expect(values.uniq.size).to eq(1)
    end

    it "F4 signs with a PKCS#12 bundle and writes its chain" do
      ca_key = OpenSSL::PKey::RSA.new(2048)
      ca = issue("/CN=p12 ca", key: ca_key, authority: true)
      leaf_key = OpenSSL::PKey::RSA.new(2048)
      leaf = issue("/CN=p12 leaf", key: leaf_key, issuer: ca, issuer_key: ca_key)

      Tempfile.create(["bundle", ".p12"]) do |file|
        file.binmode
        file.write(OpenSSL::PKCS12.create("secret", "leaf", leaf_key, leaf, [ca]).to_der)
        file.flush

        bundle = HankoXml::Key.from_pkcs12(Pathname.new(file.path), password: "secret")
        signed = HankoXml::Signer.new(**bundle.to_h).sign(xml).to_s
        written = key_info(signed).xpath("ds:X509Data/ds:X509Certificate", ds).map { |c| c.text.gsub(/\s/, "") }

        expect(written.uniq).to contain_exactly(pem_body(leaf.to_pem), pem_body(ca.to_pem))
        expect(HankoXml.valid?(signed, certificate: leaf.to_pem)).to be true
      end
    end

    it "F9 raises a clear error for an Ed25519 key (#69)" do
      ed25519 = OpenSSL::PKey.generate_key("ED25519")
      [ed25519, ed25519.private_to_pem].each do |key|
        expect { HankoXml::Signer.new(key: key) }.to raise_error(HankoXml::ConfigurationError, /unsupported ED25519/)
      end
    end

    # Signing does not validate the chain; verification with store: does.
    it "F11 signs with an expired intermediate in certificates:" do
      root_key = OpenSSL::PKey::RSA.new(2048)
      root = issue("/CN=root", key: root_key, authority: true)
      intermediate_key = OpenSSL::PKey::RSA.new(2048)
      expired = issue(
        "/CN=intermediate",
        key: intermediate_key,
        issuer: root,
        issuer_key: root_key,
        authority: true,
        not_after: Time.now - 60
      )
      leaf_key = OpenSSL::PKey::RSA.new(2048)
      leaf = issue("/CN=leaf", key: leaf_key, issuer: expired, issuer_key: intermediate_key)

      signed = sign_in_place(key: leaf_key.to_pem, certificate: leaf.to_pem, certificates: [expired.to_pem])
      store = OpenSSL::X509::Store.new
      store.add_cert(root)

      expect(HankoXml.valid?(signed, certificate: leaf.to_pem)).to be true
      expect(HankoXml.valid?(signed, store: store)).to be false
    end
  end
end
