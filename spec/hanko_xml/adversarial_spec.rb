# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require "pathname"
require "socket"
require "tmpdir"

# #14: hostile-input regression coverage -- tampering, signature wrapping
# (XSW), key substitution, XXE, entity expansion and weak keys. Every case
# here must fail closed; none may leak data or run unbounded.
RSpec.describe "Adversarial input" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:signer_key_pem) { fixtures.join("signer.key").read }
  let(:signer_cert_pem) { fixtures.join("signer.crt").read }
  let(:unsigned_xml) { %(<Envelope xmlns="urn:hanko_xml:example"><Data Id="a">A</Data></Envelope>) }
  let(:signed_xml) { HankoXml.sign(unsigned_xml, key: signer_key_pem, certificate: signer_cert_pem).to_s }
  let(:ds) { { "ds" => HankoXml::NS["ds"] } }

  def verify(xml, **options)
    HankoXml::Verifier.new(certificate: signer_cert_pem, **options).verify(xml)
  end

  def self_signed(key, subject: "/CN=adversary")
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 2
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse(subject)
    cert.public_key = key.is_a?(OpenSSL::PKey::EC) ? OpenSSL::PKey::EC.new(key.public_to_der) : key.public_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 3600
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert
  end

  # Replaces one base64 character with a different one, so the value stays
  # schema-valid and only the cryptographic check can catch it.
  def flip_base64(value)
    value = value.gsub(/\s/, "")
    value[0] = value[0] == "A" ? "B" : "A"
    value
  end

  describe "tampering" do
    it "rejects a modified DigestValue" do
      doc = Nokogiri::XML(signed_xml)
      digest = doc.at_xpath("//ds:DigestValue", ds)
      digest.content = flip_base64(digest.content)

      result = verify(doc.to_xml)
      expect(result.valid?).to be false
      expect(result.errors).to all(be_a(HankoXml::VerificationError))
    end

    it "rejects a modified SignatureValue" do
      doc = Nokogiri::XML(signed_xml)
      value = doc.at_xpath("//ds:SignatureValue", ds)
      value.content = flip_base64(value.content)

      expect(verify(doc.to_xml).valid?).to be false
    end

    it "rejects modified signed content" do
      expect(verify(signed_xml.sub(">A</Data>", ">B</Data>")).valid?).to be false
    end

    it "rejects a document whose Signature was stripped" do
      result = verify(unsigned_xml)
      expect(result.valid?).to be false
      expect(result.errors.map(&:class)).to include(HankoXml::SignatureMissing)
    end
  end

  describe "signature wrapping (XSW)" do
    let(:fragment_signed_xml) do
      HankoXml::Signer.new(
        key: signer_key_pem,
        certificate: signer_cert_pem,
        references: [HankoXml::Reference.new(uri: "#a", transforms: [])],
        policy: HankoXml::Policy.fragment
      ).sign(unsigned_xml).to_s
    end

    # Moves the signed <Data Id="a"> into a <Wrapper> and puts attacker
    # content where the application expects it.
    def wrap(xml, evil_id:)
      signed_data = %(<Data Id="a">A</Data>)
      raise "fixture changed" unless xml.include?(signed_data)

      xml.sub(signed_data, %(<Wrapper>#{signed_data}</Wrapper><Data Id="#{evil_id}">EVIL</Data>))
    end

    it "rejects a fragment signature under Policy.strict (require_signed_root)" do
      result = verify(fragment_signed_xml)
      expect(result.valid?).to be false
      expect(result.errors.map(&:message).join).to include("require_signed_root")
    end

    it "rejects a wrapped duplicate ID on the verify path (reject_duplicate_ids)" do
      result = verify(wrap(fragment_signed_xml, evil_id: "a"), policy: HankoXml::Policy.fragment)
      expect(result.valid?).to be false
      expect(result.errors).to all(be_a(HankoXml::PolicyError))
      expect(result.errors.map(&:message).join).to include("reject_duplicate_ids")
    end

    # With the scan off, xmlsec resolves #a to the first (wrapped, genuine)
    # element and the signature is valid; signed? must still tell the two
    # same-Id elements apart.
    it "does not report the duplicate-ID attacker node as signed with reject_duplicate_ids off" do
      policy = HankoXml::Policy.fragment.with(reject_duplicate_ids: false)
      result = verify(wrap(fragment_signed_xml, evil_id: "a"), policy: policy)
      expect(result.valid?).to be true

      genuine, evil = result.document.xpath("//*[@Id='a']").to_a
      expect(evil.text).to eq("EVIL")
      expect(result.signed?(genuine)).to be true
      expect(result.signed?(evil)).to be false
    end

    it "does not report moved-away attacker content as signed" do
      result = verify(wrap(fragment_signed_xml, evil_id: "b"), policy: HankoXml::Policy.fragment)
      expect(result.valid?).to be true

      evil = result.document.at_xpath("//*[@Id='b']")
      expect(result.signed?(evil)).to be false
      expect { result.at_signed("/*/*[local-name()='Data']") }.to raise_error(HankoXml::NotSignedError)
      expect(result.at_signed("//*[@Id='a']").text).to eq("A")
    end

    it "refuses to pick one of several signatures by default" do
      doc = Nokogiri::XML(signed_xml)
      doc.root.add_child(doc.at_xpath("//ds:Signature", ds).dup)

      expect { verify(doc.to_xml) }.to raise_error(HankoXml::MultipleSignatures)
    end
  end

  describe "key substitution" do
    let(:attacker_key) { OpenSSL::PKey::RSA.new(2048) }

    it "ignores an attacker certificate in KeyInfo, even one reusing the trusted subject" do
      subject = OpenSSL::X509::Certificate.new(signer_cert_pem).subject.to_s
      forged = HankoXml.sign(
        unsigned_xml.sub(">A<", ">EVIL<"),
        key: attacker_key.to_pem,
        certificate: self_signed(attacker_key, subject: subject).to_pem
      ).to_s

      expect(verify(forged).valid?).to be false
    end

    context "with an HMAC SignatureMethod keyed on the public certificate" do
      let(:hmac_forged_xml) do
        doc = Nokogiri::XML(signed_xml.sub(
                              "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                              "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"
                            ))
        signed_info = doc.at_xpath("//ds:SignedInfo", ds).canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)
        public_der = OpenSSL::X509::Certificate.new(signer_cert_pem).to_der
        doc.at_xpath("//ds:SignatureValue", ds).content =
          [OpenSSL::HMAC.digest("SHA256", public_der, signed_info)].pack("m0")
        doc.to_xml
      end

      it "rejects it as a policy violation under Policy.strict" do
        result = verify(hmac_forged_xml)
        expect(result.valid?).to be false
        expect(result.errors).to all(be_a(HankoXml::PolicyError))
      end

      it "still rejects it under Policy.permissive, because trust stays pinned" do
        expect(verify(hmac_forged_xml, policy: HankoXml::Policy.permissive).valid?).to be false
      end

      # #92: allow_hmac: true with certificate trust is a legal configuration
      # (Policy.permissive is exactly that), so nothing raises at Verifier.new.
      # The defence is xmlsec's: the pinned signKey (S-01) is an RSA key, and
      # xmlsec will not use it for an HMAC SignatureMethod, whatever public
      # bytes the attacker keyed the HMAC on.
      it "is rejected for every public value an attacker could key the HMAC on, under either trust source" do
        cert = OpenSSL::X509::Certificate.new(signer_cert_pem)
        secrets = [cert.to_der, signer_cert_pem, cert.public_key.to_der, cert.public_key.to_pem]
        trusts = [{ certificate: signer_cert_pem }, { key: cert.public_key.to_pem }]

        secrets.product(trusts).each do |secret, trust|
          doc = Nokogiri::XML(hmac_forged_xml)
          signed_info = doc.at_xpath("//ds:SignedInfo", ds).canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)
          doc.at_xpath("//ds:SignatureValue", ds).content =
            [OpenSSL::HMAC.digest("SHA256", secret, signed_info)].pack("m0")

          verifier = HankoXml::Verifier.new(policy: HankoXml::Policy.permissive, **trust)
          expect(verifier.verify(doc.to_xml).valid?).to be false
        end
      end
    end
  end

  describe "external entities (XXE)" do
    around do |example|
      Dir.mktmpdir do |dir|
        @secret_path = File.join(dir, "secret.txt")
        File.write(@secret_path, "TOPSECRET")
        example.run
      end
    end

    let(:xxe_xml) do
      <<~XML
        <?xml version="1.0"?>
        <!DOCTYPE Envelope [<!ENTITY x SYSTEM "file://#{@secret_path}">]>
        <Envelope xmlns="urn:hanko_xml:example"><Data Id="a">&x;</Data></Envelope>
      XML
    end

    it "does not expand a SYSTEM entity when parsing" do
      expect(HankoXml.parse(xxe_xml).to_xml).not_to include("TOPSECRET")
    end

    it "does not sign the entity's target file" do
      signed = begin
        HankoXml.sign(xxe_xml, key: signer_key_pem, certificate: signer_cert_pem).to_s
      rescue HankoXml::Error
        ""
      end
      expect(signed).not_to include("TOPSECRET")
    end

    it "does not validate a signed document that gained an external entity" do
      body = signed_xml.sub(/\A<\?xml[^>]*\?>\s*/, "").sub(">A</Data>", ">&x;</Data>")
      hostile = %(<?xml version="1.0"?>\n<!DOCTYPE Envelope [<!ENTITY x SYSTEM "file://#{@secret_path}">]>\n#{body})

      result = verify(hostile)
      expect(result.valid?).to be false
      expect(result.errors.map(&:message).join).not_to include("TOPSECRET")
    end

    it "does not fetch an external parameter entity over the network" do
      server = TCPServer.new("127.0.0.1", 0)
      xml = <<~XML
        <?xml version="1.0"?>
        <!DOCTYPE Envelope [<!ENTITY % p SYSTEM "http://127.0.0.1:#{server.addr[1]}/evil.dtd"> %p;]>
        <Envelope xmlns="urn:hanko_xml:example"><Data Id="a">A</Data></Envelope>
      XML

      begin
        HankoXml::Verifier.new(certificate: signer_cert_pem).verify(xml)
      rescue HankoXml::Error
        nil
      end

      connection = begin
        server.accept_nonblock
      rescue IO::WaitReadable
        nil
      end
      expect(connection).to be_nil
    ensure
      connection&.close
      server&.close
    end
  end

  describe "entity expansion (billion laughs)" do
    let(:bomb_xml) do
      entities = [%(<!ENTITY a "#{"a" * 10}">)]
      ("b".."i").each_with_index do |name, i|
        previous = ("a".ord + i).chr
        entities << %(<!ENTITY #{name} "#{"&#{previous};" * 10}">)
      end
      <<~XML
        <?xml version="1.0"?>
        <!DOCTYPE Envelope [#{entities.join}]>
        <Envelope xmlns="urn:hanko_xml:example"><Data Id="a">&i;</Data></Envelope>
      XML
    end

    it "rejects it when parsing, without expanding it" do
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      expect { HankoXml.parse(bomb_xml) }.to raise_error(HankoXml::ParseError) { |e| expect(e.xmlsec_errors.join).to match(/amplification/) }
      expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 5
    end

    it "rejects it when signing" do
      expect do
        HankoXml.sign(bomb_xml, key: signer_key_pem, certificate: signer_cert_pem)
      end.to raise_error(HankoXml::ParseError)
    end

    it "rejects it when verifying" do
      expect { verify(bomb_xml) }.to raise_error(HankoXml::ParseError)
    end
  end

  describe "weak keys under Policy.strict" do
    it "rejects verifying a signature made with a 512-bit RSA key" do
      key = OpenSSL::PKey::RSA.new(512)
      cert = self_signed(key)
      relaxed = HankoXml::Policy.strict.with(min_rsa_key_bits: 0)
      signed = HankoXml.sign(unsigned_xml, key: key.to_pem, certificate: cert.to_pem, policy: relaxed).to_s

      expect(HankoXml.valid?(signed, certificate: cert.to_pem, policy: relaxed)).to be true

      result = HankoXml::Verifier.new(certificate: cert.to_pem).verify(signed)
      expect(result.valid?).to be false
      expect(result.errors.map(&:message).join).to include("min_rsa_key_bits")
    end

    it "rejects signing with a 512-bit RSA key" do
      key = OpenSSL::PKey::RSA.new(512)
      expect do
        HankoXml.sign(unsigned_xml, key: key.to_pem, certificate: self_signed(key).to_pem)
      end.to raise_error(HankoXml::PolicyError, /min_rsa_key_bits/)
    end

    # The vendored xmlsec cannot sign on sub-256-bit curves, so these check
    # the policy directly rather than through a full round trip.
    it "rejects signing with a 224-bit EC key before reaching xmlsec" do
      key = OpenSSL::PKey::EC.generate("secp224r1")
      expect do
        HankoXml.sign(unsigned_xml, key: key.to_pem, certificate: self_signed(key).to_pem)
      end.to raise_error(HankoXml::PolicyError, /min_ec_key_bits/)
    end

    it "rejects a 224-bit EC trust certificate" do
      cert = self_signed(OpenSSL::PKey::EC.generate("secp224r1"))
      expect { HankoXml::Policy.strict.enforce_key_size!([cert]) }
        .to raise_error(HankoXml::PolicyError, /ec key is 224 bits/)
      expect { HankoXml::Policy.strict.enforce_key_size!([self_signed(OpenSSL::PKey::EC.generate("prime256v1"))]) }
        .not_to raise_error
    end
  end
end
