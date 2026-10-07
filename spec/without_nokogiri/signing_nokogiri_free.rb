# frozen_string_literal: true

require_relative "helper"

# Signing an existing <Signature> template on bytes, with Nokogiri hidden
# (#102). The checks #sign! runs with a DOM run here on the same bytes
# (S-05, S-12); what needs a DOM raises NokogiriRequired.
RSpec.describe "Signing without Nokogiri" do
  let(:fixtures) { WithoutNokogiri::FIXTURES }
  let(:key) { fixtures.join("signer.key").read }
  let(:certificate) { fixtures.join("signer.crt").read }
  let(:template) { fixtures.join("template.xml").read }
  let(:signer) { HankoXml::Signer.new(key: key, certificate: certificate) }

  def sign(document = template, **options)
    signer.sign(document, **options)
  end

  describe "an existing template" do
    it "signs a String, a path and an IO into a SignedDocument that verifies" do
      [template, fixtures.join("template.xml"), StringIO.new(template)].each do |source|
        signed = sign(source)

        expect(signed).to be_a(HankoXml::SignedDocument)
        expect(HankoXml.valid?(signed.to_s, certificate: certificate)).to be true
        expect(signed.valid?(certificate: certificate)).to be true
      end
    end

    it "fills <KeyInfo> from the key, as the DOM path does" do
      signed = sign.to_s

      expect(signed).to include("<X509Certificate>")
      expect(signed).not_to include("<X509Data/>")
    end

    it "keeps the caller's input as it was" do
      source = template.dup
      sign(source)
      expect(source).to eq(template)
    end

    it "matches what the DOM-free verifier reads back" do
      result = HankoXml.verify!(sign.to_s, certificate: certificate)

      expect(result.signature_method).to eq(:rsa_sha256)
      expect(result.covers_root?).to be true
    end
  end

  describe "SignedDocument from bytes" do
    let(:signed) { sign }

    it "serializes the signed bytes, with or without the declaration" do
      expect(signed.to_xml).to eq(signed.to_s)
      expect(signed.bytes.encoding).to eq(Encoding::BINARY)
      expect(signed.to_xml(declaration: false)).not_to start_with("<?xml")
      expect(signed.to_xml(declaration: false)).to start_with("<Envelope")

      io = StringIO.new
      signed.write_to(io)
      expect(io.string).to eq(signed.to_s)
    end

    it "is frozen, has no document, and raises NokogiriRequired for DOM readers" do
      expect(signed).to be_frozen
      expect(signed.document).to be_nil
      expect { signed.at_xpath("//x") }.to raise_error(HankoXml::NokogiriRequired, /SignedDocument#at_xpath/)
      expect { signed.signatures }.to raise_error(HankoXml::NokogiriRequired, /SignedDocument#signatures/)
      expect { signed.root = nil }.to raise_error(HankoXml::FrozenSignatureError)
      expect(signed.inspect).to eq("#<HankoXml::SignedDocument signatures=1>")
    end
  end

  describe "selecting the template" do
    let(:two) { template.sub("</Envelope>", "#{template[%r{<Signature .*</Signature>}m]}</Envelope>") }

    it "returns an already-signed document unchanged" do
      signed = sign.to_s
      expect(sign(signed).to_s).to eq(signed)
    end

    it "refuses to re-sign with force:, whose stale <X509Certificate> only the DOM path can clear (#72)" do
      expect { sign(sign.to_s, force: true) }.to raise_error(HankoXml::NokogiriRequired, /already holds/)
    end

    it "signs one template per call, chosen by its document-order index" do
      expect { sign(two) }.to raise_error(HankoXml::NokogiriRequired, /several <Signature> templates.*signature:/)

      first = sign(two, signature: 0).to_s
      both = sign(first, signature: -1).to_s
      verifier = HankoXml::Verifier.new(certificate: certificate, policy: HankoXml::Policy.fragment)
      expect(verifier.verify_all(both).map(&:valid?)).to eq([false, true])
      expect(HankoXml.signature_present?(both)).to be true
    end

    it "refuses an index with no template" do
      expect { sign(signature: 1) }.to raise_error(HankoXml::ConfigurationError, /signature: 1 not found/)
      expect { sign(signature: "//x") }.to raise_error(HankoXml::ConfigurationError, /not found/)
    end

    it "keeps the template modes" do
      required = HankoXml::Signer.new(key: key, certificate: certificate, template: :require)
      built = HankoXml::Signer.new(key: key, certificate: certificate, template: :build)

      expect { required.sign("<doc/>") }.to raise_error(HankoXml::ConfigurationError, /no <Signature> found/)
      expect { built.sign(template) }.to raise_error(HankoXml::ConfigurationError, /already exists/)
      expect { built.sign("<doc/>") }.to raise_error(HankoXml::NokogiriRequired, /Building a <Signature> template/)
      expect { signer.sign!(template) }.to raise_error(HankoXml::NokogiriRequired)
      expect { signer.template(template) }.to raise_error(HankoXml::NokogiriRequired)
    end
  end

  describe "the checks before Native.sign (S-05)" do
    it "enforces the policy on the template" do
      sha1 = template.sub("xmlenc#sha256", "xmldsig#sha1")
      expect { sign(sha1) }.to raise_error(HankoXml::PolicyError, /sha1/i)
    end

    it "refuses template references other than this Signer's" do
      expect { HankoXml::Signer.new(key: key, certificate: certificate, references: ["#other"]).sign(template) }
        .to raise_error(HankoXml::ConfigurationError, /do not match this Signer's references/)
    end

    it "applies max_document_size before reading (S-12)" do
      tight = HankoXml::Signer.new(key: key, certificate: certificate,
                                   policy: HankoXml::Policy.strict.with(max_document_size: 100))
      expect { tight.sign(template) }.to raise_error(HankoXml::PolicyError, /max_document_size/)
    end

    it "rejects malformed XML" do
      expect { sign("#{template}<") }.to raise_error(HankoXml::ParseError)
    end
  end

  describe "a <KeyInfo> that would need DOM edits" do
    it "refuses stale certificate values rather than sign them (#72)" do
      stale = template.sub("<X509Data/>", "<X509Data><X509Certificate>c3RhbGU=</X509Certificate></X509Data>")
      expect { sign(stale) }.to raise_error(HankoXml::NokogiriRequired, /already holds certificate or key values/)
    end

    it "refuses an empty <KeyName>, which the DOM path names (#67)" do
      named = template.sub("<X509Data/>", "<KeyName/><X509Data/>")
      expect { sign(named) }.to raise_error(HankoXml::NokogiriRequired, /empty <KeyName>/)
    end

    it "signs a <KeyName> that already holds a name" do
      named = template.sub("<X509Data/>", "<KeyName>idp-1</KeyName><X509Data/>")
      expect(sign(named).to_s).to include("<KeyName>idp-1</KeyName>")
    end
  end
end
