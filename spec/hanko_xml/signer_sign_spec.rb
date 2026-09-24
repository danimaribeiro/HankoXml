# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "pathname"
require "stringio"
require "tempfile"

# #52 / SIGNING_TEST_COVERAGE.md groups A (end to end), D (template modes
# and multiple signatures), G (placement through the Signer) and H (error
# paths). Every signature produced here is checked by verifying it.
RSpec.describe "HankoXml::Signer signing" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:key_pem) { fixtures.join("signer.key").read }
  let(:cert_pem) { fixtures.join("signer.crt").read }
  let(:xml) { %(<Envelope xmlns="urn:x"><Data Id="a">A</Data><Other Id="b">B</Other></Envelope>) }
  let(:ds) { { "ds" => HankoXml::NS["ds"] } }
  let(:x_ns) { { "x" => "urn:x" } }

  def signer(**options)
    HankoXml::Signer.new(key: key_pem, certificate: cert_pem, **options)
  end

  def verification(signed, **options)
    HankoXml::Verifier.new(certificate: cert_pem, **options).verify(signed.to_s)
  end

  def valid?(signed, **options)
    verification(signed, **options).valid?
  end

  describe "A: end to end" do
    it "A1 signs a String, appending one Signature to the root" do
      signed = signer.sign(xml).to_s
      doc = Nokogiri::XML(signed)

      expect(doc.xpath("//ds:Signature", ds).size).to eq(1)
      expect(doc.root.element_children.last.name).to eq("Signature")
      expect(valid?(signed)).to be true
    end

    it "A2 #sign leaves an input Document untouched" do
      input = Nokogiri::XML(xml)
      before = input.to_xml
      result = signer.sign(input)

      expect(result).to be_a(HankoXml::SignedDocument)
      expect(input.to_xml).to eq(before)
      expect(input.at_xpath("//ds:Signature", ds)).to be_nil
      expect(result.document).not_to equal(input)
      expect(valid?(result)).to be true
    end

    it "A3 #sign! mutates and returns the same Document" do
      doc = Nokogiri::XML(xml)
      expect(signer.sign!(doc)).to equal(doc)
      expect(doc.at_xpath("//ds:SignatureValue", ds).text.strip).not_to be_empty
      expect(valid?(HankoXml.serialize(doc))).to be true
    end

    it "A4 accepts a Pathname, a File and an IO" do
      Tempfile.create(["unsigned", ".xml"]) do |file|
        file.write(xml)
        file.flush

        expect(valid?(signer.sign(Pathname.new(file.path)))).to be true
        File.open(file.path) { |io| expect(valid?(signer.sign(io))).to be true }
      end
      expect(valid?(signer.sign(StringIO.new(xml)))).to be true
    end

    it "A5 survives SignedDocument#to_xml and a re-parse" do
      reparsed = Nokogiri::XML(signer.sign(xml).to_xml)
      expect(valid?(HankoXml.serialize(reparsed))).to be true
    end

    # Why SignedDocument exists: Nokogiri's default formatting re-indents.
    it "A6 does not survive re-indenting with Nokogiri's to_xml" do
      reindented = Nokogiri::XML(signer.sign(xml).document.to_xml(indent: 2)).to_xml(indent: 4)
      expect(valid?(reindented)).to be false
    end

    it "A7 reuses one frozen Signer across threads" do
      shared = signer
      results = Array.new(8) do |i|
        Thread.new { valid?(shared.sign(xml.sub(">A<", ">#{i}<"))) }
      end.map(&:value)

      expect(results).to all(be true)
    end

    it "A8 does not re-sign or add a signature on a second #sign!" do
      doc = Nokogiri::XML(xml)
      signer.sign!(doc)
      bytes = HankoXml.serialize(doc)
      signer.sign!(doc)

      expect(HankoXml.serialize(doc)).to eq(bytes)
      expect(doc.xpath("//ds:Signature", ds).size).to eq(1)
    end

    it "A9 force: true re-signs an already-signed document" do
      doc = Nokogiri::XML(xml)
      signer.sign!(doc)
      old_value = doc.at_xpath("//ds:SignatureValue", ds).text
      doc.at_xpath("//x:Data", x_ns).content = "changed"
      signer.sign!(doc, force: true)

      expect(doc.at_xpath("//ds:SignatureValue", ds).text).not_to eq(old_value)
      expect(valid?(HankoXml.serialize(doc))).to be true
    end

    # Pinned semantics: :adopt only fills unsigned templates, and :build
    # refuses a document that has any <Signature>. Adding a second signature
    # means inserting its template yourself (see D6).
    it "A10 neither adds a second signature under :adopt nor under :build" do
      doc = Nokogiri::XML(xml)
      signer.sign!(doc)

      signer.sign!(doc)
      expect(doc.xpath("//ds:Signature", ds).size).to eq(1)
      expect { signer(template: :build).sign!(doc) }.to raise_error(HankoXml::ConfigurationError, /already exists/)
    end

    it "A12 signs an ISO-8859-1 document and keeps its declaration" do
      declaration = %(<?xml version="1.0" encoding="ISO-8859-1"?>\n)
      latin1 = %(#{declaration}<Envelope xmlns="urn:x"><Data>ol\xE1 a\xE7\xE3o</Data></Envelope>).force_encoding(
        "ISO-8859-1"
      )
      signed = signer.sign(latin1).to_s

      expect(signed).to start_with(%(<?xml version="1.0" encoding="ISO-8859-1"?>))
      expect(valid?(signed)).to be true
    end

    it "A12 signs non-ASCII UTF-8 content" do
      signed = signer.sign(%(<Envelope xmlns="urn:x"><Data>olá ação 日本</Data></Envelope>)).to_s
      expect(Nokogiri::XML(signed).at_xpath("//x:Data", x_ns).text).to eq("olá ação 日本")
      expect(valid?(signed)).to be true
    end

    it "A13 gives the Signature the ds namespace, not the root's default" do
      signature = Nokogiri::XML(signer.sign(xml).to_s).root.element_children.last
      expect(signature.namespace.href).to eq(HankoXml::NS["ds"])
    end

    it "A14 keeps processing instructions, comments and CDATA" do
      source = <<~XML
        <?xml version="1.0"?>
        <?xml-stylesheet href="a.xsl"?>
        <!-- before -->
        <Envelope xmlns="urn:x"><![CDATA[x<y]]><!-- inside --><Data>A</Data></Envelope>
        <!-- after -->
      XML
      signed = signer.sign(source).to_s

      expect(signed).to include(
        "<?xml-stylesheet",
        "<!-- before -->",
        "<!-- inside -->",
        "<!-- after -->",
        "<![CDATA[x<y]]>"
      )
      expect(valid?(signed)).to be true
    end

    it "A15 keeps an internal DTD subset" do
      source = %(<?xml version="1.0"?>\n<!DOCTYPE Envelope [<!ELEMENT Envelope ANY>]>\n) +
        %(<Envelope xmlns="urn:x"><Data>A</Data></Envelope>)
      signed = signer.sign(source).to_s

      expect(signed).to include("<!DOCTYPE Envelope")
      expect(valid?(signed)).to be true
    end

    describe "A16 size and depth" do
      it "signs 250 levels of nesting" do
        deep = %(<Envelope xmlns="urn:x">#{"<n>" * 250}x#{"</n>" * 250}</Envelope>)
        expect(valid?(signer.sign(deep))).to be true
      end

      it "rejects nesting past libxml2's default depth limit as a ParseError" do
        deep = %(<Envelope xmlns="urn:x">#{"<n>" * 5000}x#{"</n>" * 5000}</Envelope>)
        expect { signer.sign(deep) }.to raise_error(HankoXml::ParseError) { |e|
          expect(e.xmlsec_errors.join).to match(/depth/i)
        }
      end

      it "signs a 15 MiB document spread over many elements" do
        chunk = "a" * 10_240
        big = %(<Envelope xmlns="urn:x">#{"<d>#{chunk}</d>" * 1536}</Envelope>)
        expect(big.bytesize).to be > 15 * 1024 * 1024

        expect(valid?(signer.sign(big))).to be true
      end

      # The 10 MB text node limit is libxml2's, and not every version has it
      # on this path: 2.13 rejects the node, 2.9.14 (Ubuntu 24.04) accepts
      # it. What must hold either way is that nothing is silently truncated.
      it "rejects a single text node over libxml2's 10 MB limit as a ParseError, or signs all of it" do
        text = "a" * (11 * 1024 * 1024)
        big = %(<Envelope xmlns="urn:x"><Data>#{text}</Data></Envelope>)

        begin
          signed = signer.sign(big).to_s
        rescue HankoXml::ParseError
          next
        end

        huge = Nokogiri::XML(signed) { |config| config.strict.huge }
        expect(huge.at_xpath("//x:Data", x_ns).text.size).to eq(text.size)
        expect(valid?(signed)).to be true
      end
    end
  end

  describe "D: template modes and multiple signatures" do
    let(:fragment) { HankoXml::Policy.fragment }

    it "D1 template: :build signs an unsigned document" do
      expect(valid?(signer(template: :build).sign(xml))).to be true
    end

    it "D2 template: :build refuses a document that already has a Signature" do
      signed = signer.sign(xml).to_s
      expect { signer(template: :build).sign(signed) }.to raise_error(HankoXml::ConfigurationError, /already exists/)
    end

    it "D3 template: :require refuses a document without a Signature" do
      expect { signer(template: :require).sign(xml) }.to raise_error(
        HankoXml::ConfigurationError,
        /no <Signature> found/
      )
    end

    it "D4 template: :require signs an existing empty template" do
      template = fixtures.join("template_exc_c14n.xml").read
      expect(valid?(signer(template: :require).sign(template))).to be true
    end

    # Two templates with different references need one Signer each, since
    # an adopted template's references must match the Signer's (S-05).
    it "D5 signs two sibling fragment templates with one Signer each, then verify_all" do
      doc = Nokogiri::XML(xml)
      doc.at_xpath("//x:Data", x_ns).add_next_sibling(signer(references: ["#a"]).template(doc))
      doc.root.add_child(signer(references: ["#b"]).template(doc))

      signer(references: ["#a"], policy: fragment).sign!(doc, signature: 0)
      signer(references: ["#b"], policy: fragment).sign!(doc, signature: 1)

      results = HankoXml::Verifier.new(certificate: cert_pem, policy: fragment).verify_all(HankoXml.serialize(doc))
      expect(results.map(&:valid?)).to eq([true, true])
    end

    it "D5 refuses to sign an adopted template whose references differ from the Signer's" do
      doc = Nokogiri::XML(xml)
      doc.root.add_child(signer(references: ["#b"]).template(doc))

      expect { signer(references: ["#a"], policy: fragment).sign!(doc) }.to raise_error(
        HankoXml::ConfigurationError,
        /do not match/
      )
    end

    it "D6 signs an inner signature first, then an outer one that covers it" do
      doc = Nokogiri::XML(xml)
      doc.at_xpath("//x:Data", x_ns).add_child(signer(references: ["#a"]).template(doc))
      doc.root.add_child(signer.template(doc))

      signer(references: ["#a"], policy: fragment).sign!(doc, signature: 0)
      signer(policy: fragment).sign!(doc, signature: 1)
      signed = HankoXml.serialize(doc)

      results = HankoXml::Verifier.new(certificate: cert_pem, policy: fragment).verify_all(signed)
      expect(results.map(&:valid?)).to eq([true, true])
      expect(results.last.covers_root?).to be true
    end
  end

  describe "G: placement through the Signer" do
    it "G1 :append_to_root" do
      signed = signer(placement: :append_to_root).sign(xml).to_s
      expect(Nokogiri::XML(signed).root.element_children.last.name).to eq("Signature")
      expect(valid?(signed)).to be true
    end

    it "G2 :prepend_to_root" do
      signed = signer(placement: :prepend_to_root).sign(xml).to_s
      expect(Nokogiri::XML(signed).root.element_children.first.name).to eq("Signature")
      expect(valid?(signed)).to be true
    end

    it "G3 Placement.after, NF-e shape: sibling Signature over a referenced Id" do
      nfe = %(<NFe xmlns="http://www.portalfiscal.inf.br/nfe"><infNFe Id="NFe1" versao="4.00"><x>1</x></infNFe></NFe>)
      policy = HankoXml::Policy.legacy_sha1.with(require_signed_root: false)
      signed = signer(
        placement: HankoXml::Placement.after("//n:infNFe", namespaces: { "n" => "http://www.portalfiscal.inf.br/nfe" }),
        references: [
          HankoXml::Reference.new(uri: "#NFe1", transforms: %i[enveloped_signature c14n], digest_method: :sha1)
        ],
        signature_method: :rsa_sha1,
        canonicalization_method: :c14n,
        policy: policy
      ).sign(nfe).to_s

      expect(signed).to include("</infNFe><Signature")
      expect(valid?(signed, policy: policy)).to be true
    end

    it "G4 Placement.before" do
      signed = signer(placement: HankoXml::Placement.before("//x:Other", namespaces: x_ns)).sign(xml).to_s
      expect(signed).to include("<Signature").and include("</Signature><Other")
      expect(valid?(signed)).to be true
    end

    it "G5 Placement.append_to and prepend_to a nested element" do
      appended = signer(placement: HankoXml::Placement.append_to("//x:Other", namespaces: x_ns)).sign(xml).to_s
      prepended = signer(placement: HankoXml::Placement.prepend_to("//x:Other", namespaces: x_ns)).sign(xml).to_s

      expect(appended).to include(">B<Signature")
      expect(prepended).to include(%(Id="b"><Signature))
      expect(valid?(appended)).to be true
      expect(valid?(prepended)).to be true
    end

    it "G6 Placement.detached raises instead of signing nothing" do
      detached = signer(placement: :detached, references: ["#a"], policy: HankoXml::Policy.fragment)
      expect { detached.sign(xml) }.to raise_error(HankoXml::ConfigurationError, /detached/)

      doc = Nokogiri::XML(xml)
      doc.root.add_child(detached.template(doc))
      expect(valid?(detached.sign(doc), policy: HankoXml::Policy.fragment)).to be true
    end

    it "G7 Placement.custom" do
      placement = HankoXml::Placement.custom do |doc, signature|
        doc.root.first_element_child.add_next_sibling(signature)
      end
      signed = signer(placement: placement).sign(xml).to_s

      expect(signed).to include("A</Data><Signature")
      expect(valid?(signed)).to be true
    end

    it "G8 raises PlacementError before signing when the XPath matches zero or several nodes" do
      expect(HankoXml::Native).not_to receive(:sign)
      expect { signer(placement: HankoXml::Placement.after("//nope")).sign(xml) }.to raise_error(
        HankoXml::PlacementError,
        /matched no nodes/
      )
      expect { signer(placement: HankoXml::Placement.after("/*/*")).sign(xml) }.to raise_error(
        HankoXml::PlacementError,
        /matched 2 nodes/
      )
    end
  end

  describe "H: error paths" do
    it "H1 malformed XML is a ParseError" do
      expect { signer.sign("<a>") }.to raise_error(HankoXml::ParseError)
    end

    it "H2 an empty document or one without a root is a ParseError" do
      expect { signer.sign("") }.to raise_error(HankoXml::ParseError)
      expect { signer.sign(%(<?xml version="1.0"?>)) }.to raise_error(HankoXml::ParseError)
    end

    it "H3 an xmlsec signing failure is a SigningError carrying the xmlsec log" do
      # A missing reference target gets past policy and fails inside xmlsec.
      expect { signer(references: ["#nope"], policy: HankoXml::Policy.fragment).sign(xml) }.to raise_error(
        HankoXml::SigningError
      ) { |e| expect(e.xmlsec_errors).not_to be_empty }
    end

    it "H4 a non-String id_attributes entry reaching native is a NativeError" do
      expect { HankoXml::Native.sign(xml, key_pem, [cert_pem], [1], 0) }.to raise_error(
        HankoXml::NativeError,
        /not a String/
      )
    end

    it "H5 an unsupported input type is an ArgumentError" do
      expect { signer.sign(42) }.to raise_error(ArgumentError)
    end

    it "H6 signs concurrently with distinct Signers" do
      results = Array.new(8) do |i|
        Thread.new { valid?(signer.sign(xml.sub(">B<", ">#{i}<"))) }
      end.map(&:value)

      expect(results).to all(be true)
    end

    it "N3 never puts key material in an error message" do
      marker = key_pem.lines[1].strip[0, 24]
      failures = [
        -> { signer.sign("<a>") },
        -> { signer(references: ["#nope"], policy: HankoXml::Policy.fragment).sign(xml) },
        -> { HankoXml::Signer.new(key: key_pem.sub("MII", "MIX")) },
        -> { signer(signature_method: :rsa_sha1).sign(xml) }
      ]

      messages = failures.map do |failure|
        failure.call
        nil
      rescue HankoXml::Error => e
        [e.message, *(e.respond_to?(:xmlsec_errors) ? e.xmlsec_errors : [])].join("\n")
      end

      expect(messages.compact.size).to eq(failures.size)
      messages.each do |message|
        expect(message).not_to include("BEGIN")
        expect(message).not_to include(marker)
      end
    end
  end
end
