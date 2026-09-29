# frozen_string_literal: true

require "nokogiri"
require "open3"
require "pathname"
require "rbconfig"

# The native structural checks that let verification run on bytes, with or
# without Nokogiri (#102).
RSpec.describe "HankoXml::Native structural checks (#102)" do
  let(:fixtures) { Pathname.new(__dir__).join("../fixtures") }
  let(:signed) { fixtures.join("signed.xml").binread }
  let(:ids) { %w[Id ID id] }
  let(:ds) { HankoXml::NS["ds"] }

  describe ".scan" do
    it "counts signatures and reports each one's element index and <SignatureValue> presence" do
      result = HankoXml::Native.scan(signed, ids, true)

      expect(result[:signature_count]).to eq(1)
      expect(result[:signature_values]).to eq([true])
      # <Envelope> is 0 and <Data> is 1, so <Signature> is element 2.
      expect(result[:signature_element_indexes]).to eq([2])
    end

    it "reports an empty <SignatureValue> as absent, whitespace included" do
      xml = %(<r><ds:Signature xmlns:ds="#{ds}"><ds:SignatureValue> \n\t</ds:SignatureValue></ds:Signature></r>)

      expect(HankoXml::Native.scan(xml, ids, true)[:signature_values]).to eq([false])
    end

    it "flags two ID attributes with the same value, across attribute names (S-06)" do
      expect(HankoXml::Native.scan(%(<r><a Id="x"/><b ID="x"/></r>), ids, true)[:duplicate_ids]).to be true
      expect(HankoXml::Native.scan(%(<r><a Id="x"/><b ID="y"/></r>), ids, true)[:duplicate_ids]).to be false
    end

    it "flags a namespaced ID attribute that collides, since xmlSecAddIDs registers it too" do
      xml = %(<r xmlns:p="urn:p"><a Id="x"/><b p:Id="x"/></r>)

      expect(HankoXml::Native.scan(xml, ids, true)[:duplicate_ids]).to be true
    end

    it "lists the IDs that xmlsec's ID table resolves to the root element" do
      xml = %(<r xmlns:p="urn:p" Id="top" p:ID="alt"><c Id="child"/></r>)

      expect(HankoXml::Native.scan(xml, ids, true)[:root_ids]).to contain_exactly("top", "alt")
    end

    it "does not list a root ID another element registered first" do
      xml = %(<r ID="dup"><c/></r>)

      expect(HankoXml::Native.scan(xml, %w[Id], true)[:root_ids]).to be_empty
      expect(HankoXml::Native.scan(xml, ids, true)[:root_ids]).to eq(["dup"])
    end

    it "rejects a recoverable libxml2 error when strict, as a strict Nokogiri parse does" do
      xml = "<a><x:b/></a>"

      expect { HankoXml::Native.scan(xml, ids, true) }.to raise_error(HankoXml::ParseError) { |error|
        expect(error.message).not_to include("x:b")
        expect(error.xmlsec_errors.join).to match(/Namespace prefix x on b is not defined/)
      }
      expect { HankoXml.parse(xml) }.to raise_error(HankoXml::ParseError)
      expect(HankoXml::Native.scan(xml, ids, false)[:signature_count]).to eq(0)
    end

    it "rejects malformed XML either way" do
      expect { HankoXml::Native.scan("<a><b></a>", ids, false) }.to raise_error(HankoXml::ParseError)
    end
  end

  describe ".validate_schema" do
    let(:xsd) { HankoXml::Verifier::DEFAULT_SCHEMA_PATH }

    it "returns no errors for a schema-valid <Signature>" do
      expect(HankoXml::Native.validate_schema(signed, 0, xsd)).to eq([])
    end

    it "returns libxml2's errors for an invalid one" do
      xml = %(<r><ds:Signature xmlns:ds="#{ds}"/></r>)

      expect(HankoXml::Native.validate_schema(xml, 0, xsd).join).to match(/Missing child element.*SignedInfo/)
    end

    it "agrees with the Nokogiri schema on the same <Signature>" do
      xml = %(<r><ds:Signature xmlns:ds="#{ds}"><ds:SignedInfo/></ds:Signature></r>)
      sig = Nokogiri::XML(xml).at_xpath("//ds:Signature", "ds" => ds)

      native = HankoXml::Native.validate_schema(xml, 0, xsd)
      dom = HankoXml::Dom.schema_errors(HankoXml::Verifier.default_schema, sig)
      expect(native.empty?).to eq(dom.empty?)
      expect(native).not_to be_empty
    end

    it "raises NativeError for an out-of-range signature index" do
      expect { HankoXml::Native.validate_schema(signed, 3, xsd) }.to raise_error(HankoXml::NativeError)
    end
  end

  it "keeps libxml2's parse errors off stderr" do
    script = <<~RUBY
      require "hanko_xml"
      begin
        HankoXml::Native.scan("<a><b></a>", [], true)
      rescue HankoXml::ParseError
      end
      begin
        HankoXml::Native.inspect_sig("<a xml:id='1'/>", 0)
      rescue HankoXml::Error
      end
    RUBY
    lib = Pathname.new(__dir__).join("../../lib").expand_path.to_s
    _out, err, status = Open3.capture3(RbConfig.ruby, "-I", lib, "-e", script)

    expect(status).to be_success
    expect(err).to be_empty
  end

  describe "Policy on the native scan" do
    let(:policy) { HankoXml::Policy.strict }
    let(:sig_info) { HankoXml::SignatureInfo.from_native(HankoXml::Native.inspect_sig(signed, 0)) }

    it "rejects duplicate IDs from xml_bytes: alone, without a document" do
      xml = signed.sub("<Data>", %(<Data Id="a"><x p:Id="a" xmlns:p="urn:p"/>))
      errors = policy.violations(sig_info, xml_bytes: xml, id_attributes: ids)

      expect(errors.map(&:message).join).to match(/reject_duplicate_ids/)
    end

    it "still accepts a document: alone, serializing it for the scan" do
      errors = policy.violations(sig_info, document: Nokogiri::XML(signed), id_attributes: ids)

      expect(errors).to be_empty
    end

    it "fails closed with neither xml_bytes: nor document:" do
      messages = policy.violations(sig_info, id_attributes: ids).map(&:message)

      expect(messages.join).to match(/require_signed_root needs the document/)
      expect(messages.join).to match(/reject_duplicate_ids needs the document/)
    end
  end

  describe "Verification without a document" do
    let(:sig_info) { HankoXml::SignatureInfo.from_native(HankoXml::Native.inspect_sig(signed, 0)) }

    def verification(reference_element_indexes:, signature_element_index: 2, valid: true)
      HankoXml::Verification.new(valid: valid, errors: [], signature_info: sig_info, signature_node: nil,
                                 document: nil, reference_element_indexes: reference_element_indexes,
                                 reference_valid: [valid], signature_element_index: signature_element_index)
    end

    it "answers covers_root? from the native element indexes" do
      expect(verification(reference_element_indexes: [0]).covers_root?).to be true
      expect(verification(reference_element_indexes: [1]).covers_root?).to be false
      expect(verification(reference_element_indexes: [0], valid: false).covers_root?).to be false
    end

    it "excludes the root when an enveloped reference's <Signature> is the root itself" do
      expect(verification(reference_element_indexes: [0], signature_element_index: 0).covers_root?).to be false
    end

    it "raises NokogiriRequired for coverage questions about nodes" do
      result = verification(reference_element_indexes: [0])

      expect { result.signed?(Object.new) }.to raise_error(HankoXml::NokogiriRequired, /signed\?/)
      expect { result.signed_nodes }.to raise_error(HankoXml::NokogiriRequired)
      expect { result.at_signed("//x") }.to raise_error(HankoXml::NokogiriRequired)
      expect { result.signed("//x") }.to raise_error(HankoXml::NokogiriRequired)
    end
  end

  it "Verifier refuses resolver: without Nokogiri, rather than skip it" do
    allow(HankoXml::Dom).to receive(:available?).and_return(false)

    expect { HankoXml::Verifier.new(key: fixtures.join("signer.key").read, resolver: ->(_doc, _id) {}) }
      .to raise_error(HankoXml::NokogiriRequired, /resolver/)
  end

  it "HankoXml.signature_present? rejects malformed XML" do
    expect { HankoXml.signature_present?("<a><x:b/></a>") }.to raise_error(HankoXml::ParseError)
  end
end
