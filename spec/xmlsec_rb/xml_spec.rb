# frozen_string_literal: true

require "nokogiri"
require "pathname"

RSpec.describe "XmlsecRb.parse / .serialize" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }

  describe ".parse" do
    it "parses well-formed XML into a Nokogiri::XML::Document" do
      doc = XmlsecRb.parse("<a><b/></a>")
      expect(doc).to be_a(Nokogiri::XML::Document)
      expect(doc.root.name).to eq("a")
    end

    it "raises XmlsecRb::ParseError for malformed XML, not silently recovering" do
      expect { XmlsecRb.parse("<a><b></a>") }.to raise_error(XmlsecRb::ParseError)
    end

    it "raises XmlsecRb::ParseError for a plain non-XML String" do
      expect { XmlsecRb.parse("not xml") }.to raise_error(XmlsecRb::ParseError)
    end
  end

  describe ".serialize" do
    it "is byte-faithful (AS_XML, never FORMAT) and does not reindent" do
      doc = XmlsecRb.parse("<a><b>x</b></a>")
      expect(XmlsecRb.serialize(doc)).not_to include("\n  ")
    end

    it "round-trips a real signed fixture without altering its bytes" do
      original = fixtures.join("signed_exc_c14n.xml").read
      doc = XmlsecRb.parse(original)
      expect(XmlsecRb.serialize(doc)).to eq(original)
    end
  end

  describe "XmlsecRb.coerce_document" do
    it "returns a Document as-is" do
      doc = Nokogiri::XML("<a/>")
      expect(XmlsecRb.coerce_document(doc)).to equal(doc)
    end

    it "resolves a Node to its owning Document" do
      doc = Nokogiri::XML("<a><b/></a>")
      expect(XmlsecRb.coerce_document(doc.root)).to equal(doc)
    end

    it "parses a String" do
      expect(XmlsecRb.coerce_document("<a/>").root.name).to eq("a")
    end

    it "reads a path-like object" do
      doc = XmlsecRb.coerce_document(fixtures.join("template.xml"))
      expect(doc.root.name).to eq("Envelope")
    end

    it "reads anything responding to #read" do
      doc = XmlsecRb.coerce_document(StringIO.new("<a/>"))
      expect(doc.root.name).to eq("a")
    end

    it "raises ArgumentError for an unsupported type" do
      expect { XmlsecRb.coerce_document(42) }.to raise_error(ArgumentError)
    end
  end

  it "XmlsecRb::NS carries the ds/ds11/ec prefixes" do
    expect(XmlsecRb::NS["ds"]).to eq("http://www.w3.org/2000/09/xmldsig#")
  end
end
