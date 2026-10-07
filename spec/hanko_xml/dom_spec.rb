# frozen_string_literal: true

require "nokogiri"
require "openssl"
require "pathname"
require "ripper"

RSpec.describe HankoXml::Dom do
  it "reports Nokogiri as available in this suite" do
    expect(described_class.available?).to be true
  end

  it "#document? / #node? / #certificate? / #pkey? classify Nokogiri/OpenSSL objects" do
    doc = Nokogiri::XML("<a/>")
    expect(described_class.document?(doc)).to be true
    expect(described_class.node?(doc.root)).to be true
    expect(described_class.document?("not a doc")).to be false

    cert = OpenSSL::X509::Certificate.new(File.read(Pathname.new(__dir__).join("..", "fixtures", "signer.crt")))
    expect(described_class.certificate?(cert)).to be true

    key = OpenSSL::PKey::RSA.new(File.read(Pathname.new(__dir__).join("..", "fixtures", "signer.key")))
    expect(described_class.pkey?(key)).to be true
  end

  describe "#require!" do
    it "does not raise when Nokogiri is available" do
      expect { described_class.require!("some capability") }.not_to raise_error
    end
  end

  describe "the Nokogiri seam (#102)" do
    let(:lib_dir) { Pathname.new(__dir__).join("../../lib") }
    let(:ruby_files) { Dir.glob(lib_dir.join("**/*.rb")).sort }

    # Constant tokens only: a comment or an error message may name Nokogiri,
    # code may not.
    def nokogiri_constant_lines(file)
      Ripper.lex(File.read(file, encoding: "UTF-8")).filter_map do |(line, _col), type, token|
        line if type == :on_const && token == "Nokogiri"
      end.uniq
    end

    it "keeps every Nokogiri constant reference in dom.rb" do
      offenders = ruby_files.each_with_object({}) do |file, found|
        next if File.basename(file) == "dom.rb"

        lines = nokogiri_constant_lines(file)
        found[Pathname.new(file).relative_path_from(lib_dir).to_s] = lines if lines.any?
      end

      expect(offenders).to be_empty, "Nokogiri referenced outside HankoXml::Dom: #{offenders.inspect}"
    end

    it "sees the references dom.rb does make, so the scan is not vacuous" do
      expect(nokogiri_constant_lines(lib_dir.join("hanko_xml/dom.rb").to_s)).not_to be_empty
    end

    it "never requires Nokogiri: the caller decides the load order (API_CONTRACT §3.1)" do
      requiring = ruby_files.select do |file|
        File.read(file, encoding: "UTF-8").match?(/^\s*require\s*\(?\s*["']nokogiri["']/)
      end

      expect(requiring).to be_empty
    end
  end

  describe ".parse" do
    it "returns the document and no errors for well-formed XML" do
      doc, errors = described_class.parse("<a><b/></a>")
      expect(doc.root.name).to eq("a")
      expect(errors).to be_empty
    end

    it "returns no document and the syntax error for malformed XML, never recovering" do
      doc, errors = described_class.parse("<a><b></a>")
      expect(doc).to be_nil
      expect(errors).not_to be_empty
    end
  end

  describe ".to_xml" do
    let(:doc) { Nokogiri::XML("<a>\n  <b>x</b>\n</a>") }

    it "serializes byte-faithfully, keeping whitespace, with the declaration by default" do
      xml = described_class.to_xml(doc)
      expect(xml).to start_with("<?xml")
      expect(xml).to include("<a>\n  <b>x</b>\n</a>")
    end

    it "omits the declaration on request" do
      expect(described_class.to_xml(doc, declaration: false)).to start_with("<a>")
    end
  end

  describe ".xpath" do
    let(:doc) { Nokogiri::XML("<a><b/></a>") }

    it "runs the expression" do
      expect(described_class.xpath(doc, "//b", {}).size).to eq(1)
    end

    it "returns the block's result on a syntax error" do
      expect(described_class.xpath(doc, "//unbound:b", {}) { :invalid }).to eq(:invalid)
    end

    it "propagates a syntax error without a block" do
      expect { described_class.xpath(doc, "//unbound:b", {}) }.to raise_error(StandardError)
    end
  end

  describe ".schema_from_file / .schema_errors" do
    let(:schema) { HankoXml::Verifier.default_schema }
    let(:sig_ns) { HankoXml::NS["ds"] }

    it "validates a copy of the node, leaving the original in place" do
      doc = Nokogiri::XML(%(<root><ds:Signature xmlns:ds="#{sig_ns}"/></root>))
      sig = doc.root.first_element_child

      expect(described_class.schema_errors(schema, sig)).not_to be_empty
      expect(sig.parent).to eq(doc.root)
    end

    it "raises NokogiriRequired rather than NameError without Nokogiri" do
      allow(described_class).to receive(:available?).and_return(false)

      expect { described_class.schema_from_file("unused.xsd") }
        .to raise_error(HankoXml::NokogiriRequired, /XML Schema validation/)
    end
  end

  describe ".extend_nodes" do
    it "is a no-op without Nokogiri" do
      allow(described_class).to receive(:available?).and_return(false)

      expect(described_class.extend_nodes(Module.new)).to be false
    end
  end

  describe "#capabilities" do
    it "reports every capability true when Nokogiri is loaded" do
      caps = described_class.capabilities
      expect(caps[:sign]).to be true
      expect(caps[:coverage_checks]).to be true
      expect(caps[:schema]).to be true
    end

    it "reports verify and signing an existing template available without Nokogiri, and every DOM " \
       "capability unavailable (#102)" do
      allow(described_class).to receive(:available?).and_return(false)

      caps = described_class.capabilities
      expect(caps.slice(:verify, :sign_existing_template).values).to all(be true)
      expect(caps.except(:verify, :sign_existing_template).values).to all(be false)
      expect { described_class.require!("HankoXml.parse") }
        .to raise_error(HankoXml::NokogiriRequired, /HankoXml.parse needs a DOM.*require "nokogiri"/)
    end
  end
end
