# frozen_string_literal: true

# XML digital signature verification backed by libxmlsec1.
module HankoXml
  # XML-DSig namespace prefixes used in every XPath this library runs
  # internally -- never //Signature, never local-name(). See
  # API_CONTRACT.md §6.8.
  NS = {
    "ds" => "http://www.w3.org/2000/09/xmldsig#",
    "ds11" => "http://www.w3.org/2009/xmldsig11#",
    "ec" => "http://www.w3.org/2001/10/xml-exc-c14n#"
  }.freeze

  class << self
    # Parses +source+ (a String, IO, or path-like object) the one way that
    # does not break XML-DSig: strict (no RECOVER), nonet, never NOBLANKS,
    # never NOENT, never HUGE. See API_CONTRACT.md §6.3.
    #
    # Raises HankoXml::NokogiriRequired without Nokogiri, HankoXml::ParseError
    # on malformed input.
    def parse(source)
      Dom.require!("HankoXml.parse")

      begin
        doc = ::Nokogiri::XML(source) { |config| config.strict.nonet }
      rescue ::Nokogiri::XML::SyntaxError => e
        raise HankoXml::ParseError, e.message
      end

      raise HankoXml::ParseError, doc.errors.map(&:message).join("; ") if doc.errors.any?

      doc
    end

    # Byte-faithful serialization: AS_XML only, never FORMAT (which
    # reindents the tree and invalidates any signature over it). See
    # API_CONTRACT.md §6.3.
    def serialize(doc)
      Dom.require!("HankoXml.serialize")

      doc.to_xml(save_with: ::Nokogiri::XML::Node::SaveOptions::AS_XML)
    end

    # Coerces any of the accepted document input shapes (§6.2) into a
    # Nokogiri::XML::Document: an existing Document as-is, a Node via its
    # #document, a String of markup, a path-like object, or anything
    # responding to #read.
    def coerce_document(input)
      case input
      when ->(obj) { Dom.document?(obj) }
        input
      when ->(obj) { Dom.node?(obj) }
        input.document
      when String
        parse(input)
      when ->(obj) { obj.respond_to?(:to_path) }
        parse(::File.binread(input.to_path))
      when ->(obj) { obj.respond_to?(:read) }
        parse(input.read)
      else
        raise ArgumentError,
              "expected a Nokogiri::XML::Document/Node, an XML String, a path-like object " \
              "(Pathname/File), or an IO, got #{input.class}"
      end
    end
  end
end
