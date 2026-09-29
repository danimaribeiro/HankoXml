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

      doc, errors = Dom.parse(source)
      raise parse_error(errors) if errors.any?

      doc
    end

    # libxml2's diagnostics can quote the document (tag names, text), so they
    # go in #xmlsec_errors, never in #message (#96, API_CONTRACT.md §5.10).
    def parse_error(errors)
      HankoXml::ParseError.new("the document is not well-formed XML", xmlsec_errors: errors.map(&:message))
    end
    private :parse_error

    # Byte-faithful serialization: AS_XML only, never FORMAT (which
    # reindents the tree and invalidates any signature over it). See
    # API_CONTRACT.md §6.3.
    def serialize(doc)
      Dom.require!("HankoXml.serialize")

      Dom.to_xml(doc)
    end

    # Coerces any of the accepted document input shapes (§6.2) into a
    # Nokogiri::XML::Document: an existing Document as-is, a Node via its
    # #document, a String of markup, a path-like object, or anything
    # responding to #read.
    #
    # +policy+, when given, applies its +max_document_size+ to unparsed
    # input before it is read or parsed (S-12): a String by #bytesize, a
    # path by File.size, an IO by reading at most one byte past the limit.
    # An existing Document/Node is not checked here; Signer/Verifier check
    # its serialized form before any native call.
    def coerce_document(input, policy: nil)
      limit = policy&.max_document_size
      limit = nil unless limit&.finite?

      case input
      when ->(obj) { Dom.document?(obj) }
        input
      when ->(obj) { Dom.node?(obj) }
        input.document
      when String
        policy&.enforce_document_size!(input.bytesize)
        parse(input)
      when ->(obj) { obj.respond_to?(:to_path) }
        policy&.enforce_document_size!(::File.size(input.to_path))
        parse(::File.binread(input.to_path))
      when ->(obj) { obj.respond_to?(:read) }
        source = limit ? input.read(limit + 1) : input.read
        policy&.enforce_document_size!(source.to_s.bytesize)
        parse(source)
      else
        raise ArgumentError,
              "expected a Nokogiri::XML::Document/Node, an XML String, a path-like object " \
              "(Pathname/File), or an IO, got #{input.class}"
      end
    end
  end
end
