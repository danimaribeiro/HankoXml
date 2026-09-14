# frozen_string_literal: true

module HankoXml
  # A safe-serialization wrapper around a signed Nokogiri::XML::Document.
  # See API_CONTRACT.md §6.7.
  #
  # A bare Nokogiri document's #to_xml defaults to formatting/reindenting
  # the tree, which invalidates the signature that was just computed. This
  # wrapper intercepts serialization to ensure it is always byte-faithful.
  class SignedDocument
    # @return [Nokogiri::XML::Document] The underlying Nokogiri document.
    attr_reader :document

    # Initializes the wrapper with a signed document.
    # @param document [Nokogiri::XML::Document] The signed document.
    def initialize(document)
      @document = document
      freeze
    end

    # Safely serializes the document to an XML String without re-formatting.
    #
    # @param declaration [Boolean] Whether to include the `<?xml ...?>` declaration.
    # @return [String] The serialized XML.
    def to_xml(declaration: true)
      options = ::Nokogiri::XML::Node::SaveOptions::AS_XML
      options |= ::Nokogiri::XML::Node::SaveOptions::NO_DECL unless declaration
      @document.to_xml(save_with: options)
    end

    # Alias for {#to_xml}.
    # @return [String]
    def to_s
      to_xml
    end

    # Serializes the document to a byte string.
    # @return [String] The serialized XML in binary encoding.
    def bytes
      to_xml.b
    end

    # Writes the safely serialized XML to an IO object.
    #
    # @param io [IO] The stream to write to.
    # @param declaration [Boolean] Whether to include the `<?xml ...?>` declaration.
    def write_to(io, declaration: true)
      io.write(to_xml(declaration: declaration))
    end

    # Returns all `<ds:Signature>` nodes in the document.
    # @return [Nokogiri::XML::NodeSet]
    def signatures
      @document.xpath(".//ds:Signature", ds: NS["ds"])
    end

    # Verifies the signatures against a given trust source.
    #
    # @param kwargs [Hash] Configuration options passed to {Verifier#initialize}
    #   (certificate:, certificates:, store:, key:, keys:, policy:, etc).
    # @return [Boolean] True if the signature is valid.
    def valid?(**kwargs)
      HankoXml.verify(@document, **kwargs).valid?
    end

    def inspect
      "#<HankoXml::SignedDocument signatures=#{signatures.size}>"
    end
  end
end
