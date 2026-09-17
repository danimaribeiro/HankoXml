# frozen_string_literal: true

module HankoXml
  # A safe-serialization wrapper around a signed Nokogiri::XML::Document.
  # See API_CONTRACT.md §6.7.
  #
  # A bare Nokogiri document's #to_xml defaults to formatting/reindenting
  # the tree, which invalidates the signature that was just computed. This
  # wrapper intercepts serialization to ensure it is always byte-faithful.
  #
  # Read-only Nokogiri methods are delegated; mutators raise
  # FrozenSignatureError (S-17). Nodes returned by the readers are still the
  # live tree, so serialization also checks that the document is unchanged
  # since signing and raises FrozenSignatureError if it is not.
  class SignedDocument
    READ_METHODS = %i[at at_css at_xpath css search xpath root encoding errors namespaces
                      children version url].freeze

    MUTATORS = %i[<< add_child add_next_sibling add_previous_sibling after before children= content=
                  inner_html= native_content= parent= remove remove_attribute replace root= set_attribute
                  []= delete encoding= unlink add_namespace add_namespace_definition default_namespace=
                  do_xinclude canonicalize! remove_namespaces! swap wrap].freeze

    # @return [Nokogiri::XML::Document] The underlying Nokogiri document.
    #   Escape hatch: mutating it invalidates the signature, and this
    #   wrapper's serializers then raise FrozenSignatureError. Serialize an
    #   intentionally modified document with HankoXml.serialize(document).
    attr_reader :document

    # Initializes the wrapper with a signed document.
    # @param document [Nokogiri::XML::Document] The signed document.
    def initialize(document)
      @document = document
      @signed_xml = serialize(declaration: true).freeze
      freeze
    end

    READ_METHODS.each do |name|
      define_method(name) { |*args, **kwargs, &block| @document.public_send(name, *args, **kwargs, &block) }
    end

    MUTATORS.each do |name|
      define_method(name) do |*|
        raise HankoXml::FrozenSignatureError,
              "SignedDocument##{name} would invalidate the signature; use #document if you really mean to " \
              "modify it, and HankoXml.serialize to write the result"
      end
    end

    # Safely serializes the document to an XML String without re-formatting.
    #
    # @param declaration [Boolean] Whether to include the `<?xml ...?>` declaration.
    # @return [String] The serialized XML.
    # @raise [HankoXml::FrozenSignatureError] if the document changed since signing.
    def to_xml(declaration: true)
      current = serialize(declaration: true)
      unless current == @signed_xml
        raise HankoXml::FrozenSignatureError,
              "the signed document was modified after signing, so this serialization would not verify; " \
              "use HankoXml.serialize(signed.document) if the change is intentional"
      end

      declaration ? current : serialize(declaration: false)
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
    #   (certificate:, certificates:, store:, key:, keys:, policy:, schema:,
    #   signature:, etc).
    # @return [Boolean] True if the signature is valid.
    def valid?(**kwargs)
      HankoXml.verify(@document, **kwargs).valid?
    end

    def inspect
      "#<HankoXml::SignedDocument signatures=#{signatures.size}>"
    end

    private

    def serialize(declaration:)
      options = ::Nokogiri::XML::Node::SaveOptions::AS_XML
      options |= ::Nokogiri::XML::Node::SaveOptions::NO_DECLARATION unless declaration
      @document.to_xml(save_with: options)
    end
  end
end
