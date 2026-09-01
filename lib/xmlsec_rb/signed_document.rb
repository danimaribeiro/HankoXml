# frozen_string_literal: true

module XmlsecRb
  # A safe-serialization wrapper around a signed Nokogiri::XML::Document.
  # See API_CONTRACT.md §6.7.
  #
  # A bare Nokogiri document's #to_xml defaults to formatting/reindenting
  # the tree, which invalidates the signature that was just computed. This
  # wrapper intercepts serialization to ensure it is always byte-faithful.
  class SignedDocument
    attr_reader :document

    def initialize(document)
      @document = document
      freeze
    end

    def to_xml(declaration: true)
      options = ::Nokogiri::XML::Node::SaveOptions::AS_XML
      unless declaration
        options |= ::Nokogiri::XML::Node::SaveOptions::NO_DECL
      end
      @document.to_xml(save_with: options)
    end

    def to_s
      to_xml
    end

    def bytes
      to_xml.b
    end

    def write_to(io, declaration: true)
      io.write(to_xml(declaration: declaration))
    end
    
    def signatures
      @document.xpath(".//ds:Signature", ds: NS["ds"])
    end
    
    def valid?(certificate: nil, certificates: nil, store: nil, key: nil, keys: nil)
      XmlsecRb.verify(@document, certificate: certificate, certificates: certificates, store: store, key: key, keys: keys).valid?
    end

    def inspect
      "#<XmlsecRb::SignedDocument signatures=#{signatures.size}>"
    end
  end
end
