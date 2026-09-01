# frozen_string_literal: true

require_relative "xmlsec_rb/version"
require_relative "xmlsec_rb/xmlsec_rb"
require_relative "xmlsec_rb/dom"
require_relative "xmlsec_rb/errors"
require_relative "xmlsec_rb/algorithms"
require_relative "xmlsec_rb/xml"
require_relative "xmlsec_rb/key"
require_relative "xmlsec_rb/transform"
require_relative "xmlsec_rb/reference"
require_relative "xmlsec_rb/key_info"
require_relative "xmlsec_rb/placement"
require_relative "xmlsec_rb/signature_info"
require_relative "xmlsec_rb/policy"
require_relative "xmlsec_rb/template"
require_relative "xmlsec_rb/signer"
require_relative "xmlsec_rb/verification"
require_relative "xmlsec_rb/verifier"
require_relative "xmlsec_rb/signed_document"

# XML digital signature verification backed by libxmlsec1.
module XmlsecRb
  class << self
    # True when Nokogiri is loaded. See §6.1.
    def nokogiri?
      Dom.available?
    end

    # Which capabilities are available given whether Nokogiri is loaded.
    # See §6.1.
    def capabilities
      Dom.capabilities
    end

    # Signs an XML document, returning a safely-serializable +SignedDocument+ wrapper.
    # This is a convenience shortcut that creates a +Signer+ and calls +#sign+.
    # The original document is not modified (a deep clone is created).
    #
    # @param doc_or_xml [String, Nokogiri::XML::Node, Nokogiri::XML::Document, IO] The XML to sign.
    # @param kwargs [Hash] Configuration options passed to {Signer#initialize}.
    # @return [XmlsecRb::SignedDocument] A wrapper around the cloned, signed document.
    def sign(doc_or_xml, **kwargs)
      XmlsecRb::Signer.new(**kwargs).sign(doc_or_xml)
    end

    # Signs a Nokogiri XML document in place.
    # This is a convenience shortcut that creates a +Signer+ and calls +#sign!+.
    #
    # @param doc [Nokogiri::XML::Node, Nokogiri::XML::Document] The document to mutate.
    # @param kwargs [Hash] Configuration options passed to {Signer#initialize}.
    # @return [Nokogiri::XML::Node, Nokogiri::XML::Document] The mutated original document.
    def sign!(doc, **kwargs)
      XmlsecRb::Signer.new(**kwargs).sign!(doc)
    end

    # Verifies an XML signature, returning a comprehensive {Verification} object.
    # This is a convenience shortcut that creates a +Verifier+ and calls +#verify+.
    # Does not raise cryptographic errors; inspect the returned object to determine validity.
    #
    # @param xml [String, Nokogiri::XML::Node, Nokogiri::XML::Document, IO] The signed XML.
    # @param kwargs [Hash] Configuration options passed to {Verifier#initialize}.
    # @return [XmlsecRb::Verification] The result of the verification attempt.
    def verify(xml, **kwargs)
      XmlsecRb::Verifier.new(**kwargs).verify(xml)
    end

    # Verifies an XML signature, raising an exception if invalid.
    # This is a convenience shortcut that creates a +Verifier+ and calls +#verify!+.
    #
    # @param xml [String, Nokogiri::XML::Node, Nokogiri::XML::Document, IO] The signed XML.
    # @param kwargs [Hash] Configuration options passed to {Verifier#initialize}.
    # @raise [XmlsecRb::VerificationError] If the signature is cryptographically invalid or violates policy.
    # @raise [XmlsecRb::Error] If parsing fails or trust sources are misconfigured.
    # @return [XmlsecRb::Verification] The valid verification result.
    def verify!(xml, **kwargs)
      XmlsecRb::Verifier.new(**kwargs).verify!(xml)
    end

    # Checks whether the document contains at least one populated <ds:Signature>.
    # Does NOT verify the signature's cryptographic validity.
    #
    # @param xml [String, Nokogiri::XML::Node, Nokogiri::XML::Document, IO] The XML to check.
    # @return [Boolean] True if a non-empty <ds:SignatureValue> exists, false otherwise.
    def signed?(xml)
      doc = XmlsecRb.coerce_document(xml)
      sigs = doc.xpath(".//ds:Signature", ds: NS["ds"])
      sigs.any? do |sig|
        val = sig.at_xpath("./ds:SignatureValue", ds: NS["ds"])
        val && !val.content.strip.empty?
      end
    end

    # Returns whether zero-copy DOM verification is available on this platform.
    #
    # @return [Boolean] Always false (libxmlsec1 requires serialization).
    def zero_copy_available?
      false
    end

    private

    def xml_bytes(xml)
      if defined?(::Nokogiri::XML::Document) && (xml.is_a?(::Nokogiri::XML::Document) || xml.is_a?(::Nokogiri::XML::Node))
        return XmlsecRb.serialize(xml).b
      end

      case xml
      when String
        xml.b
      when ->(obj) { obj.respond_to?(:to_path) }
        File.binread(xml.to_path)
      else
        raise ArgumentError,
              "expected a Nokogiri::XML::Document, an XML String, or a path-like object " \
              "(Pathname/File), got #{xml.class}"
      end
    end

    def nokogiri_document?(obj)
      defined?(Nokogiri::XML::Document) && obj.is_a?(Nokogiri::XML::Document)
    end

    def openssl_certificate?(obj)
      defined?(OpenSSL::X509::Certificate) && obj.is_a?(OpenSSL::X509::Certificate)
    end

    def cert_pem_bytes(certificate)
      return certificate.to_pem.b if openssl_certificate?(certificate)
      return certificate.b if certificate.is_a?(String)
      return File.binread(certificate.to_path) if certificate.respond_to?(:to_path)

      raise ArgumentError,
            "expected an OpenSSL::X509::Certificate, a PEM String, or a path-like object " \
            "(Pathname/File), got #{certificate.class}"
    end
  end

  ::Xmlsec = XmlsecRb unless defined?(::Xmlsec)
end
