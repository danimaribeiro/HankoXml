# frozen_string_literal: true

require_relative "xmlsec_rb/version"
require_relative "xmlsec_rb/xmlsec_rb"

# XML digital signature verification backed by libxmlsec1.
module XmlsecRb
  class Error < StandardError; end

  class << self
    # Verifies the XML-DSig <Signature> in +xml+ against +certificate+, a
    # trusted certificate. Returns true only when libxmlsec1 confirms the
    # signature is cryptographically valid and chains to that certificate;
    # false for a well-formed but invalid/untrusted signature. Raises
    # XmlsecRb::Error when verification can't run at all (unparseable XML,
    # no <Signature> element, unreadable certificate).
    #
    # +xml+ accepts:
    #   - a Nokogiri::XML::Document (serialized via #to_xml)
    #   - a String of XML markup
    #   - a Pathname, File, or anything responding to #to_path (read from disk)
    #
    # +certificate+ accepts:
    #   - an OpenSSL::X509::Certificate (converted via #to_pem)
    #   - a String of PEM-encoded certificate data
    #   - a Pathname, File, or anything responding to #to_path (read from disk)
    def validate(xml, certificate)
      cert = cert_pem_bytes(certificate)

      # A Nokogiri::XML::Document is handed to the native layer by pointer
      # (#pointer_id), not by re-serializing + re-parsing: the caller may
      # have just built this document in memory (e.g. about to sign it), and
      # a to_xml round trip would be wasted work at best and risk subtly
      # reformatting it at worst.
      if nokogiri_document?(xml)
        Native.validate_doc_pointer(xml.pointer_id, cert)
      else
        Native.validate_bytes(xml_bytes(xml), cert)
      end
    end

    private

    def xml_bytes(xml)
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
end
