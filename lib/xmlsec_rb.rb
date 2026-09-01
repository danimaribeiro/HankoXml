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

    def sign(doc_or_xml, **kwargs)
      XmlsecRb::Signer.new(**kwargs).sign(doc_or_xml)
    end

    def sign!(doc, **kwargs)
      XmlsecRb::Signer.new(**kwargs).sign!(doc)
    end

    def verify(xml, **kwargs)
      XmlsecRb::Verifier.new(**kwargs).verify(xml)
    end

    def verify!(xml, **kwargs)
      XmlsecRb::Verifier.new(**kwargs).verify!(xml)
    end

    def signed?(xml)
      doc = XmlsecRb.coerce_document(xml)
      sigs = doc.xpath(".//ds:Signature", ds: NS["ds"])
      sigs.any? do |sig|
        val = sig.at_xpath("./ds:SignatureValue", ds: NS["ds"])
        val && !val.content.strip.empty?
      end
    end

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
      result = verify(xml, certificate: certificate)
      
      if !result.valid?
        error = result.errors.first
        if error.is_a?(XmlsecRb::ParseError) || error.is_a?(XmlsecRb::SignatureMissing) || error.is_a?(XmlsecRb::NativeError)
          raise XmlsecRb::Error, error.message
        end
      end

      result.valid?
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
