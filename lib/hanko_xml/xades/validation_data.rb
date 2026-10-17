# frozen_string_literal: true

require "openssl"

module HankoXml
  module Xades
    # The XAdES-LT validation material (#167): certificates for
    # <xades:CertificateValues>, CRLs and OCSP responses for
    # <xades:RevocationValues>. The caller collects it; the library never
    # fetches. Nothing here is trusted: a verifier treats it as
    # attacker-supplied until it chains to its own anchors (S-22, #168).
    #
    # Each entry is checked for its type only: X.509 certificates, X.509
    # CRLs, and OCSPResponses whose responseStatus is successful.
    ValidationData = Struct.new(:certificates, :crls, :ocsp_responses, keyword_init: true) do
      # @param certificates [Array<OpenSSL::X509::Certificate, String, Key>] Anything Key.coerce reads.
      # @param crls [Array<OpenSSL::X509::CRL, String>] PEM or DER.
      # @param ocsp_responses [Array<OpenSSL::OCSP::Response, String>] DER OCSPResponse.
      def initialize(certificates: [], crls: [], ocsp_responses: [])
        super(
          certificates: Array(certificates).map { |value| ValidationData.certificate(value) }.freeze,
          crls: Array(crls).map { |value| ValidationData.crl(value) }.freeze,
          ocsp_responses: Array(ocsp_responses).map { |value| ValidationData.ocsp_response(value) }.freeze
        )
        if to_h.values.all?(&:empty?)
          raise HankoXml::ConfigurationError, "validation_data: needs certificates:, crls: or ocsp_responses:"
        end

        freeze
      end

      def self.coerce(value)
        case value
        when nil, ValidationData then value
        when Hash then new(**value)
        else
          raise HankoXml::ConfigurationError,
                "validation_data: must be a Xades::ValidationData, a Hash of its keywords or nil"
        end
      end

      def self.certificate(value)
        key = HankoXml::Key.coerce(value)
        return key.to_openssl if key.certificate?

        raise HankoXml::ConfigurationError, "validation_data certificates: must be X.509 certificates"
      rescue HankoXml::KeyLoadError, ::ArgumentError
        raise HankoXml::ConfigurationError, "validation_data certificates: must be X.509 certificates"
      end

      def self.crl(value)
        return value if value.is_a?(OpenSSL::X509::CRL)
        raise HankoXml::ConfigurationError, "validation_data crls: must be X.509 CRLs" unless value.is_a?(String)

        OpenSSL::X509::CRL.new(value)
      rescue OpenSSL::X509::CRLError
        raise HankoXml::ConfigurationError, "validation_data crls: must be X.509 CRLs (PEM or DER)"
      end

      def self.ocsp_response(value)
        response = value.is_a?(OpenSSL::OCSP::Response) ? value : parse_ocsp_response(value)
        unless response.status == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL && response.basic
          raise HankoXml::ConfigurationError,
                "validation_data ocsp_responses: must be successful OCSP responses " \
                "(responseStatus #{response.status})"
        end

        response
      end

      def self.parse_ocsp_response(value)
        unless value.is_a?(String)
          raise HankoXml::ConfigurationError, "validation_data ocsp_responses: must be DER OCSPResponses"
        end

        OpenSSL::OCSP::Response.new(value)
      rescue OpenSSL::OCSP::OCSPError
        raise HankoXml::ConfigurationError, "validation_data ocsp_responses: must be DER OCSPResponses"
      end
      private_class_method :parse_ocsp_response

      # Appends <xades:CertificateValues> and <xades:RevocationValues> (each
      # only when it has entries) to +parent+, an UnsignedSignatureProperties
      # in +namespace+.
      def append_to(parent, namespace)
        add = lambda do |node, name|
          child = parent.document.create_element(name)
          node.add_child(child)
          child.namespace = namespace
          child
        end
        encapsulate = ->(node, name, der) { add.call(node, name).content = [der].pack("m0") }

        unless certificates.empty?
          values = add.call(parent, "CertificateValues")
          certificates.each do |certificate|
            encapsulate.call(values, "EncapsulatedX509Certificate", certificate.to_der)
          end
        end
        return if crls.empty? && ocsp_responses.empty?

        # RevocationValuesType is a sequence: CRLValues, then OCSPValues.
        revocation = add.call(parent, "RevocationValues")
        unless crls.empty?
          values = add.call(revocation, "CRLValues")
          crls.each { |crl| encapsulate.call(values, "EncapsulatedCRLValue", crl.to_der) }
        end
        return if ocsp_responses.empty?

        values = add.call(revocation, "OCSPValues")
        ocsp_responses.each { |response| encapsulate.call(values, "EncapsulatedOCSPValue", response.to_der) }
      end
    end
  end
end
