# frozen_string_literal: true

require "openssl"

module HankoXml
  module Xades
    # Obtains the RFC 3161 token for a XAdES-T <xades:SignatureTimeStamp>
    # (#162). The imprint is a digest of the signature's <ds:SignatureValue>,
    # canonicalized by xmlsec (#161) with the CanonicalizationMethod the
    # SignatureTimeStamp skeleton already declares. OpenSSL::Timestamp builds
    # the request and parses the response; the Signer's timestamper: performs
    # the exchange.
    #
    # The response is checked against the request before it is used: status
    # granted, the same imprint and digest, the same nonce. Its TSA signature
    # is not checked here: that needs the TSA's trust anchors, which the
    # verifier holds (#163).
    #
    # @api private
    class SignatureTimeStamper
      # The skeleton's CanonicalizationMethod and EncapsulatedTimeStamp, from
      # the <ds:Signature>.
      TIMESTAMP_PATH = [
        [HankoXml::NS["ds"], "Object", nil], [NS, "QualifyingProperties", nil], [NS, "UnsignedProperties", nil],
        [NS, "UnsignedSignatureProperties", nil], [NS, "SignatureTimeStamp", nil]
      ].freeze
      METHOD_PATH = [*TIMESTAMP_PATH, [HankoXml::NS["ds"], "CanonicalizationMethod", nil]].freeze
      ENCAPSULATED_XPATH = "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/" \
                           "xades:UnsignedSignatureProperties/xades:SignatureTimeStamp/xades:EncapsulatedTimeStamp"

      # PKIStatus granted and grantedWithMods (RFC 3161 §2.4.2).
      GRANTED = [0, 1].freeze

      def initialize(signer)
        @signer = signer
        @digest = HankoXml::Algorithms.name_for(
          :digest, HankoXml::Algorithms.uri_for(:digest, signer.timestamp_digest_method)
        ).to_s.tr("_", "-")
      end

      # The DER TimeStampToken for the nth signature in +signed_bytes+.
      def token(signed_bytes, index)
        canonical = Native.canonicalize(signed_bytes, index, [[HankoXml::NS["ds"], "SignatureValue", nil]],
                                        METHOD_PATH)
        request = build_request(OpenSSL::Digest.digest(@digest, canonical))
        response = exchange(request)
        check_response!(request, response)
        response.token.to_der
      end

      private

      def build_request(imprint)
        OpenSSL::Timestamp::Request.new.tap do |request|
          request.algorithm = @digest
          request.message_imprint = imprint
          request.nonce = OpenSSL::BN.rand(64)
          request.cert_requested = true
        end
      end

      def exchange(request)
        der = @signer.timestamper.call(request.to_der)
        unless der.is_a?(String)
          raise HankoXml::SigningError, "timestamper: returned #{der.class}, not a DER TimeStampResp"
        end

        OpenSSL::Timestamp::Response.new(der)
      rescue OpenSSL::Timestamp::TimestampError
        raise HankoXml::SigningError, "timestamper: returned bytes that are not a DER TimeStampResp"
      end

      def check_response!(request, response)
        unless GRANTED.include?(response.status.to_i) && response.token
          raise HankoXml::SigningError,
                "the TSA did not grant the timestamp (status #{response.status.to_i}#{status_text(response)})"
        end

        info = response.token_info
        unless info.message_imprint == request.message_imprint && digest_name(info.algorithm) == @digest
          raise HankoXml::SigningError, "the TSA's token does not cover this signature's SignatureValue imprint"
        end
        return if info.nonce == request.nonce

        raise HankoXml::SigningError, "the TSA's token does not carry the request's nonce"
      end

      def digest_name(algorithm)
        OpenSSL::Digest.new(algorithm).name.downcase
      rescue RuntimeError, OpenSSL::Digest::DigestError
        nil
      end

      def status_text(response)
        text = Array(response.status_text).join("; ")
        text.empty? ? "" : ": #{text}"
      end
    end
  end
end
