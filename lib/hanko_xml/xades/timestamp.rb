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

module HankoXml
  module Xades
    # A verified <xades:SignatureTimeStamp> (#163), on
    # Xades::Verification#signature_timestamps.
    SignatureTimeStamp = Struct.new(:id, :time, :serial_number, :tsa_certificate, :digest_method, :policy_id,
                                    keyword_init: true) do
      def initialize(**)
        super
        freeze
      end
    end

    # Verifies one <xades:SignatureTimeStamp> of a signature whose XML-DSig
    # and signed properties already verified (#163).
    #
    # OpenSSL does the RFC 3161 work: OpenSSL::Timestamp::Response#verify
    # checks the TSA's signature, its chain to the caller's TSA trust and the
    # timeStamping purpose, and that the token's imprint is the digest of the
    # bytes this class hands it. Those bytes are the <ds:SignatureValue>,
    # canonicalized by xmlsec (#161) with the CanonicalizationMethod the
    # SignatureTimeStamp declares. Both algorithms go through the policy.
    #
    # The element is attacker-controlled until this passes: it lies outside
    # everything the signature covers.
    #
    # @api private
    class SignatureTimeStampCheck
      SIGNATURE_VALUE_PATH = [[HankoXml::NS["ds"], "SignatureValue", nil]].freeze
      # The children a SignatureTimeStamp may have. Include and ReferenceInfo
      # belong to other timestamp kinds, XMLTimeStamp has no defined format.
      ALLOWED_CHILDREN = [[HankoXml::NS["ds"], "CanonicalizationMethod"], [:xades, "EncapsulatedTimeStamp"]].freeze

      # +path+ is the native path from the <ds:Signature> to this
      # SignatureTimeStamp.
      def initialize(node, path, ns:, policy:, tsa_store:)
        @node = node
        @path = path
        @ns = ns
        @policy = policy
        @tsa_store = tsa_store
      end

      # @return [SignatureTimeStamp]
      # @raise [XadesError, PolicyError]
      def verify(xml_bytes, signature_index)
        check_children!
        check_canonicalization_method!
        canonical = Native.canonicalize(xml_bytes, signature_index, SIGNATURE_VALUE_PATH,
                                        [*@path, [HankoXml::NS["ds"], "CanonicalizationMethod", nil]])
        response = wrap(token_der)
        digest = digest_method(response.token_info.algorithm)
        verify_token!(response, digest, canonical)
        result(response, digest)
      rescue HankoXml::NativeError, HankoXml::ParseError
        fail!("the SignatureValue could not be canonicalized for the SignatureTimeStamp")
      end

      private

      def check_children!
        children = @node.element_children
        unless children.all? { |child| allowed_child?(child) }
          fail!("a <xades:SignatureTimeStamp> holds only CanonicalizationMethod and EncapsulatedTimeStamp")
        end
        return if children.count { |child| child.name == "EncapsulatedTimeStamp" } == 1

        fail!("a <xades:SignatureTimeStamp> needs exactly one <xades:EncapsulatedTimeStamp>")
      end

      def allowed_child?(child)
        ALLOWED_CHILDREN.any? do |ns, name|
          child.name == name && child.namespace&.href == (ns == :xades ? @ns["xades"] : ns)
        end
      end

      def check_canonicalization_method!
        methods = @node.xpath("ds:CanonicalizationMethod", @ns)
        unless methods.size == 1 && methods.first["Algorithm"]
          fail!("a <xades:SignatureTimeStamp> without a CanonicalizationMethod is not supported")
        end

        @policy.enforce_algorithm!(:canonicalization, methods.first["Algorithm"])
      end

      def token_der
        @node.at_xpath("xades:EncapsulatedTimeStamp", @ns).text.gsub(/\s/, "").unpack1("m0")
      rescue ArgumentError
        fail!("<xades:EncapsulatedTimeStamp> is not Base64")
      end

      # A TimeStampToken is a ContentInfo; OpenSSL verifies it as the token of
      # a granted TimeStampResp, so it is wrapped in one.
      def wrap(token)
        status = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(0)])
        OpenSSL::Timestamp::Response.new(OpenSSL::ASN1::Sequence([status, OpenSSL::ASN1.decode(token)]).to_der)
      rescue OpenSSL::ASN1::ASN1Error, OpenSSL::Timestamp::TimestampError
        fail!("<xades:EncapsulatedTimeStamp> is not an RFC 3161 TimeStampToken OpenSSL can read")
      end

      # The token's imprint digest, as a registry URI the policy allows.
      def digest_method(openssl_name)
        name = OpenSSL::Digest.new(openssl_name.to_s).name.downcase.tr("-", "_").to_sym
        uri = HankoXml::Algorithms.uri_for(:digest, name)
        fail!("the SignatureTimeStamp imprint digest is not a registered digest") unless uri

        @policy.enforce_algorithm!(:digest, uri)
        [name, uri]
      rescue RuntimeError, OpenSSL::Digest::DigestError
        fail!("the SignatureTimeStamp imprint digest is not a registered digest")
      end

      def verify_token!(response, digest, canonical)
        request = OpenSSL::Timestamp::Request.new
        request.algorithm = digest.first.to_s.tr("_", "-")
        request.message_imprint = OpenSSL::Digest.digest(request.algorithm, canonical)
        response.verify(request, @tsa_store)
      rescue OpenSSL::Timestamp::TimestampError
        fail!("the SignatureTimeStamp does not verify: its TSA is not trusted, its signature is invalid, " \
              "or it does not cover this signature's SignatureValue")
      end

      def result(response, digest)
        info = response.token_info
        SignatureTimeStamp.new(
          id: @node["Id"]&.dup&.freeze,
          time: info.gen_time.utc.freeze,
          serial_number: info.serial_number.to_i,
          tsa_certificate: response.tsa_certificate,
          digest_method: digest.last,
          policy_id: info.policy_id
        )
      end

      def fail!(message)
        raise HankoXml::XadesError, message
      end
    end
  end
end
