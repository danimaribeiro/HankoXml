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

      def self.check_timestamper!(timestamper)
        return if timestamper.nil? || timestamper.respond_to?(:call)

        raise HankoXml::ConfigurationError, "timestamper: must respond to #call (TimeStampReq DER -> TimeStampResp DER)"
      end

      # The imprint algorithms go through the registry and +policy+, like
      # every algorithm the signature itself uses.
      def self.check_algorithms!(policy, digest:, canonicalization:)
        { digest: digest, canonicalization: canonicalization }.each do |slot, name|
          unless HankoXml::Algorithms.uri_for(slot, name)
            raise HankoXml::ConfigurationError,
                  "timestamp_#{slot}_method: #{name.inspect} is not a registered #{slot} algorithm"
          end

          policy.enforce_algorithm!(slot, name)
        end
      end

      # The DER TimeStampToken for the nth signature in +signed_bytes+.
      # +method_path+ leads from the <ds:Signature> to the skeleton's
      # CanonicalizationMethod.
      def token(signed_bytes, index, method_path = METHOD_PATH)
        token_for(Native.canonicalize(signed_bytes, index, [[HankoXml::NS["ds"], "SignatureValue", nil]],
                                      method_path))
      end

      # The DER TimeStampToken over the digest of +input+ (an ArchiveTimeStamp's
      # input, #169).
      def token_for(input)
        request = build_request(OpenSSL::Digest.digest(@digest, input))
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
    # Xades::Verification#signature_timestamps, or <xades141:ArchiveTimeStamp>
    # (#169), on Xades::Verification#archive_timestamps.
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
        canonical = imprint_input(xml_bytes, signature_index)
        response = wrap(token_der)
        digest = digest_method(response.token_info.algorithm)
        verify_token!(response, digest, canonical)
        result(response, digest)
      rescue HankoXml::NativeError, HankoXml::ParseError
        fail!("the #{covered} could not be canonicalized for the #{kind}")
      end

      private

      def kind
        "SignatureTimeStamp"
      end

      def element
        "xades:SignatureTimeStamp"
      end

      def covered
        "SignatureValue"
      end

      def method_path
        [*@path, [HankoXml::NS["ds"], "CanonicalizationMethod", nil]]
      end

      # The bytes the token's imprint must be the digest of.
      def imprint_input(xml_bytes, signature_index)
        Native.canonicalize(xml_bytes, signature_index, SIGNATURE_VALUE_PATH, method_path)
      end

      def check_children!
        children = @node.element_children
        unless children.all? { |child| allowed_child?(child) }
          fail!("a <#{element}> holds only CanonicalizationMethod and EncapsulatedTimeStamp")
        end
        return if children.count { |child| child.name == "EncapsulatedTimeStamp" } == 1

        fail!("a <#{element}> needs exactly one <xades:EncapsulatedTimeStamp>")
      end

      def allowed_child?(child)
        ALLOWED_CHILDREN.any? do |ns, name|
          child.name == name && child.namespace&.href == (ns == :xades ? @ns["xades"] : ns)
        end
      end

      def check_canonicalization_method!
        methods = @node.xpath("ds:CanonicalizationMethod", @ns)
        unless methods.size == 1 && methods.first["Algorithm"]
          fail!("a <#{element}> without a CanonicalizationMethod is not supported")
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
        fail!("the #{kind} imprint digest is not a registered digest") unless uri

        @policy.enforce_algorithm!(:digest, uri)
        [name, uri]
      rescue RuntimeError, OpenSSL::Digest::DigestError
        fail!("the #{kind} imprint digest is not a registered digest")
      end

      def verify_token!(response, digest, canonical)
        request = OpenSSL::Timestamp::Request.new
        request.algorithm = digest.first.to_s.tr("_", "-")
        request.message_imprint = OpenSSL::Digest.digest(request.algorithm, canonical)
        response.verify(request, @tsa_store)
      rescue OpenSSL::Timestamp::TimestampError
        fail!("the #{kind} does not verify: its TSA is not trusted, its signature is invalid, " \
              "or it does not cover this signature's #{covered}")
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

    # Verifies one <xades141:ArchiveTimeStamp> (XAdES-LTA, #169) as
    # SignatureTimeStampCheck does a SignatureTimeStamp, over the input EN 319
    # 132-1 §5.5.2.2 defines, concatenated in this order:
    #
    # 1. each SignedInfo Reference's data, as xmlsec digested it
    #    (Native.reference_data);
    # 2. ds:SignedInfo, ds:SignatureValue and ds:KeyInfo (if present);
    # 3. every UnsignedSignatureProperties child before this ArchiveTimeStamp;
    # 4. every ds:Object except the one holding QualifyingProperties;
    #
    # 2 to 4 each canonicalized by xmlsec (#161) with the ArchiveTimeStamp's
    # CanonicalizationMethod. A Reference whose data is a node set was
    # canonicalized by xmlsec with inclusive c14n, so it is only accepted when
    # that is the ArchiveTimeStamp's method too.
    #
    # @api private
    class ArchiveTimeStampCheck < SignatureTimeStampCheck
      INCLUSIVE_C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
      BASE64_TRANSFORM = "http://www.w3.org/2000/09/xmldsig#base64"

      # Whether any SignedInfo Reference leaves a node set: its transforms do
      # not end in a canonicalization or base64, so xmlsec canonicalized it
      # with inclusive c14n before digesting.
      def self.node_set_references?(signature_info)
        signature_info.references.any? do |reference|
          last = reference.transforms.last
          last.nil? || !(HankoXml::Algorithms.name_for(:canonicalization, last) || last == BASE64_TRANSFORM)
        end
      end

      # The native paths of EN 319 132-1 §5.5.2.2 steps 2 to 4 for the
      # ArchiveTimeStamp +node+ in +properties+ (an UnsignedSignatureProperties
      # at native +path+).
      def self.element_paths(signature, qualifying, properties, node, path)
        ds = HankoXml::NS["ds"]
        paths = [[[ds, "SignedInfo", nil]], [[ds, "SignatureValue", nil]]]
        paths << [[ds, "KeyInfo", nil]] if signature.at_xpath("ds:KeyInfo", "ds" => ds)
        properties.element_children.take_while { |child| !child.equal?(node) }.each do |child|
          paths << [*path, sibling_step(child)]
        end
        signature.xpath("ds:Object", "ds" => ds).each_with_index do |object, i|
          paths << [[ds, "Object", i]] unless object.equal?(qualifying.parent)
        end
        paths
      end

      def self.sibling_step(child)
        href = child.namespace&.href
        Locator.fail!("an unsigned signature property has no namespace") unless href

        same = child.parent.element_children.select do |other|
          other.name == child.name && other.namespace&.href == href
        end
        [href, child.name, same.index(child)]
      end
      private_class_method :sibling_step

      # The concatenated input: the References' data, then each element at
      # +element_paths+ canonicalized with the method at +method_path+.
      def self.input(xml_bytes, signature_index, references, element_paths, method_path)
        element_paths.inject(references.map(&:b).join.b) do |bytes, path|
          bytes << Native.canonicalize(xml_bytes, signature_index, path, method_path).b
        end
      end

      # +references+: the octets of step 1; +node_set_references+: whether any
      # of them was a node set; +element_paths+: the native paths of 2 to 4.
      def initialize(node, path, references:, node_set_references:, element_paths:, **options)
        super(node, path, **options)
        @references = references
        @node_set_references = node_set_references
        @element_paths = element_paths
      end

      private

      def kind
        "ArchiveTimeStamp"
      end

      def element
        "xades141:ArchiveTimeStamp"
      end

      def covered
        "signed data, signature and validation data"
      end

      def imprint_input(xml_bytes, signature_index)
        method = @node.at_xpath("ds:CanonicalizationMethod", @ns)["Algorithm"]
        if @node_set_references && method != INCLUSIVE_C14N
          fail!("an ArchiveTimeStamp over a Reference whose data is a node set needs inclusive c14n " \
                "as its CanonicalizationMethod")
        end

        self.class.input(xml_bytes, signature_index, @references, @element_paths, method_path)
      end
    end
  end
end
