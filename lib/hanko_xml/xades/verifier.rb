# frozen_string_literal: true

require "openssl"
require "time"

module HankoXml
  module Xades
    # A {HankoXml::Verification} that also carries the XAdES signed
    # properties. #valid?, #signed? and #at_signed are false/raise whenever
    # the XAdES checks failed, not only when XML-DSig did.
    class Verification < HankoXml::Verification
      # @return [SignedProperties, nil] Only when #valid?.
      attr_reader :signed_properties

      def initialize(signed_properties: nil, **attributes)
        @signed_properties = signed_properties
        super(**attributes)
      end
    end

    # Verifies a XAdES-B signature (#58): the XML-DSig signature through
    # {HankoXml::Verifier}, then its <xades:SignedProperties>.
    #
    # Everything read comes from the SignedProperties element that xmlsec
    # itself resolved and digested for the Type=SignedProperties Reference, and
    # that element must be the one inside this signature's single
    # QualifyingProperties. A decoy SignedProperties placed where a lookup by
    # XPath would find it is never read (XAdES signature wrapping). The
    # SigningCertificate(V2) must then name the certificate that verified.
    #
    # Reads XAdES 1.3.2 and the older 1.2.2 and 1.1.1 namespaces (#86); the
    # whole signature must use one.
    #
    # Needs certificate-based trust (certificate:, certificates:, store:), and
    # Nokogiri: the signed properties are read from the DOM (#102).
    # Unsigned properties (XAdES-T/LT/LTA) are ignored: #81, #82.
    class Verifier < HankoXml::Verifier # rubocop:disable Metrics/ClassLength
      # @param signature_policy [SignaturePolicy, Hash, :implied, nil] When given, the signed
      #   SignaturePolicyIdentifier must be exactly this.
      # All other keywords are {HankoXml::Verifier}'s.
      def initialize(signature_policy: nil, **options)
        Dom.require!("HankoXml::Xades::Verifier")
        if options[:key] || options[:keys]
          raise HankoXml::ConfigurationError,
                "XAdES verification needs certificate:, certificates: or store:, since the signed properties " \
                "commit to a certificate"
        end

        @expected_signature_policy = coerce_signature_policy(signature_policy)
        super(**options)
      end

      # The signed properties commit to a certificate, so XAdES needs trust in
      # it; there is no integrity-only XAdES verification (#103).
      def self.without_trust_verification(**)
        raise HankoXml::ConfigurationError,
              "XAdES verification needs certificate:, certificates: or store:; " \
              "without_trust_verification is not available for it"
      end

      def verify(xml)
        xades(super)
      end

      def verify_all(xml)
        super.map { |verification| xades(verification) }
      end

      private

      def xades(verification)
        return rebuild(verification) unless verification.valid?

        properties = signed_properties(verification)
        rebuild(verification, signed_properties: properties)
      rescue HankoXml::XadesError, HankoXml::PolicyError => e
        rebuild(verification, error: e)
      end

      def rebuild(verification, signed_properties: nil, error: nil)
        Verification.new(
          valid: verification.valid? && error.nil?,
          errors: [*verification.errors, *error],
          signature_info: verification.signature_info,
          signature_node: verification.signature_node,
          document: verification.document,
          namespaces: verification.namespaces,
          certificate: verification.certificate,
          certificate_chain: verification.certificate_chain,
          trusted: verification.trusted?,
          root_signature: verification.send(:root_signature),
          id_attributes: verification.id_attributes,
          resolver: verification.resolver,
          reference_element_indexes: verification.reference_element_indexes,
          reference_valid: verification.reference_valid,
          signature_element_index: verification.signature_element_index,
          signed_properties: signed_properties
        )
      end

      def signed_properties(verification)
        node, ns = signed_properties_node(verification)
        signature_properties = node.at_xpath("xades:SignedSignatureProperties", ns)
        fail!("<xades:SignedProperties> has no <xades:SignedSignatureProperties>") unless signature_properties

        check_signing_certificate!(signature_properties, verification.certificate, ns)
        policy = signature_policy(signature_properties, ns)
        check_signature_policy!(policy)

        SignedProperties.new(
          signing_time: signing_time(signature_properties, ns),
          signature_policy: policy,
          claimed_roles: signature_properties.xpath("xades:SignerRoleV2/xades:ClaimedRoles/xades:ClaimedRole | " \
                                                    "xades:SignerRole/xades:ClaimedRoles/xades:ClaimedRole", ns)
                                             .map { |role| role.text.strip.freeze }.freeze,
          data_object_formats: data_object_formats(node, ns)
        )
      end

      # The SignedProperties xmlsec digested, checked to be the one this
      # signature's QualifyingProperties holds, and the namespaces to read it
      # with.
      def signed_properties_node(verification)
        info, reference = signed_properties_reference(verification)
        qualifying, ns = qualifying_properties(verification.signature_node)

        type_namespace = VERSIONED_SIGNED_PROPERTIES_TYPES[info.type]
        if type_namespace && type_namespace != ns["xades"]
          fail!("the SignedProperties <Reference> Type names another XAdES version than its QualifyingProperties")
        end

        expected = qualifying.xpath("xades:SignedProperties", ns)
        unless expected.size == 1 && expected.first.pointer_id == reference.node.pointer_id
          fail!("the signed <xades:SignedProperties> is not the one in this signature's QualifyingProperties")
        end

        [reference.node, ns]
      end

      # The single SignedProperties Reference, as SignedInfo claims it and as
      # it verified.
      def signed_properties_reference(verification)
        pairs = verification.signature_info.references.zip(verification.references)
                            .select { |info, reference| signed_properties_reference?(info, reference) }
        unless pairs.size == 1
          fail!("a XAdES signature has exactly one <Reference> of Type #{SIGNED_PROPERTIES_TYPE}, " \
                "this one has #{pairs.size}")
        end

        reference = pairs.first.last
        fail!("the SignedProperties <Reference> did not verify") unless reference.valid? && reference.node

        pairs.first
      end

      # This signature's single QualifyingProperties, in any XAdES namespace,
      # and the namespaces to read it with.
      def qualifying_properties(signature)
        signature_id = signature["Id"].to_s
        fail!("the <Signature> has no Id for QualifyingProperties to target") if signature_id.empty?

        qualifying = signature.xpath("ds:Object/*[local-name()='QualifyingProperties']", "ds" => HankoXml::NS["ds"])
                              .select { |node| NAMESPACES.include?(node.namespace&.href) }
        fail!("a XAdES signature has exactly one <xades:QualifyingProperties>") unless qualifying.size == 1

        qualifying = qualifying.first
        fail!("<xades:QualifyingProperties> does not target this <Signature>") unless targets?(qualifying, signature_id)

        [qualifying, { "ds" => HankoXml::NS["ds"], "xades" => qualifying.namespace.href }]
      end

      # By its Type, or, with no Type (as some 1.2.2 signatures write it), by
      # what xmlsec resolved and digested: a SignedProperties element in a
      # XAdES namespace. Never by the URI text (#86).
      def signed_properties_reference?(info, reference)
        return info.type == SIGNED_PROPERTIES_TYPE || VERSIONED_SIGNED_PROPERTIES_TYPES.key?(info.type) if info.type

        node = reference.node
        !node.nil? && node.name == "SignedProperties" && NAMESPACES.include?(node.namespace&.href)
      end

      # Target is "#" + the Signature Id. The older namespaces also had
      # signers write the bare Id (Target="Signature"). Either way the
      # QualifyingProperties must sit in this <Signature>'s own <Object>.
      def targets?(qualifying, signature_id)
        target = qualifying["Target"]
        return true if target == "##{signature_id}"

        LEGACY_NAMESPACES.include?(qualifying.namespace.href) && target == signature_id
      end

      def check_signing_certificate!(signature_properties, certificate, ns)
        fail!("no certificate verified the signature, so SigningCertificate cannot be checked") unless certificate

        v2 = signature_properties.xpath("xades:SigningCertificateV2/xades:Cert", ns)
        v1 = signature_properties.xpath("xades:SigningCertificate/xades:Cert", ns)
        if v1.empty? == v2.empty?
          fail!("exactly one of <xades:SigningCertificate> or <xades:SigningCertificateV2> is required")
        end

        cert = (v2.empty? ? v1 : v2).find { |candidate| certificate_digest_matches?(candidate, certificate, ns) }
        fail!("SigningCertificate does not name the certificate that verified the signature") unless cert

        check_issuer_serial!(cert, certificate, ns)
      end

      def certificate_digest_matches?(cert, certificate, ns)
        digest_method = cert.at_xpath("xades:CertDigest/ds:DigestMethod/@Algorithm", ns)&.value
        digest_value = cert.at_xpath("xades:CertDigest/ds:DigestValue", ns)&.text
        fail!("a <xades:Cert> has no CertDigest") unless digest_method && digest_value

        @policy.enforce_algorithm!(:digest, digest_method)
        name = HankoXml::Algorithms.name_for(:digest, digest_method)
        actual = Xades.openssl_digest(name, certificate.to_der)
        decoded = digest_value.gsub(/\s/, "").unpack1("m")
        OpenSSL.fixed_length_secure_compare(actual, decoded) if actual.bytesize == decoded.bytesize
      end

      # IssuerSerialV2 must decode to the certificate's issuer and serial.
      # The v1 IssuerSerial's issuer is a DN string whose formatting varies
      # between implementations, so only its serial number is compared.
      def check_issuer_serial!(cert, certificate, ns)
        v2 = cert.at_xpath("xades:IssuerSerialV2", ns)&.text
        v1 = cert.at_xpath("xades:IssuerSerial/ds:X509SerialNumber", ns)&.text

        if v2
          issuer, serial = decode_issuer_serial(v2)
          return if issuer == certificate.issuer && serial == certificate.serial

          fail!("IssuerSerialV2 does not match the certificate that verified the signature")
        elsif v1
          fail!("the IssuerSerial of <xades:SigningCertificate> is malformed") unless v1.strip.match?(/\A\d+\z/)
          return if OpenSSL::BN.new(v1.strip) == certificate.serial

          fail!("IssuerSerial does not match the certificate that verified the signature")
        end
      end

      # RFC 5035 IssuerSerial: SEQUENCE { GeneralNames, INTEGER }, the issuer
      # being the GeneralNames' directoryName [4].
      def decode_issuer_serial(base64)
        sequence = OpenSSL::ASN1.decode(base64.gsub(/\s/, "").unpack1("m"))
        general_names, serial = sequence.value if sequence.is_a?(OpenSSL::ASN1::Sequence)
        names = general_names.is_a?(OpenSSL::ASN1::Sequence) ? general_names.value : []
        directory_name = names.find { |name| name.tag == 4 && name.tag_class == :CONTEXT_SPECIFIC }
        name = directory_name&.value&.first
        unless name && serial.is_a?(OpenSSL::ASN1::Integer)
          fail!("the IssuerSerialV2 of <xades:SigningCertificateV2> is malformed")
        end

        [OpenSSL::X509::Name.new(name.to_der), serial.value]
      rescue OpenSSL::ASN1::ASN1Error, OpenSSL::X509::NameError
        fail!("the IssuerSerialV2 of <xades:SigningCertificateV2> is malformed")
      end

      def signing_time(signature_properties, ns)
        text = signature_properties.at_xpath("xades:SigningTime", ns)&.text
        return nil unless text

        Time.iso8601(text.strip).utc.freeze
      rescue ArgumentError
        fail!("<xades:SigningTime> is not an xs:dateTime")
      end

      def signature_policy(signature_properties, ns)
        identifier = signature_properties.at_xpath("xades:SignaturePolicyIdentifier", ns)
        return nil unless identifier
        return :implied if identifier.at_xpath("xades:SignaturePolicyImplied", ns)

        policy_id = identifier.at_xpath("xades:SignaturePolicyId", ns)
        SignaturePolicy.new(
          identifier: policy_id&.at_xpath("xades:SigPolicyId/xades:Identifier", ns)&.text.to_s.strip,
          description: policy_id&.at_xpath("xades:SigPolicyId/xades:Description", ns)&.text,
          digest_method: policy_id&.at_xpath("xades:SigPolicyHash/ds:DigestMethod/@Algorithm", ns)&.value.to_s,
          digest_value: policy_id&.at_xpath("xades:SigPolicyHash/ds:DigestValue", ns)&.text.to_s.gsub(/\s/, "")
        )
      rescue HankoXml::ConfigurationError
        fail!("<xades:SignaturePolicyIdentifier> is malformed")
      end

      def check_signature_policy!(policy)
        expected = @expected_signature_policy
        return if expected.nil?
        return if expected == :implied && policy == :implied
        return if policy.is_a?(SignaturePolicy) && expected.is_a?(SignaturePolicy) &&
                  policy.identifier == expected.identifier &&
                  policy.digest_value == expected.digest_value &&
                  policy.digest_method == HankoXml::Algorithms.uri_for(:digest, expected.digest_method)

        fail!("the signed SignaturePolicyIdentifier is not the expected signature policy")
      end

      def data_object_formats(signed_properties, ns)
        signed_properties.xpath("xades:SignedDataObjectProperties/xades:DataObjectFormat", ns).map do |format|
          {
            object_reference: format["ObjectReference"],
            mime_type: format.at_xpath("xades:MimeType", ns)&.text,
            description: format.at_xpath("xades:Description", ns)&.text,
            encoding: format.at_xpath("xades:Encoding", ns)&.text
          }.freeze
        end.freeze
      end

      def coerce_signature_policy(value)
        case value
        when nil, :implied, SignaturePolicy then value
        when Hash then SignaturePolicy.new(**value)
        else
          raise HankoXml::ConfigurationError,
                "signature_policy: must be a Xades::SignaturePolicy, a Hash of its keywords, :implied or nil"
        end
      end

      def fail!(message)
        raise HankoXml::XadesError, message
      end
    end
  end
end
