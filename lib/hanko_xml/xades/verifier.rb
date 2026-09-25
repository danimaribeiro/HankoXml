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
    # Needs certificate-based trust (certificate:, certificates:, store:).
    # Unsigned properties (XAdES-T/LT/LTA) are ignored: #81, #82.
    class Verifier < HankoXml::Verifier
      DS = { "ds" => HankoXml::NS["ds"], "xades" => NS }.freeze
      private_constant :DS

      # @param signature_policy [SignaturePolicy, Hash, :implied, nil] When given, the signed
      #   SignaturePolicyIdentifier must be exactly this.
      # All other keywords are {HankoXml::Verifier}'s.
      def initialize(signature_policy: nil, **options)
        if options[:key] || options[:keys]
          raise HankoXml::ConfigurationError,
            "XAdES verification needs certificate:, certificates: or store:, since the signed properties " \
              "commit to a certificate"
        end

        @expected_signature_policy = coerce_signature_policy(signature_policy)
        super(**options)
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
          id_attributes: verification.id_attributes,
          resolver: verification.resolver,
          reference_element_indexes: verification.reference_element_indexes,
          reference_valid: verification.reference_valid,
          signed_properties: signed_properties
        )
      end

      def signed_properties(verification)
        node = signed_properties_node(verification)
        signature_properties = node.at_xpath("xades:SignedSignatureProperties", DS)
        fail!("<xades:SignedProperties> has no <xades:SignedSignatureProperties>") unless signature_properties

        check_signing_certificate!(signature_properties, verification.certificate)
        policy = signature_policy(signature_properties)
        check_signature_policy!(policy)

        SignedProperties.new(
          signing_time: signing_time(signature_properties),
          signature_policy: policy,
          claimed_roles: signature_properties
            .xpath(
              "xades:SignerRoleV2/xades:ClaimedRoles/xades:ClaimedRole | " \
                "xades:SignerRole/xades:ClaimedRoles/xades:ClaimedRole",
              DS
            )
            .map { |role| role.text.strip.freeze }
            .freeze,
          data_object_formats: data_object_formats(node)
        )
      end

      # The SignedProperties xmlsec digested, checked to be the one this
      # signature's QualifyingProperties holds.
      def signed_properties_node(verification)
        signature = verification.signature_node
        indexes = verification.signature_info.references.each_index.select do |i|
          verification.signature_info.references[i].type == SIGNED_PROPERTIES_TYPE
        end
        unless indexes.size == 1
          fail!(
            "a XAdES signature has exactly one <Reference> of Type #{SIGNED_PROPERTIES_TYPE}, " \
              "this one has #{indexes.size}"
          )
        end

        reference = verification.references[indexes.first]
        fail!("the SignedProperties <Reference> did not verify") unless reference.valid? && reference.node

        signature_id = signature["Id"].to_s
        fail!("the <Signature> has no Id for QualifyingProperties to target") if signature_id.empty?

        qualifying = signature.xpath("ds:Object/xades:QualifyingProperties", DS)
        fail!("a XAdES signature has exactly one <xades:QualifyingProperties>") unless qualifying.size == 1
        unless qualifying.first["Target"] == "##{signature_id}"
          fail!("<xades:QualifyingProperties> does not target this <Signature>")
        end

        expected = qualifying.first.xpath("xades:SignedProperties", DS)
        unless expected.size == 1 && expected.first.pointer_id == reference.node.pointer_id
          fail!("the signed <xades:SignedProperties> is not the one in this signature's QualifyingProperties")
        end

        reference.node
      end

      def check_signing_certificate!(signature_properties, certificate)
        fail!("no certificate verified the signature, so SigningCertificate cannot be checked") unless certificate

        v2 = signature_properties.xpath("xades:SigningCertificateV2/xades:Cert", DS)
        v1 = signature_properties.xpath("xades:SigningCertificate/xades:Cert", DS)
        if v1.empty? == v2.empty?
          fail!("exactly one of <xades:SigningCertificate> or <xades:SigningCertificateV2> is required")
        end

        cert = (v2.empty? ? v1 : v2).find { |candidate| certificate_digest_matches?(candidate, certificate) }
        fail!("SigningCertificate does not name the certificate that verified the signature") unless cert

        check_issuer_serial!(cert, certificate)
      end

      def certificate_digest_matches?(cert, certificate)
        digest_method = cert.at_xpath("xades:CertDigest/ds:DigestMethod/@Algorithm", DS)&.value
        digest_value = cert.at_xpath("xades:CertDigest/ds:DigestValue", DS)&.text
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
      def check_issuer_serial!(cert, certificate)
        v2 = cert.at_xpath("xades:IssuerSerialV2", DS)&.text
        v1 = cert.at_xpath("xades:IssuerSerial/ds:X509SerialNumber", DS)&.text

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

      def signing_time(signature_properties)
        text = signature_properties.at_xpath("xades:SigningTime", DS)&.text
        return nil unless text

        Time.iso8601(text.strip).utc.freeze
      rescue ArgumentError
        fail!("<xades:SigningTime> is not an xs:dateTime")
      end

      def signature_policy(signature_properties)
        identifier = signature_properties.at_xpath("xades:SignaturePolicyIdentifier", DS)
        return nil unless identifier

        return :implied if identifier.at_xpath("xades:SignaturePolicyImplied", DS)

        policy_id = identifier.at_xpath("xades:SignaturePolicyId", DS)
        SignaturePolicy.new(
          identifier: policy_id&.at_xpath("xades:SigPolicyId/xades:Identifier", DS)&.text.to_s.strip,
          description: policy_id&.at_xpath("xades:SigPolicyId/xades:Description", DS)&.text,
          digest_method: policy_id&.at_xpath("xades:SigPolicyHash/ds:DigestMethod/@Algorithm", DS)&.value.to_s,
          digest_value: policy_id&.at_xpath("xades:SigPolicyHash/ds:DigestValue", DS)&.text.to_s.gsub(/\s/, "")
        )
      rescue HankoXml::ConfigurationError
        fail!("<xades:SignaturePolicyIdentifier> is malformed")
      end

      def check_signature_policy!(policy)
        expected = @expected_signature_policy
        return if expected.nil?

        return if expected == :implied && policy == :implied

        if policy.is_a?(SignaturePolicy) &&
            expected.is_a?(SignaturePolicy) &&
            policy.identifier == expected.identifier &&
            policy.digest_value == expected.digest_value &&
            policy.digest_method == HankoXml::Algorithms.uri_for(:digest, expected.digest_method)
          return
        end

        fail!("the signed SignaturePolicyIdentifier is not the expected signature policy")
      end

      def data_object_formats(signed_properties)
        signed_properties.xpath("xades:SignedDataObjectProperties/xades:DataObjectFormat", DS).map do |format|
          {
            object_reference: format["ObjectReference"],
            mime_type: format.at_xpath("xades:MimeType", DS)&.text,
            description: format.at_xpath("xades:Description", DS)&.text,
            encoding: format.at_xpath("xades:Encoding", DS)&.text
          }.freeze
        end.freeze
      end

      def coerce_signature_policy(value)
        case value
        when nil, :implied, SignaturePolicy
          value
        when Hash
          SignaturePolicy.new(**value)
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
