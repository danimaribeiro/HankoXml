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
      # @return [Array<SignatureTimeStamp>, nil] The verified SignatureTimeStamps (#163), in document order;
      #   empty when there are none, nil unless #valid? or with timestamps: :ignore.
      attr_reader :signature_timestamps
      # @return [LongTermValidation, nil] The XAdES-LT validation (#168): only when #valid? and the signature
      #   carries CertificateValues or RevocationValues that were checked.
      attr_reader :long_term_validation
      # @return [Array<SignatureTimeStamp>, nil] The verified xades141:ArchiveTimeStamps (#169), in document
      #   order; empty when there are none, nil unless #valid? or with timestamps: :ignore.
      attr_reader :archive_timestamps

      def initialize(signed_properties: nil, signature_timestamps: nil, long_term_validation: nil,
                     archive_timestamps: nil, **attributes)
        @signed_properties = signed_properties
        @signature_timestamps = signature_timestamps&.freeze
        @long_term_validation = long_term_validation
        @archive_timestamps = archive_timestamps&.freeze
        super(**attributes)
      end

      # The earliest verified SignatureTimeStamp time: when a trusted third
      # party saw this signature at the latest. Nil without one.
      def timestamp_time
        signature_timestamps&.map(&:time)&.min
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
    # XAdES-T (#163): every <xades:SignatureTimeStamp> in the signature's
    # UnsignedSignatureProperties must verify against the TSA trust
    # (tsa_store: / tsa_certificates:), kept apart from the signer's. A
    # timestamp that does not verify fails the signature (fail closed).
    # Xades::Locator finds QualifyingProperties and its unsigned containers.
    #
    # XAdES-LT (#168): when the signature embeds CertificateValues or
    # RevocationValues, the signing certificate is validated at the time of
    # the earliest verified SignatureTimeStamp: XML-DSig trust (chain,
    # validity dates) at that time, then revocation evidence for every
    # certificate below the trust anchor from the embedded CRLs and OCSP
    # responses (Xades::LongTermCheck). A certificate that has expired since
    # still verifies; embedded data that does not hold fails (fail closed).
    # XAdES-LTA (#169): every xades141:ArchiveTimeStamp must verify too, over
    # the EN 319 132-1 input (Xades::ArchiveTimeStampCheck), against the same
    # TSA trust; fail closed, and not read with timestamps: :ignore.
    #
    # Needs certificate-based trust (certificate:, certificates:, store:), and
    # Nokogiri: the signed properties are read from the DOM (#102).
    class Verifier < HankoXml::Verifier # rubocop:disable Metrics/ClassLength
      TIMESTAMP_MODES = %i[verify require ignore].freeze
      LONG_TERM_MODES = %i[verify require ignore].freeze

      # @param signature_policy [SignaturePolicy, Hash, :implied, nil] When given, the signed
      #   SignaturePolicyIdentifier must be exactly this.
      # @param timestamps [Symbol] :verify (default) checks every SignatureTimeStamp present; :require also
      #   fails a signature without one; :ignore does not read them, the XAdES-B behavior.
      # @param tsa_store [OpenSSL::X509::Store, nil] Trust for the TSAs, not the signer.
      # @param tsa_certificates [Array<OpenSSL::X509::Certificate, String, Key>, nil] Trusted TSA roots or
      #   certificates, instead of tsa_store:.
      # @param long_term [Symbol, nil] :verify checks embedded XAdES-LT values when present; :require also
      #   fails a signature without them; :ignore does not read them. nil (default) is :verify, or :ignore with
      #   timestamps: :ignore, since the validation time comes from a SignatureTimeStamp.
      # @param revocation_grace [Numeric] Seconds an embedded CRL or OCSP response may predate the validation
      #   time and still count as fresh. 0 (default): it must be issued at or after it.
      # All other keywords are {HankoXml::Verifier}'s.
      def initialize(signature_policy: nil, timestamps: :verify, tsa_store: nil, tsa_certificates: nil,
                     long_term: nil, revocation_grace: 0, **options)
        Dom.require!("HankoXml::Xades::Verifier")
        if options[:key] || options[:keys]
          raise HankoXml::ConfigurationError,
                "XAdES verification needs certificate:, certificates: or store:, since the signed properties " \
                "commit to a certificate"
        end

        @expected_signature_policy = coerce_signature_policy(signature_policy)
        @timestamps = coerce_timestamps(timestamps)
        @tsa_store = coerce_tsa_store(tsa_store, tsa_certificates)
        @long_term = coerce_long_term(long_term)
        @revocation_grace = coerce_revocation_grace(revocation_grace)
        # Kept to verify the XML-DSig signature again at the validation time.
        @options = options.freeze
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
        as_xades(super)
      end

      def verify_all(xml)
        super.map { |verification| as_xades(verification) }
      end

      private

      # Every signature verified goes through here, with the bytes and the
      # index the native layer used, which the timestamp checks reuse.
      #
      # With XAdES-LT values, the SignatureTimeStamps are verified first, as
      # their earliest time is when the signing certificate is validated
      # (#168): the XML-DSig signature is then verified at that time.
      def verify_single(input, index)
        values, timestamps = long_term_plan(input, index)
        return xades(super, input.bytes, index) unless values

        time = timestamps.map(&:time).min
        verification = xades(at_time(time, values, input, index), input.bytes, index, timestamps: timestamps)
        return verification unless verification.valid?

        validation = LongTermCheck.new(grace: @revocation_grace, clock_skew: @policy.clock_skew)
                                  .verify(time: time, chain: long_term_chain(verification), values: values)
        rebuild(verification, signed_properties: verification.signed_properties,
                              signature_timestamps: verification.signature_timestamps,
                              archive_timestamps: verification.archive_timestamps,
                              long_term_validation: validation)
      rescue HankoXml::XadesError, HankoXml::PolicyError => e
        rebuild(verification || super, error: e)
      end

      # The embedded XAdES-LT values and the verified SignatureTimeStamps, or
      # nil when there are no values to check.
      def long_term_plan(input, index)
        return nil if @long_term == :ignore

        signature = signature_nodes(input)[index]
        values = long_term_values(signature)
        unless values
          if @long_term == :require
            fail!("long_term: :require, but the signature has no <xades:CertificateValues> or " \
                  "<xades:RevocationValues>")
          end
          return nil
        end

        timestamps = signature_timestamps(signature, input.bytes, index)
        if timestamps.empty?
          fail!("XAdES-LT values need a verified <xades:SignatureTimeStamp> for their validation time")
        end

        [values, timestamps]
      end

      # A signature whose QualifyingProperties or unsigned containers cannot
      # be located has no values here: the signed-properties and timestamp
      # checks fail it on the same structure, with their own message.
      def long_term_values(signature)
        qualifying, ns = Locator.qualifying_properties(signature)
        properties = Locator.unsigned_signature_properties(qualifying, ns)
      rescue HankoXml::XadesError
        nil
      else
        LongTermValues.read(properties, ns)
      end

      # The XML-DSig verification at +time+ (unless the caller fixed
      # verification_time:), with the embedded CertificateValues as untrusted
      # intermediates for a store: chain.
      def at_time(time, values, input, index)
        verifier = AtTime.new(intermediates: values.certificates, signature_policy: @expected_signature_policy,
                              timestamps: :ignore, long_term: :ignore,
                              **@options.merge(verification_time: verification_time || time))
        HankoXml::Verifier.instance_method(:verify_single).bind_call(verifier, input, index)
      end

      # store: gives the chain OpenSSL validated; certificate: and
      # certificates: pin the signing certificate itself as the anchor.
      def long_term_chain(verification)
        verification.certificate_chain || [verification.certificate]
      end

      # A result that never reached verify_single (no signature found).
      def as_xades(verification)
        verification.is_a?(Verification) ? verification : rebuild(verification)
      end

      def xades(verification, xml_bytes, index, timestamps: nil)
        return rebuild(verification) unless verification.valid?

        properties = signed_properties(verification)
        timestamps ||= signature_timestamps(verification.signature_node, xml_bytes, index)
        archives = archive_timestamps(verification, xml_bytes, index)
        rebuild(verification, signed_properties: properties, signature_timestamps: timestamps,
                              archive_timestamps: archives)
      rescue HankoXml::XadesError, HankoXml::PolicyError => e
        rebuild(verification, error: e)
      end

      def rebuild(verification, signed_properties: nil, signature_timestamps: nil, long_term_validation: nil,
                  archive_timestamps: nil, error: nil)
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
          signed_properties: signed_properties,
          signature_timestamps: signature_timestamps,
          long_term_validation: long_term_validation,
          archive_timestamps: archive_timestamps
        )
      end

      # Each SignatureTimeStamp of this signature, verified (#163). Read only
      # along the path from its own QualifyingProperties, never by a search
      # that a wrapped element elsewhere could satisfy.
      def signature_timestamps(signature, xml_bytes, index)
        return nil if @timestamps == :ignore

        nodes, path, xades_ns = signature_timestamp_nodes(signature)
        if nodes.empty?
          fail!("timestamps: :require, but the signature has no <xades:SignatureTimeStamp>") if @timestamps == :require
          return []
        end

        unless @tsa_store
          fail!("the signature has a <xades:SignatureTimeStamp>; pass tsa_store: or tsa_certificates: to " \
                "verify it, or timestamps: :ignore")
        end

        nodes.each_with_index.map do |node, i|
          SignatureTimeStampCheck.new(node, [*path, [xades_ns, "SignatureTimeStamp", i]],
                                      ns: { "ds" => HankoXml::NS["ds"], "xades" => xades_ns },
                                      policy: @policy, tsa_store: @tsa_store).verify(xml_bytes, index)
        end
      end

      # Each xades141:ArchiveTimeStamp of this signature, verified (#169), read
      # along the same path as the SignatureTimeStamps.
      def archive_timestamps(verification, xml_bytes, index)
        return nil if @timestamps == :ignore

        signature = verification.signature_node
        qualifying, ns = Locator.qualifying_properties(signature)
        properties = Locator.unsigned_signature_properties(qualifying, ns)
        nodes = properties ? properties.xpath("xades141:ArchiveTimeStamp", "xades141" => NS141).to_a : []
        return [] if nodes.empty?

        fail!("ArchiveTimeStamp is verified only with XAdES 1.3.2 QualifyingProperties") unless ns["xades"] == NS
        unless @tsa_store
          fail!("the signature has a <xades141:ArchiveTimeStamp>; pass tsa_store: or tsa_certificates: to " \
                "verify it, or timestamps: :ignore")
        end

        path = Locator.unsigned_path(signature, qualifying, NS)
        references = reference_data(verification, xml_bytes, index)
        node_set = ArchiveTimeStampCheck.node_set_references?(verification.signature_info)
        nodes.each_with_index.map do |node, i|
          ArchiveTimeStampCheck.new(node, [*path, [NS141, "ArchiveTimeStamp", i]],
                                    references: references, node_set_references: node_set,
                                    element_paths: ArchiveTimeStampCheck.element_paths(signature, qualifying,
                                                                                       properties, node, path),
                                    ns: { "ds" => HankoXml::NS["ds"], "xades" => NS },
                                    policy: @policy, tsa_store: @tsa_store).verify(xml_bytes, index)
        end
      end

      # Each SignedInfo Reference's data as xmlsec digested it, verifying the
      # signature again with the key that verified it.
      def reference_data(verification, xml_bytes, index)
        octets = Native.reference_data(xml_bytes, [verification.certificate.public_key.to_pem], native_id_attributes,
                                       index, @referenced_documents.to_a, @policy.allows?(:transform, :xpath_filter2))
        fail!("a Reference's data could not be read for the ArchiveTimeStamp") if octets.any?(&:nil?)

        octets
      rescue HankoXml::NativeError
        fail!("the signature's Reference data could not be read for the ArchiveTimeStamp")
      end

      # The SignatureTimeStamp elements, the native path to their parent, and
      # their XAdES namespace.
      def signature_timestamp_nodes(signature)
        qualifying, ns = Locator.qualifying_properties(signature)
        properties = Locator.unsigned_signature_properties(qualifying, ns)
        return [[], nil] unless properties

        timestamps = properties.xpath("xades:SignatureTimeStamp", ns)
        if timestamps.any? && ns["xades"] != NS
          fail!("SignatureTimeStamp is verified only in the XAdES 1.3.2 namespace")
        end

        [timestamps.to_a, Locator.unsigned_path(signature, qualifying, ns["xades"]), ns["xades"]]
      end

      def coerce_long_term(value)
        value = @timestamps == :ignore ? :ignore : :verify if value.nil?
        unless LONG_TERM_MODES.include?(value)
          raise HankoXml::ConfigurationError, "long_term: must be one of #{LONG_TERM_MODES.inspect}"
        end
        if value != :ignore && @timestamps == :ignore
          raise HankoXml::ConfigurationError,
                "long_term: #{value.inspect} needs SignatureTimeStamps for its validation time; " \
                "it cannot go with timestamps: :ignore"
        end
        if value == :require && @tsa_store.nil?
          raise HankoXml::ConfigurationError, "long_term: :require needs tsa_store: or tsa_certificates:"
        end

        value
      end

      def coerce_revocation_grace(value)
        return value if value.is_a?(Numeric) && value >= 0

        raise HankoXml::ConfigurationError, "revocation_grace: must be a number of seconds, 0 or more"
      end

      def coerce_timestamps(value)
        return value if TIMESTAMP_MODES.include?(value)

        raise HankoXml::ConfigurationError, "timestamps: must be one of #{TIMESTAMP_MODES.inspect}"
      end

      # The TSA trust, separate from the signer's: tsa_store: as given, or a
      # store over tsa_certificates:.
      def coerce_tsa_store(store, certificates)
        raise HankoXml::ConfigurationError, "pass tsa_store: or tsa_certificates:, not both" if store && certificates

        if @timestamps == :require && !store && !certificates
          raise HankoXml::ConfigurationError, "timestamps: :require needs tsa_store: or tsa_certificates:"
        end
        return tsa_store_from(certificates) if store.nil?
        return store if store.is_a?(OpenSSL::X509::Store)

        raise HankoXml::ConfigurationError, "tsa_store: must be an OpenSSL::X509::Store"
      end

      def tsa_store_from(certificates)
        return nil if certificates.nil?

        list = Array(certificates)
        raise HankoXml::ConfigurationError, "tsa_certificates: must not be empty" if list.empty?

        OpenSSL::X509::Store.new.tap do |store|
          list.each do |certificate|
            key = HankoXml::Key.coerce(certificate)
            raise HankoXml::ConfigurationError, "tsa_certificates: must be X.509 certificates" unless key.certificate?

            store.add_cert(key.to_openssl)
          end
        end
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
        qualifying, ns = Locator.qualifying_properties(verification.signature_node)

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

      # By its Type, or, with no Type (as some 1.2.2 signatures write it), by
      # what xmlsec resolved and digested: a SignedProperties element in a
      # XAdES namespace. Never by the URI text (#86).
      def signed_properties_reference?(info, reference)
        return info.type == SIGNED_PROPERTIES_TYPE || VERSIONED_SIGNED_PROPERTIES_TYPES.key?(info.type) if info.type

        node = reference.node
        !node.nil? && node.name == "SignedProperties" && NAMESPACES.include?(node.namespace&.href)
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

      # The XML-DSig verification of an XAdES-LT signature (#168): embedded
      # certificates may complete the store: chain, never be its anchor or
      # its signing certificate.
      #
      # @api private
      class AtTime < Verifier
        def initialize(intermediates:, **options)
          @intermediates = intermediates
          super(**options)
        end

        private

        def chain_intermediates
          @intermediates
        end
      end
    end
  end
end
