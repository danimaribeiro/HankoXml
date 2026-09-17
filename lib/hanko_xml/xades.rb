# frozen_string_literal: true

require "openssl"
require "securerandom"
require "time"

module HankoXml
  # XAdES (ETSI EN 319 132-1) baseline signatures: XML-DSig plus signed
  # qualifying properties. Only structure lives here. xmlsec digests the
  # SignedProperties Reference and signs, exactly as for any other same-document
  # Reference. See API_CONTRACT.md §12 and docs/src/content/guide/comparison-signxml.md.
  module Xades
    NS = "http://uri.etsi.org/01903/v1.3.2#"
    # The Reference Type that marks the Reference over <xades:SignedProperties>.
    SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties"

    # <xades:SignaturePolicyIdentifier>: the policy document's identifier (an
    # OID URN or URI) and the digest of that document.
    SignaturePolicy = Struct.new(:identifier, :digest_value, :digest_method, :description, keyword_init: true) do
      def initialize(identifier:, digest_value:, digest_method: :sha256, description: nil)
        begin
          digest_value.to_s.unpack1("m0")
        rescue ArgumentError
          raise HankoXml::ConfigurationError,
                "signature_policy digest_value: must be Base64 (the policy document's digest)"
        end

        super
        freeze
      end
    end

    # <xades:DataObjectFormat> for the signed data.
    DataObjectFormat = Struct.new(:mime_type, :description, :encoding, keyword_init: true) do
      def initialize(mime_type: nil, description: nil, encoding: nil)
        if [mime_type, description, encoding].all?(&:nil?)
          raise HankoXml::ConfigurationError, "data_object_format: needs a mime_type:, description: or encoding:"
        end

        super
        freeze
      end
    end

    # A {HankoXml::Signer} that produces XAdES-B (baseline) signatures (#57).
    #
    # On top of the Signer's own references it adds a <ds:Object> holding
    # <xades:QualifyingProperties>, and a Reference over its
    # <xades:SignedProperties>: SigningTime, SigningCertificateV2 (digest of
    # certificate:), and optionally SignaturePolicyIdentifier, SignerRoleV2
    # and DataObjectFormat.
    #
    # Always builds a new <Signature> (template: :build). Timestamps and
    # validation data (XAdES-T/LT/LTA) are separate: #81, #82.
    class Signer < HankoXml::Signer
      attr_reader :signing_time, :signature_policy, :claimed_roles, :data_object_format

      # @param certificate [Key, OpenSSL::X509::Certificate, String, Pathname] Required: SigningCertificateV2
      #   commits to it.
      # @param signing_time [Time, nil] The SigningTime to sign; nil means the time #sign runs.
      # @param signature_policy [SignaturePolicy, Hash, :implied, nil] SignaturePolicyIdentifier, if any.
      # @param claimed_roles [Array<String>] SignerRoleV2/ClaimedRoles.
      # @param data_object_format [DataObjectFormat, Hash, nil] Describes the signed data; applies to each
      #   of this Signer's own references, which get an Id when they have none.
      # @param signature_id [String, nil] The <Signature> Id; generated when nil, since QualifyingProperties
      #   targets it.
      # All other keywords are {HankoXml::Signer}'s.
      def initialize(certificate: nil, signing_time: nil, signature_policy: nil, claimed_roles: [],
                     data_object_format: nil, signature_id: nil, template: :build, **options, &block)
        unless template.to_sym == :build
          raise HankoXml::ConfigurationError,
                "template: #{template.inspect} is not supported for XAdES; it always builds a new <Signature>"
        end
        if signing_time && !signing_time.respond_to?(:utc)
          raise HankoXml::ConfigurationError, "signing_time: must be a Time, got #{signing_time.class}"
        end

        @signing_time = signing_time&.dup&.utc&.freeze
        @signature_policy = coerce_signature_policy(signature_policy)
        @claimed_roles = Array(claimed_roles).map { |role| role.to_s.dup.freeze }.freeze
        @data_object_format = coerce_data_object_format(data_object_format)

        super(certificate: certificate, signature_id: signature_id || "xades-#{SecureRandom.hex(8)}",
              template: :build, **options, &block)
      end

      # This Signer's own references (the whole document when it has none),
      # then the Reference over SignedProperties.
      def references
        own = super
        own = [HankoXml::Reference.new(uri: "", digest_method: digest_method)] if own.empty?
        own = own.each_with_index.map { |ref, i| with_id(ref, i) } if data_object_format
        [*own, signed_properties_reference]
      end

      # The <Signature> the Signer would build, with <xades:QualifyingProperties>.
      def template(doc_or_xml)
        signature = super
        signature.add_child(QualifyingProperties.new(signature, self).build)
        signature
      end

      def signed_properties_id
        "#{signature_id}-signedprops"
      end

      private

      def signed_properties_reference
        HankoXml::Reference.new(uri: "##{signed_properties_id}", type: SIGNED_PROPERTIES_TYPE,
                                transforms: [:exc_c14n], digest_method: digest_method)
      end

      def with_id(ref, index)
        return ref if ref.id

        HankoXml::Reference.new(uri: ref.uri, transforms: ref.transforms, digest_method: ref.digest_method,
                                id: "#{signature_id}-ref-#{index}", type: ref.type)
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

      def coerce_data_object_format(value)
        case value
        when nil, DataObjectFormat then value
        when Hash then DataObjectFormat.new(**value)
        else
          raise HankoXml::ConfigurationError,
                "data_object_format: must be a Xades::DataObjectFormat, a Hash of its keywords or nil"
        end
      end

      # Checked with the key material, after the block may have set certificate:.
      def check_key_material!
        super
        return if certificate.is_a?(HankoXml::Key) && certificate.certificate?

        raise HankoXml::ConfigurationError, "XAdES needs certificate:, which SigningCertificateV2 commits to"
      end
    end

    # Builds <ds:Object><xades:QualifyingProperties> for a <Signature> template.
    # Every node gets its namespace explicitly, so the caller's DOM (sign!)
    # answers XPath the same way a re-parse of the signed bytes would.
    class QualifyingProperties
      def initialize(signature, signer)
        @doc = signature.document
        @ds_namespace = signature.namespace
        @signer = signer
      end

      def build
        object = element("Object")
        qualifying = @doc.create_element("QualifyingProperties")
        object.add_child(qualifying)
        @xades_ns = qualifying.add_namespace_definition("xades", NS)
        qualifying.namespace = @xades_ns
        qualifying["Target"] = "##{@signer.signature_id}"
        signed = xades(qualifying, "SignedProperties")
        signed["Id"] = @signer.signed_properties_id

        build_signature_properties(xades(signed, "SignedSignatureProperties"))
        build_data_object_properties(signed) if @signer.data_object_format
        object
      end

      private

      def build_signature_properties(parent)
        xades(parent, "SigningTime").content = (@signer.signing_time || Time.now.utc).utc.xmlschema
        build_signing_certificate(xades(parent, "SigningCertificateV2"))
        build_signature_policy(parent) if @signer.signature_policy
        return if @signer.claimed_roles.empty?

        roles = xades(xades(parent, "SignerRoleV2"), "ClaimedRoles")
        @signer.claimed_roles.each { |role| xades(roles, "ClaimedRole").content = role }
      end

      def build_signing_certificate(parent)
        certificate = @signer.certificate.to_openssl
        cert = xades(parent, "Cert")
        digest(xades(cert, "CertDigest"), @signer.digest_method, certificate.to_der)
        xades(cert, "IssuerSerialV2").content = [issuer_serial_der(certificate)].pack("m0")
      end

      # RFC 5035 IssuerSerial: issuer as GeneralNames { directoryName [4] Name }.
      def issuer_serial_der(certificate)
        name = OpenSSL::ASN1.decode(certificate.issuer.to_der)
        general_names = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ASN1Data.new([name], 4, :CONTEXT_SPECIFIC)])
        OpenSSL::ASN1::Sequence([general_names, OpenSSL::ASN1::Integer(certificate.serial)]).to_der
      end

      def build_signature_policy(parent)
        identifier = xades(parent, "SignaturePolicyIdentifier")
        policy = @signer.signature_policy
        return xades(identifier, "SignaturePolicyImplied") if policy == :implied

        policy_id = xades(identifier, "SignaturePolicyId")
        sig_policy_id = xades(policy_id, "SigPolicyId")
        xades(sig_policy_id, "Identifier").content = policy.identifier
        xades(sig_policy_id, "Description").content = policy.description if policy.description
        hash = xades(policy_id, "SigPolicyHash")
        hash.add_child(digest_method_element(policy.digest_method))
        hash.add_child(element("DigestValue")).content = policy.digest_value
      end

      def build_data_object_properties(signed)
        properties = xades(signed, "SignedDataObjectProperties")
        format = @signer.data_object_format
        @signer.references.reject { |ref| ref.type == SIGNED_PROPERTIES_TYPE }.each do |ref|
          node = xades(properties, "DataObjectFormat")
          node["ObjectReference"] = "##{ref.id}"
          xades(node, "Description").content = format.description if format.description
          xades(node, "MimeType").content = format.mime_type if format.mime_type
          xades(node, "Encoding").content = format.encoding if format.encoding
        end
      end

      def digest(parent, digest_method, bytes)
        parent.add_child(digest_method_element(digest_method))
        algorithm = HankoXml::Algorithms.name_for(:digest, HankoXml::Algorithms.uri_for(:digest, digest_method))
        parent.add_child(element("DigestValue")).content = OpenSSL::Digest.new(algorithm.to_s).base64digest(bytes)
      end

      def digest_method_element(digest_method)
        element("DigestMethod").tap { |node| node["Algorithm"] = HankoXml::Algorithms.uri_for(:digest, digest_method) }
      end

      def xades(parent, name)
        node = @doc.create_element(name)
        parent.add_child(node)
        node.namespace = @xades_ns
        node
      end

      # An XML-DSig element, in the default namespace <Signature> declares.
      def element(name)
        @doc.create_element(name).tap { |node| node.namespace = @ds_namespace }
      end
    end
  end
end
