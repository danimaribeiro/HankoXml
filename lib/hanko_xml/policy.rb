# frozen_string_literal: true

module HankoXml
  # A frozen allowlist, enforced in Ruby before anything reaches
  # libxmlsec1, on both signing and verification. See API_CONTRACT.md §5.8.
  class Policy
    FIELDS = %i[
      signature_methods digest_methods canonicalization_methods transforms
      allow_external_references allow_retrieval_method allow_same_document_xpointer
      max_references require_references
      require_signed_root reject_duplicate_ids max_document_size max_transforms_per_reference
      min_rsa_key_bits min_ec_key_bits allow_hmac check_certificate_validity clock_skew
      schema
    ].freeze

    STRICT_DEFAULTS = {
      signature_methods: %i[rsa_sha256 rsa_sha384 rsa_sha512 ecdsa_sha256 ecdsa_sha384 ecdsa_sha512],
      digest_methods: %i[sha256 sha384 sha512],
      canonicalization_methods: %i[c14n exc_c14n c14n11 c14n_with_comments exc_c14n_with_comments],
      transforms: %i[enveloped_signature base64 c14n exc_c14n c14n11 c14n_with_comments
                     exc_c14n_with_comments],

      allow_external_references: false,
      allow_retrieval_method: false,
      allow_same_document_xpointer: false,
      max_references: 8,
      require_references: true,

      require_signed_root: true,
      reject_duplicate_ids: true,
      max_document_size: 16 * 1024 * 1024,
      max_transforms_per_reference: 4,

      min_rsa_key_bits: 2048,
      min_ec_key_bits: 256,
      allow_hmac: false,
      check_certificate_validity: true,
      clock_skew: 60,

      schema: :default
    }.freeze

    attr_reader(*FIELDS)

    def initialize(**overrides)
      unknown = overrides.keys - FIELDS
      raise ArgumentError, "unknown Policy field(s): #{unknown.inspect}" unless unknown.empty?

      values = STRICT_DEFAULTS.merge(overrides)
      FIELDS.each { |f| instance_variable_set(:"@#{f}", values[f]) }
      freeze
    end

    def with(**overrides)
      self.class.new(**to_h.merge(overrides))
    end

    def to_h
      FIELDS.each_with_object({}) { |f, h| h[f] = public_send(f) }
    end

    class << self
      def strict
        @strict ||= new
      end

      # strict, minus require_signed_root -- for protocols that sign a
      # fragment (SAML assertions).
      def fragment
        @fragment ||= strict.with(require_signed_root: false)
      end

      # strict + SHA-1 digest and RSA-SHA1 signature.
      def legacy_sha1
        @legacy_sha1 ||= strict.with(
          digest_methods: strict.digest_methods + [:sha1],
          signature_methods: strict.signature_methods + [:rsa_sha1]
        )
      end

      # Everything libxmlsec1 supports. Documented as unsafe.
      def permissive
        @permissive ||= new(
          signature_methods: Algorithms.signature.names,
          digest_methods: Algorithms.digest.names,
          canonicalization_methods: Algorithms.canonicalization.names,
          transforms: Algorithms.transform.names,
          allow_external_references: true,
          allow_retrieval_method: true,
          allow_same_document_xpointer: true,
          max_references: Float::INFINITY,
          require_references: false,
          require_signed_root: false,
          reject_duplicate_ids: false,
          max_document_size: Float::INFINITY,
          max_transforms_per_reference: Float::INFINITY,
          min_rsa_key_bits: 0,
          min_ec_key_bits: 0,
          allow_hmac: true,
          check_certificate_validity: false,
          clock_skew: 0,
          schema: nil
        )
      end
    end

    # Validates +signature_info+ (a SignatureInfo) against this policy.
    # Returns an Array<HankoXml::PolicyError>, empty when compliant. Never
    # raises for a policy violation -- that is #enforce!'s job.
    def violations(signature_info)
      errors = []

      errors << algorithm_violation(:signature, signature_methods, signature_info.signature_method,
                                    "signature_methods")
      errors << algorithm_violation(:canonicalization, canonicalization_methods,
                                    signature_info.canonicalization_method, "canonicalization_methods")

      if require_references && signature_info.references.empty?
        errors << HankoXml::PolicyError.new(
          "this policy requires at least one <Reference>, but <SignedInfo> has none " \
          "(require_references)"
        )
      end

      if signature_info.references.size > max_references
        errors << HankoXml::PolicyError.new(
          "<SignedInfo> has #{signature_info.references.size} references, more than this " \
          "policy's max_references (#{max_references})"
        )
      end

      signature_info.references.each do |ref|
        errors << algorithm_violation(:digest, digest_methods, ref.digest_method, "digest_methods",
                                      reference_uri: ref.uri)

        if ref.transforms.size > max_transforms_per_reference
          errors << HankoXml::PolicyError.new(
            "reference #{ref.uri.inspect} has #{ref.transforms.size} transforms, more than this " \
            "policy's max_transforms_per_reference (#{max_transforms_per_reference})"
          )
        end

        ref.transforms.each do |transform_uri|
          errors << algorithm_violation(:transform, transforms, transform_uri, "transforms",
                                        reference_uri: ref.uri)
        end

        next unless !allow_external_references && ref.external?

        errors << HankoXml::PolicyError.new(
          "reference URI #{ref.uri.inspect} is external, and allow_external_references is false"
        )
      end

      errors.compact
    end

    # Raises HankoXml::PolicyError (with all violations joined into the
    # message) if +signature_info+ violates this policy.
    def enforce!(signature_info)
      errors = violations(signature_info)
      return if errors.empty?

      raise HankoXml::PolicyError, errors.map(&:message).join("; ")
    end

    private

    def algorithm_violation(slot, allowlist, uri_or_name, field_name, reference_uri: nil)
      return nil if uri_or_name.nil?

      allowed = allowlist.any? do |allowed_entry|
        Algorithms.uri_for(slot, allowed_entry) == Algorithms.uri_for(slot, uri_or_name)
      end
      return nil if allowed

      name = Algorithms.name_for(slot, uri_or_name)
      location = reference_uri ? " on reference #{reference_uri.inspect}" : ""

      HankoXml::PolicyError.new(
        "#{slot} method #{uri_or_name}#{name ? " (#{name.inspect})" : ""}#{location} is not in " \
        "this policy's #{field_name}. Use a preset such as HankoXml::Policy.legacy_sha1 or " \
        "Policy#with(#{field_name}: …) if this document genuinely requires it."
      )
    end
  end
end
