# frozen_string_literal: true

require "openssl"

module HankoXml
  # A frozen allowlist, enforced in Ruby before anything reaches
  # libxmlsec1, on both signing and verification. See API_CONTRACT.md §5.8.
  class Policy # rubocop:disable Metrics/ClassLength
    FIELDS = %i[
      signature_methods digest_methods canonicalization_methods transforms
      allow_external_references allow_retrieval_method allow_same_document_xpointer
      max_references require_references
      require_signed_root reject_duplicate_ids max_document_size max_transforms_per_reference
      min_rsa_key_bits min_ec_key_bits min_dsa_key_bits allow_hmac check_certificate_validity clock_skew
      require_signing_key_usage schema
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
      min_dsa_key_bits: 2048,
      allow_hmac: false,
      check_certificate_validity: true,
      clock_skew: 60,
      # store: only -- the signing certificate's KeyUsage, when present, must
      # allow digitalSignature or nonRepudiation (#63).
      require_signing_key_usage: true,

      schema: :default
    }.freeze

    attr_reader(*FIELDS)

    def initialize(**overrides)
      unknown = overrides.keys - FIELDS
      raise ArgumentError, "unknown Policy field(s): #{unknown.inspect}" unless unknown.empty?

      values = STRICT_DEFAULTS.merge(overrides)
      FIELDS.each { |f| instance_variable_set(:"@#{f}", values[f]) }
      @allowed_uris = snapshot_allowed_uris
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

      # fragment + what the W3C interop signatures (merlin-xmldsig-twenty-three,
      # phaos-xmldsig-three) need: SHA-1 with RSA or DSA, and 1024-bit RSA and
      # DSA keys.
      # For verifying legacy signatures from other implementations (#62), never
      # as a default. External references, RetrievalMethod, HMAC and
      # XPath/XSLT stay off, as in strict.
      def interop
        @interop ||= fragment.with(
          digest_methods: fragment.digest_methods + [:sha1],
          signature_methods: fragment.signature_methods + %i[rsa_sha1 dsa_sha1],
          min_rsa_key_bits: 1024,
          min_dsa_key_bits: 1024
        )
      end

      # Allows everything the Ruby checks cover. Documented as unsafe. The
      # native layer still refuses XPath/XSLT transforms (S-10) and reads an
      # external URI only from referenced_documents: (#74), whatever this says.
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
          min_dsa_key_bits: 0,
          allow_hmac: true,
          check_certificate_validity: false,
          clock_skew: 0,
          require_signing_key_usage: false,
          schema: nil
        )
      end
    end

    # Validates +signature_info+ (a SignatureInfo) against this policy.
    # Returns an Array<HankoXml::PolicyError>, empty when compliant. Never
    # raises for a policy violation -- that is #enforce!'s job.
    #
    # +signature_info+ alone is enough for every algorithm/structural check
    # (works without a DOM, per API_CONTRACT.md §6.1). The keyword
    # arguments are optional context that only Signer/Verifier -- which
    # always have a DOM and trust material -- can supply, for the handful
    # of fields that genuinely need it (S-06):
    #
    # @param document [Nokogiri::XML::Document, nil] enables
    #   +require_signed_root+ / +reject_duplicate_ids+.
    # @param sig_node [Nokogiri::XML::Node, nil] the `<Signature>` being
    #   checked, alongside +document+.
    # @param id_attributes [Array<String>, nil] the caller's `id_attributes:`,
    #   alongside +document+.
    # @param xml_bytes [String, nil] the serialized document, for
    #   +max_document_size+.
    # @param check_root_signed [Boolean] whether to apply
    #   +require_signed_root+ here. `require_signed_root` (API_CONTRACT.md
    #   §5.8.1) is a *verification*-time XSW defence -- it says nothing
    #   about what is legitimate to produce, so {Signer} deliberately signs
    #   a caller-chosen fragment (opted into via `references:`, R5) without
    #   tripping it; only {Verifier} checks it.
    # @param referenced_uris [Array<String>] URIs the caller serves through
    #   `referenced_documents:` (#74). An external reference to one of them
    #   is allowed whatever +allow_external_references+ says: it is read from
    #   the caller's map, never fetched.
    #
    # +min_rsa_key_bits+ / +min_ec_key_bits+ are not checked here -- they
    # need the actual signing/trust key material, which is only available
    # once Signer/Verifier have resolved it. See #enforce_key_size!.
    def violations(signature_info, document: nil, sig_node: nil, id_attributes: nil, xml_bytes: nil,
                   check_root_signed: true, referenced_uris: [])
      errors = []

      errors << algorithm_violation(:signature, signature_info.signature_method)
      errors << algorithm_violation(:canonicalization, signature_info.canonicalization_method)
      errors << hmac_violation(signature_info)
      errors << retrieval_method_violation(signature_info)

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

      errors.concat(reference_violations(signature_info.references, referenced_uris))
      errors << root_signed_violation(document, sig_node, signature_info, id_attributes) if check_root_signed
      errors << duplicate_id_violation(document, id_attributes)
      errors << document_size_violation(xml_bytes&.bytesize)

      errors.compact
    end

    # Raises HankoXml::PolicyError (with all violations joined into the
    # message) if +signature_info+ violates this policy. Accepts the same
    # optional context keywords as #violations.
    def enforce!(signature_info, document: nil, sig_node: nil, id_attributes: nil, xml_bytes: nil,
                 check_root_signed: true, referenced_uris: [])
      errors = violations(signature_info, document: document, sig_node: sig_node, id_attributes: id_attributes,
                                          xml_bytes: xml_bytes, check_root_signed: check_root_signed,
                                          referenced_uris: referenced_uris)
      return if errors.empty?

      raise HankoXml::PolicyError, errors.map(&:message).join("; ")
    end

    # Raises HankoXml::PolicyError if +bytesize+ exceeds
    # +max_document_size+. Separate from #enforce! so Signer/Verifier can
    # apply it before parsing and before any native call -- #enforce! needs
    # Native.inspect_sig output, which already means a native parse (S-12).
    # Raises HankoXml::PolicyError unless +uri_or_name+ is in this policy's
    # allowlist for +slot+ (:signature, :digest, :canonicalization,
    # :transform). For algorithms named outside <SignedInfo>, such as a XAdES
    # certificate digest.
    def enforce_algorithm!(slot, uri_or_name)
      error = algorithm_violation(slot, uri_or_name)
      raise error if error
    end

    def enforce_document_size!(bytesize)
      error = document_size_violation(bytesize)
      raise error if error
    end

    # Raises HankoXml::PolicyError if any of +keys+
    # (OpenSSL::PKey::PKey / OpenSSL::X509::Certificate) is smaller than
    # this policy's min_rsa_key_bits / min_ec_key_bits / min_dsa_key_bits (S-06). Separate from
    # #enforce! because the real signing/trust key is only known once
    # Signer/Verifier have resolved it (Signer's own key; Verifier's
    # resolved trust material) -- after SignatureInfo has already been
    # policy-checked.
    def enforce_key_size!(keys)
      errors = Array(keys).filter_map { |key| key_size_violation(key) }
      return if errors.empty?

      raise HankoXml::PolicyError, errors.map(&:message).join("; ")
    end

    private

    def reference_violations(references, referenced_uris)
      references.flat_map do |ref|
        errors = [
          algorithm_violation(:digest, ref.digest_method, reference_uri: ref.uri)
        ]

        if ref.transforms.size > max_transforms_per_reference
          errors << HankoXml::PolicyError.new(
            "reference #{ref.uri.inspect} has #{ref.transforms.size} transforms, more than this " \
            "policy's max_transforms_per_reference (#{max_transforms_per_reference})"
          )
        end

        ref.transforms.each do |transform_uri|
          errors << algorithm_violation(:transform, transform_uri, reference_uri: ref.uri)
        end

        if !allow_external_references && ref.external? && !referenced_uris.include?(ref.document_uri)
          errors << HankoXml::PolicyError.new(
            "reference URI #{ref.uri.inspect} is external, and allow_external_references is false"
          )
        end

        if !allow_same_document_xpointer && ref.same_document_xpointer?
          errors << HankoXml::PolicyError.new(
            "reference URI #{ref.uri.inspect} is a same-document XPointer, and " \
            "allow_same_document_xpointer is false"
          )
        end

        errors
      end
    end

    def hmac_violation(signature_info)
      return nil if allow_hmac

      name = Algorithms.name_for(:signature, signature_info.signature_method)
      return nil unless name.to_s.start_with?("hmac")

      HankoXml::PolicyError.new(
        "signature method #{signature_info.signature_method} (#{name.inspect}) is HMAC-based, " \
        "and allow_hmac is false"
      )
    end

    def retrieval_method_violation(signature_info)
      return nil if allow_retrieval_method
      return nil unless signature_info.retrieval_method?

      HankoXml::PolicyError.new(
        "<KeyInfo> contains a <RetrievalMethod>, and allow_retrieval_method is false"
      )
    end

    # Structural check: does any Reference cover the document root? Mirrors
    # the same "" == whole document convention `dsig.rs` and
    # `Verification#resolve_reference` already use, plus a bare `#id`
    # matching one of the root element's own id_attributes. This runs
    # before any cryptography -- it does not need (and does not wait for)
    # a real Verification#covers_root? (S-06).
    def root_signed_violation(document, sig_node, signature_info, id_attributes)
      return nil unless require_signed_root
      return nil if document.nil? || sig_node.nil? # no DOM context: cannot check, so don't fail closed here
      return nil if signature_info.references.any? { |ref| ref.uri.to_s.empty? }

      root_ids = root_id_values(document, id_attributes)
      return nil if signature_info.references.any? { |ref| ref.fragment? && root_ids.include?(ref.uri[1..]) }

      HankoXml::PolicyError.new(
        "this policy requires the root element to be signed (require_signed_root), but no " \
        "<Reference> covers it"
      )
    end

    def root_id_values(document, id_attributes)
      root = document.root
      return [] if root.nil? || id_attributes.nil?

      id_attributes.filter_map { |attr| root[attr.is_a?(Array) ? attr[1].to_s : attr.to_s] }
    end

    # Whole-document duplicate-ID scan (S-06). Deliberately as coarse as
    # xmlSecAddIDs itself (S-03): matches by unqualified attribute name
    # only, ignoring namespace.
    def duplicate_id_violation(document, id_attributes)
      return nil unless reject_duplicate_ids
      return nil if document.nil? || id_attributes.nil? || id_attributes.empty?

      names = id_attributes.map { |attr| attr.is_a?(Array) ? attr[1].to_s : attr.to_s }
      seen = Hash.new(0)
      document.traverse do |node|
        next unless node.element?

        names.each do |name|
          value = node[name]
          seen[value] += 1 if value
        end
      end
      return nil unless seen.any? { |_, count| count > 1 }

      HankoXml::PolicyError.new(
        "document has more than one element with the same ID attribute value, and " \
        "reject_duplicate_ids is true"
      )
    end

    def document_size_violation(bytesize)
      return nil if bytesize.nil?
      return nil if bytesize <= max_document_size

      HankoXml::PolicyError.new(
        "document is #{bytesize} bytes, more than this policy's max_document_size " \
        "(#{max_document_size})"
      )
    end

    def key_size_violation(key)
      kind, bits = key_bits(key)
      return nil if kind.nil?

      field = :"min_#{kind}_key_bits"
      minimum = public_send(field)
      return nil if bits >= minimum

      HankoXml::PolicyError.new("#{kind} key is #{bits} bits, less than this policy's #{field} (#{minimum})")
    end

    def key_bits(key)
      public_key = key.is_a?(::OpenSSL::X509::Certificate) ? key.public_key : key
      case public_key
      when ::OpenSSL::PKey::RSA
        [:rsa, public_key.n.num_bits]
      when ::OpenSSL::PKey::EC
        [:ec, public_key.group.degree]
      when ::OpenSSL::PKey::DSA
        [:dsa, public_key.p.num_bits]
      else
        [nil, nil]
      end
    end

    ALGORITHM_FIELDS = {
      signature: :signature_methods,
      digest: :digest_methods,
      canonicalization: :canonicalization_methods,
      transform: :transforms
    }.freeze
    private_constant :ALGORITHM_FIELDS

    # The allowlists resolved to URIs once, at construction (S-16), so a
    # later Algorithms.register cannot change what an existing Policy --
    # Policy.strict included -- accepts.
    def snapshot_allowed_uris
      ALGORITHM_FIELDS.to_h do |slot, field|
        uris = Array(public_send(field)).filter_map { |entry| Algorithms.uri_for(slot, entry) }
        [slot, uris.to_h { |uri| [uri, true] }.freeze]
      end.freeze
    end

    def algorithm_violation(slot, uri_or_name, reference_uri: nil)
      return nil if uri_or_name.nil?

      field_name = ALGORITHM_FIELDS.fetch(slot)

      # A String from the document is compared verbatim: resolving it through
      # the registry would let Algorithm="sha256" stand in for the real URI.
      candidate = uri_or_name.is_a?(String) ? uri_or_name : Algorithms.uri_for(slot, uri_or_name)
      return nil if @allowed_uris.fetch(slot).key?(candidate)

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
