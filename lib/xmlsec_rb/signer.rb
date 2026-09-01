# frozen_string_literal: true

module XmlsecRb
  # Declares the parts of a signature -- references, transforms, KeyInfo
  # clauses, placement -- and builds the <Signature> template from them.
  # See API_CONTRACT.md §5.2.
  #
  # A Signer is frozen after construction: immutable, reusable, safe to
  # share across threads.
  #
  # Phase 1 implements everything needed to inspect what a Signer would
  # produce (#template, #to_h). Actually signing (#sign / #sign!) needs the
  # native rewrite (§14 Phase 2/3) and is not implemented yet.
  class Signer
    TEMPLATE_MODES = %i[adopt build require].freeze

    attr_accessor :key, :certificate, :certificates, :signature_method, :canonicalization_method,
                  :digest_method, :references, :placement, :id_attributes, :namespaces,
                  :signature_id, :policy
    attr_reader :template_mode

    def initialize(key:, certificate: nil, certificates: nil, signature_method: :rsa_sha256,
                   canonicalization_method: :exc_c14n, digest_method: :sha256, references: [],
                   key_info: [:x509_certificate], placement: :append_to_root,
                   id_attributes: %w[Id ID id], namespaces: {}, signature_id: nil,
                   policy: XmlsecRb::Policy.strict, template: :adopt)
      unless key.is_a?(XmlsecRb::Key) || Dom.pkey?(key) || key.is_a?(String) ||
             key.respond_to?(:to_path)
        raise XmlsecRb::ConfigurationError,
              "key: must be key material or an XmlsecRb::Key (external signers are not supported " \
              "in v1 -- see API_CONTRACT.md §5.2)"
      end

      unless TEMPLATE_MODES.include?(template.to_sym)
        raise XmlsecRb::ConfigurationError, "template: must be one of #{TEMPLATE_MODES.inspect}"
      end

      @key = XmlsecRb::Key.coerce(key)
      @certificate = certificate && XmlsecRb::Key.coerce(certificate)
      @certificates = Array(certificates).map { |c| XmlsecRb::Key.coerce(c) }
      @signature_method = signature_method
      @canonicalization_method = canonicalization_method
      @digest_method = digest_method
      @references = Array(references).map { |r| XmlsecRb::Reference.coerce(r) }
      @key_info = XmlsecRb::KeyInfo.coerce(key_info)
      @placement = XmlsecRb::Placement.coerce(placement) || XmlsecRb::Placement.append_to_root
      @id_attributes = id_attributes
      @namespaces = namespaces
      @signature_id = signature_id
      @policy = policy
      @template_mode = template.to_sym

      yield self if block_given?

      freeze
    end

    # Adds a Reference. Block form only -- see API_CONTRACT.md §5.2.
    def reference(uri = "", **kwargs)
      references << XmlsecRb::Reference.new(uri: uri, **kwargs)
    end

    # With no args, the current KeyInfo clauses. With args, replaces them --
    # block-form usage per API_CONTRACT.md §5.2 (`s.key_info :x509_certificate`).
    def key_info(*clauses)
      return @key_info if clauses.empty?

      @key_info = XmlsecRb::KeyInfo.coerce(clauses.flatten)
    end

    # The unsigned <Signature> Nokogiri::XML::Element this Signer would
    # build and insert, given its current configuration. Does not insert
    # it into +doc_or_xml+ and performs no cryptography -- for inspection
    # and testing (§5.2).
    def template(doc_or_xml)
      doc = XmlsecRb.coerce_document(doc_or_xml)
      XmlsecRb::Template.build(doc, self)
    end

    def to_h
      {
        key: key, certificate: certificate, certificates: certificates,
        signature_method: signature_method, canonicalization_method: canonicalization_method,
        digest_method: digest_method, references: references, key_info: key_info,
        placement: placement, id_attributes: id_attributes, namespaces: namespaces,
        signature_id: signature_id, policy: policy, template: template_mode
      }
    end

    def sign(_doc_or_xml)
      raise NotImplementedError,
            "XmlsecRb::Signer#sign needs the native rewrite (API_CONTRACT.md §14 Phase 2/3), " \
            "not yet implemented. Use #template to inspect what would be built."
    end

    def sign!(_doc)
      raise NotImplementedError,
            "XmlsecRb::Signer#sign! needs the native rewrite (API_CONTRACT.md §14 Phase 2/3), " \
            "not yet implemented. Use #template to inspect what would be built."
    end

    def inspect
      "#<#{self.class} key=[FILTERED] signature_method=#{signature_method.inspect} " \
        "canonicalization_method=#{canonicalization_method.inspect} digest_method=#{digest_method.inspect} " \
        "references=#{references.size}>"
    end
  end
end
