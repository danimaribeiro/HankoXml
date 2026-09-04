# frozen_string_literal: true

module HankoXml
  # The result of a signature verification attempt.
  # Provides methods to inspect which nodes were actually signed, defending against
  # XML Signature Wrapping (XSW) attacks.
  # See API_CONTRACT.md §5.4.
  class Verification
    # Details about a specific `<Reference>` inside the verified signature.
    Reference = Struct.new(:uri, :node, :digest_method, :transforms, :valid?, :errors, keyword_init: true) do
      # @return [Boolean] True if the reference uses the enveloped-signature transform.
      def enveloped?
        transforms.include?(:enveloped_signature)
      end
    end

    attr_reader :valid, :errors, :signature_info, :signature_node, :document, :certificate, :id_attributes, :resolver,
                :references

    def initialize(valid:, errors:, signature_info:, signature_node:, document:, certificate: nil,
                   id_attributes: %w[Id ID id], resolver: nil)
      @valid = valid
      @errors = errors.dup
      @signature_info = signature_info
      @signature_node = signature_node
      @document = document
      @certificate = certificate
      @id_attributes = (id_attributes || []).dup.freeze
      @resolver = resolver
      # Resolution must happen, and #errors/#valid must be able to react to it
      # (see detect_resolution_mismatches!), before we freeze below -- the object
      # is immutable from here on, so #references can't be computed lazily on
      # first access the way it used to be.
      @references = build_references
      detect_resolution_mismatches!
      @errors.freeze
      freeze
    end

    # @return [Boolean] True if the signature is completely valid.
    def valid?
      @valid
    end

    # --- Authenticated metadata ---
    def signature_method
      signature_info&.signature_method
    end

    def canonicalization_method
      signature_info&.canonicalization_method
    end

    def digest_methods
      signature_info.references.map(&:digest_method_name)
    end

    def signed_nodes
      # For each reference, get the nodes it covers
      nodes = []
      references.each do |ref|
        next unless ref.node

        # A reference covers the node and all its descendants.
        # But if it's enveloped, it excludes the signature itself.
        nodes << ref.node
      end
      nodes
    end

    def signed?(node)
      # True if the node is equal to or a descendant of any reference's target node,
      # EXCEPT if it is equal to or a descendant of the signature_node (and the reference is enveloped).
      references.any? do |ref|
        next false unless ref.node

        is_covered = node.ancestors.include?(ref.node) || node == ref.node
        if is_covered && ref.enveloped?
          is_excluded = node.ancestors.include?(signature_node) || node == signature_node
          !is_excluded
        else
          is_covered
        end
      end
    end

    def covers_root?
      signed?(document.root)
    end

    def partial?
      !covers_root?
    end

    def at_signed(xpath, ns = {})
      node = document.at_xpath(xpath, ns)
      raise HankoXml::NotSignedError, "No node found" unless node
      raise HankoXml::NotSignedError, "Node is not signed" unless signed?(node)

      node
    end

    def signed(xpath, ns = {})
      nodes = document.xpath(xpath, ns).to_a
      raise HankoXml::NotSignedError, "Some nodes are not signed" unless nodes.all? { |n| signed?(n) }

      nodes
    end

    private

    def build_references
      return [] unless signature_info

      signature_info.references.map do |ref|
        target_node = resolve_reference(ref)

        # For now, we assume if the overall signature is valid, the reference is valid.
        # xmlsec1 doesn't tell us which reference failed in the struct yet, but we can look at the errors array.
        ref_valid = valid? # Approximation for Phase 3

        Reference.new(
          uri: ref.uri,
          node: target_node,
          digest_method: ref.digest_method_name,
          transforms: ref.transform_names,
          valid?: ref_valid,
          errors: []
        ).freeze
      end
    end

    # A caller-supplied resolver: only replaces what Verification itself uses to
    # locate a node (#references[].node, #signed?) -- it never reaches
    # Native.verify, which resolves "#id" via id_attributes through xmlsec's own
    # ID table. If the two disagree, #signed?(node) could be true for a node
    # xmlsec never actually verified. Only checked when id_attributes is
    # non-empty: an empty id_attributes: means "the native side isn't matching
    # by ID attribute either", so there is no native-side resolution to compare
    # the resolver against.
    def detect_resolution_mismatches!
      return unless resolver
      return if id_attributes.empty?
      return unless signature_info

      signature_info.references.each do |ref|
        next unless ref.uri&.start_with?("#")

        id = ref.uri[1..]
        record_resolution_mismatch(id) unless same_node?(resolver.call(document, id), resolve_by_id_attributes(id))
      end
    end

    def record_resolution_mismatch(id)
      @errors << HankoXml::ResolutionMismatch.new(
        "resolver and id_attributes disagree on the target of \"##{id}\""
      )
      @valid = false
    end

    def same_node?(resolver_node, id_attributes_node)
      return true if resolver_node.nil? && id_attributes_node.nil?
      return false if resolver_node.nil? || id_attributes_node.nil?

      resolver_node == id_attributes_node
    end

    # External references fall through to nil: they are not resolved by default.
    def resolve_reference(ref)
      if ref.uri.nil? || ref.uri.empty?
        document.root
      elsif ref.uri.start_with?("#")
        resolve_fragment_reference(ref.uri[1..])
      end
    end

    def resolve_fragment_reference(id)
      return resolver.call(document, id) if resolver

      resolve_by_id_attributes(id)
    end

    def resolve_by_id_attributes(id)
      predicates = []
      bindings = { id: id }

      id_attributes.each_with_index do |attr, index|
        name_key = :"attr_name_#{index}"
        if attr.is_a?(Array) && attr.size == 2
          ns_key = :"attr_ns_#{index}"
          bindings[name_key] = attr[1].to_s
          bindings[ns_key] = attr[0].to_s
          predicates << "@*[local-name()=$#{name_key} and namespace-uri()=$#{ns_key} and .=$id]"
        else
          bindings[name_key] = attr.to_s
          predicates << "@*[local-name()=$#{name_key} and namespace-uri()='' and .=$id]"
        end
      end

      return nil if predicates.empty?

      document.at_xpath("//*[(#{predicates.join(" or ")})]", nil, bindings)
    end
  end
end
