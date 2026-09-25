# frozen_string_literal: true

module HankoXml
  # The result of a signature verification attempt.
  # Provides methods to inspect which nodes were actually signed, defending against
  # XML Signature Wrapping (XSW) attacks.
  # See API_CONTRACT.md §5.4.
  class Verification # rubocop:disable Metrics/ClassLength
    # Details about a specific `<Reference>` inside the verified signature.
    Reference = Struct.new(:uri, :node, :digest_method, :transforms, :valid?, :errors, keyword_init: true) do
      # @return [Boolean] True if the reference uses the enveloped-signature transform.
      def enveloped?
        transforms.include?(:enveloped_signature)
      end
    end

    attr_reader :valid,
      :errors,
      :signature_info,
      :signature_node,
      :document,
      :certificate,
      :id_attributes,
      :resolver,
      :references,
      :reference_element_indexes,
      :reference_valid,
      :namespaces

    def initialize(
      valid:,
      errors:,
      signature_info:,
      signature_node:,
      document:,
      certificate: nil,
      id_attributes: %w[Id ID id],
      resolver: nil,
      reference_element_indexes: nil,
      reference_valid: nil,
      namespaces: {}
    )
      @valid = valid
      @errors = errors.dup
      @signature_info = signature_info
      @signature_node = signature_node
      @document = document
      @certificate = certificate
      @id_attributes = (id_attributes || []).dup.freeze
      @resolver = resolver
      @namespaces = (namespaces || {}).transform_keys(&:to_s).freeze
      # Native.verify returns document-order element indexes from libxml2's ID
      # table (the same table xmlsec used for `#id`). When present, those are
      # authoritative for #references[].node / #signed? — Ruby does not
      # re-resolve IDs (issues #28 / #34 / S-03).
      @reference_element_indexes = reference_element_indexes&.dup&.freeze
      # Native.verify's per-Reference digest status (S-09) -- authoritative
      # when present. See #reference_valid_for.
      @reference_valid = reference_valid&.dup&.freeze
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
    # Registry names (:rsa_sha256), as API_CONTRACT.md §5.4 shows, or the URI
    # String for an algorithm the registry does not know (#96).
    def signature_method
      signature_info && (signature_info.signature_method_name || signature_info.signature_method)
    end

    def canonicalization_method
      signature_info && (signature_info.canonicalization_method_name || signature_info.canonicalization_method)
    end

    def digest_methods
      # nil signature_info: a verification that failed before inspection (#94).
      return [] unless signature_info

      signature_info.references.map { |ref| ref.digest_method_name || ref.digest_method }
    end

    def signed_nodes
      # Same rule as #signed?: nothing is covered unless the signature held (#91).
      return [] unless valid?

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
      return false unless valid?

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

    # +ns+ is merged over the Verifier's +namespaces:+, which is merged over
    # HankoXml::NS, so +ds:+ is always bound (#96).
    def at_signed(xpath, ns = {})
      node = document.at_xpath(xpath, xpath_namespaces(ns))
      raise HankoXml::NotSignedError, "No node found" unless node

      raise HankoXml::NotSignedError, "Node is not signed" unless signed?(node)

      node
    end

    def signed(xpath, ns = {})
      nodes = document.xpath(xpath, xpath_namespaces(ns)).to_a
      raise HankoXml::NotSignedError, "Some nodes are not signed" unless nodes.all? { |n| signed?(n) }

      nodes
    end

    private

    def xpath_namespaces(ns)
      HankoXml::NS.merge(namespaces).merge((ns || {}).transform_keys(&:to_s))
    end

    def build_references
      return [] unless signature_info

      signature_info.references.map.with_index do |ref, index|
        target_node = resolve_reference(ref, index)

        Reference.new(
          uri: ref.uri,
          node: target_node,
          digest_method: ref.digest_method_name,
          transforms: ref.transform_names,
          valid?: reference_valid_for(index),
          errors: reference_errors_for(ref, index)
        ).freeze
      end
    end

    # Native.verify reports each SignedInfo Reference's own digest status,
    # independent of the overall signature/key outcome (S-09): a
    # harmless-fragment Reference and the payload Reference can genuinely
    # disagree, so "the whole signature is valid" cannot stand in for "this
    # Reference's digest matched". Falls back to the overall result only when
    # there is no real per-reference answer -- a Verification built directly
    # (specs, error paths that never reached crypto) or a reference xmlsec
    # never got to because verification aborted earlier.
    def reference_valid_for(index)
      return valid? unless @reference_valid

      status = @reference_valid[index]
      status.nil? ? valid? : status
    end

    # A DigestMismatch only when xmlsec itself reported this Reference's
    # digest as wrong; the fallback in #reference_valid_for proves nothing
    # about one Reference (#96). The URI is document text, so it goes in
    # #reference_uri, not the message.
    def reference_errors_for(ref, index)
      return [] unless @reference_valid && @reference_valid[index] == false

      [HankoXml::DigestMismatch.new("a <Reference>'s digest does not match", reference_uri: ref.uri).freeze]
    end

    # When Native.verify supplied element indexes, those are the authority.
    # A caller-supplied resolver: may only *agree* with them — disagreement is
    # ResolutionMismatch (API_CONTRACT §5.9). Without native indexes (unit tests
    # that construct Verification directly), fall back to resolver / id_attributes.
    def detect_resolution_mismatches!
      return unless resolver

      return unless signature_info

      signature_info.references.each_with_index do |ref, index|
        next unless ref.uri&.start_with?("#")

        id = ref.uri[1..]
        resolver_node = resolver.call(document, id)
        expected = if reference_element_indexes
          node_at_element_index(reference_element_indexes[index])
        elsif !id_attributes.empty?
          resolve_by_id_attributes(id)
        else
          next
        end

        record_resolution_mismatch(id) unless same_node?(resolver_node, expected)
      end
    end

    def record_resolution_mismatch(id)
      @errors <<
        HankoXml::ResolutionMismatch.new("resolver and xmlsec ID resolution disagree on the target of \"##{id}\"")
      @valid = false
    end

    def same_node?(left, right)
      return true if left.nil? && right.nil?

      return false if left.nil? || right.nil?

      left == right
    end

    def resolve_reference(ref, index)
      return node_at_element_index(reference_element_indexes[index]) if reference_element_indexes

      # Fallback for Verification constructed without a Native.verify result
      # (specs / error paths that never reached crypto).
      if ref.uri.nil? || ref.uri.empty?
        document.root
      elsif ref.uri.start_with?("#")
        resolve_fragment_reference(ref.uri[1..])
      end
    end

    def node_at_element_index(index)
      return nil if index.nil?

      document.xpath("//*")[index]
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
