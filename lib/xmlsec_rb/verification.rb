# frozen_string_literal: true

module XmlsecRb
  class Verification
    Reference = Struct.new(:uri, :node, :digest_method, :transforms, :valid?, :errors, keyword_init: true) do
      def enveloped?
        transforms.include?(:enveloped_signature)
      end
    end

    attr_reader :valid, :errors, :signature_info, :signature_node, :document, :certificate

    def initialize(valid:, errors:, signature_info:, signature_node:, document:, certificate: nil)
      @valid = valid
      @errors = errors
      @signature_info = signature_info
      @signature_node = signature_node
      @document = document
      @certificate = certificate
      freeze
    end

    def valid?
      @valid
    end

    # --- Authenticated metadata ---
    def signature_method
      signature_info.signature_method_name
    end

    def canonicalization_method
      signature_info.canonicalization_method_name
    end

    def digest_methods
      signature_info.references.map(&:digest_method_name)
    end

    def references
      @references ||= signature_info.references.map do |ref|
        # Resolve the node
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
      raise XmlsecRb::NotSignedError, "No node found" unless node
      raise XmlsecRb::NotSignedError, "Node is not signed" unless signed?(node)
      node
    end

    def signed(xpath, ns = {})
      nodes = document.xpath(xpath, ns).to_a
      raise XmlsecRb::NotSignedError, "Some nodes are not signed" unless nodes.all? { |n| signed?(n) }
      nodes
    end

    private

    def resolve_reference(ref)
      if ref.uri.nil? || ref.uri.empty?
        document.root
      elsif ref.uri.start_with?("#")
        id = ref.uri[1..-1]
        # In Nokogiri, we can find by ID if registered, or we can just search by our known ID attributes
        document.at_xpath("//*[@Id='#{id}' or @ID='#{id}' or @id='#{id}']")
      else
        nil # external references are not resolved by default
      end
    end
  end
end
