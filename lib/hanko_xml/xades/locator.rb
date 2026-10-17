# frozen_string_literal: true

module HankoXml
  module Xades
    # Finds a signature's <xades:QualifyingProperties> and its unsigned
    # containers along fixed paths from the <ds:Signature>, never by a search
    # that a wrapped element elsewhere could satisfy (S-22). Xades::Verifier
    # reads, and Xades::Augmenter writes, exactly the elements found here.
    #
    # @api private
    module Locator
      module_function

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

      # Target is "#" + the Signature Id. The older namespaces also had
      # signers write the bare Id (Target="Signature"). Either way the
      # QualifyingProperties must sit in this <Signature>'s own <Object>.
      def targets?(qualifying, signature_id)
        target = qualifying["Target"]
        return true if target == "##{signature_id}"

        LEGACY_NAMESPACES.include?(qualifying.namespace.href) && target == signature_id
      end

      # The UnsignedSignatureProperties, or nil when there is none. More than
      # one UnsignedProperties or UnsignedSignatureProperties is refused: which
      # one a reader would pick is ambiguous.
      def unsigned_signature_properties(qualifying, ns)
        unsigned = qualifying.xpath("xades:UnsignedProperties", ns)
        fail!("a XAdES signature has at most one <xades:UnsignedProperties>") if unsigned.size > 1
        return nil if unsigned.empty?

        properties = unsigned.first.xpath("xades:UnsignedSignatureProperties", ns)
        fail!("a XAdES signature has at most one <xades:UnsignedSignatureProperties>") if properties.size > 1

        properties.first
      end

      # The native path (Native.canonicalize) from the <ds:Signature> to its
      # UnsignedSignatureProperties.
      def unsigned_path(signature, qualifying, xades_ns)
        object_index = signature.xpath("ds:Object", "ds" => HankoXml::NS["ds"]).index(qualifying.parent)
        [[HankoXml::NS["ds"], "Object", object_index], [xades_ns, "QualifyingProperties", nil],
         [xades_ns, "UnsignedProperties", nil], [xades_ns, "UnsignedSignatureProperties", nil]]
      end

      def fail!(message)
        raise HankoXml::XadesError, message
      end
    end
  end
end
