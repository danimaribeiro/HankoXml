# frozen_string_literal: true

module HankoXml
  # Where the <Signature> element goes. Frozen value object; Symbols coerce.
  # See API_CONTRACT.md §5.5.
  class Placement
    MODES = %i[append_to_root prepend_to_root append_to prepend_to after before detached custom].freeze

    attr_reader :mode, :target, :namespaces, :block

    def initialize(mode, target: nil, namespaces: {}, &block)
      mode = mode.to_sym
      raise HankoXml::ConfigurationError, "unknown placement mode #{mode.inspect}" unless MODES.include?(mode)

      @mode = mode
      @target = target
      @namespaces = namespaces
      @block = block
      freeze
    end

    def detached?
      mode == :detached
    end

    class << self
      def append_to_root
        new(:append_to_root)
      end

      def prepend_to_root
        new(:prepend_to_root)
      end

      def append_to(node_or_xpath, namespaces: {})
        new(:append_to, target: node_or_xpath, namespaces: namespaces)
      end

      def prepend_to(node_or_xpath, namespaces: {})
        new(:prepend_to, target: node_or_xpath, namespaces: namespaces)
      end

      def after(node_or_xpath, namespaces: {})
        new(:after, target: node_or_xpath, namespaces: namespaces)
      end

      def before(node_or_xpath, namespaces: {})
        new(:before, target: node_or_xpath, namespaces: namespaces)
      end

      def detached
        new(:detached)
      end

      def custom(&block)
        new(:custom, &block)
      end

      # Coerces a Placement, a recognised Symbol (:append_to_root,
      # :prepend_to_root, :detached), or leaves nil as-is.
      def coerce(value)
        case value
        when Placement
          value
        when Symbol
          new(value)
        when nil
          nil
        else
          raise ArgumentError, "expected a HankoXml::Placement or Symbol, got #{value.class}"
        end
      end
    end

    # Resolves +target+ to exactly one Nokogiri::XML::Node within +doc+.
    # The XPath sees HankoXml::NS, then the Signer's +namespaces:+, then
    # Placement#namespaces, each merged over the last (#96). Raises
    # HankoXml::PlacementError if the XPath matches zero or more than one
    # node.
    def resolve(doc, namespaces: {})
      return doc.root if target.nil?

      return target if HankoXml::Dom.node?(target)

      ns = HankoXml::NS.merge((namespaces || {}).transform_keys(&:to_s)).merge(self.namespaces.transform_keys(&:to_s))
      matches = begin
        doc.xpath(target, ns)
      rescue Nokogiri::XML::XPath::SyntaxError
        raise HankoXml::PlacementError,
          "placement XPath #{target.inspect} is not valid XPath; bind every prefix it uses in namespaces:"
      end

      if matches.empty?
        raise HankoXml::PlacementError, "placement XPath #{target.inspect} matched no nodes"
      elsif matches.size > 1
        raise HankoXml::PlacementError,
          "placement XPath #{target.inspect} matched #{matches.size} nodes, expected exactly one"
      end

      matches.first
    end

    # Inserts +signature_node+ into +doc+ per this placement's mode.
    # +namespaces+ are the Signer's, see #resolve. Returns +signature_node+.
    def insert(doc, signature_node, namespaces: {})
      case mode
      when :append_to_root
        doc.root.add_child(signature_node)
      when :prepend_to_root
        if doc.root.children.first
          doc.root.children.first.add_previous_sibling(signature_node)
        else
          doc.root.add_child(signature_node)
        end
      when :append_to
        resolve(doc, namespaces: namespaces).add_child(signature_node)
      when :prepend_to
        node = resolve(doc, namespaces: namespaces)
        node.children.first ? node.children.first.add_previous_sibling(signature_node) : node.add_child(signature_node)
      when :after
        resolve(doc, namespaces: namespaces).add_next_sibling(signature_node)
      when :before
        resolve(doc, namespaces: namespaces).add_previous_sibling(signature_node)
      when :detached
        # Caller does not insert; Signer#template returns the built node.
      when :custom
        block.call(doc, signature_node)
      end

      signature_node
    end
  end
end
