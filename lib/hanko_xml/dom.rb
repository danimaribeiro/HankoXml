# frozen_string_literal: true

module HankoXml
  # The single place that probes for, or calls into, Nokogiri. Nothing else
  # in the library references the Nokogiri constant directly -- see
  # API_CONTRACT.md §6.1. spec/hanko_xml/dom_spec.rb enforces this, and that
  # nothing in lib/ ever requires Nokogiri (the caller decides load order,
  # §3.1).
  #
  # The DOM operations below take no decision of their own: each is the one
  # Nokogiri call its caller needs, kept here so a DOM-free path (#102) has a
  # single seam to replace or guard.
  #
  # The rule: a missing Nokogiri may remove a capability, it may never weaken
  # one. Every check that runs with Nokogiri present runs identically in its
  # absence; the capabilities that disappear are the ones that cannot be
  # expressed at all without a DOM, and each of them raises
  # HankoXml::NokogiriRequired rather than quietly returning a less careful
  # answer.
  #
  # @api private
  module Dom
    class << self
      def available?
        defined?(::Nokogiri::XML::Document) ? true : false
      end

      def document?(obj)
        available? && obj.is_a?(::Nokogiri::XML::Document)
      end

      def node?(obj)
        available? && obj.is_a?(::Nokogiri::XML::Node)
      end

      def certificate?(obj)
        defined?(::OpenSSL::X509::Certificate) && obj.is_a?(::OpenSSL::X509::Certificate)
      end

      def pkey?(obj)
        defined?(::OpenSSL::PKey::PKey) && obj.is_a?(::OpenSSL::PKey::PKey)
      end

      # Raises HankoXml::NokogiriRequired, naming +capability+ and the fix,
      # unless Nokogiri is loaded.
      def require!(capability)
        return if available?

        raise HankoXml::NokogiriRequired,
              "#{capability} needs a DOM, and Nokogiri is not loaded. Add `gem \"nokogiri\"` to your " \
              "Gemfile and `require \"nokogiri\"` before using it. Verification, signature_present? and " \
              "signing an existing <Signature> template work without it (API_CONTRACT.md §6.1)."
      end

      # Parses +source+ strict (no RECOVER) and nonet: the one way that does
      # not break XML-DSig (API_CONTRACT.md §6.3). Returns the document and
      # libxml2's errors, or nil and the SyntaxError strict mode raised.
      def parse(source)
        doc = ::Nokogiri::XML(source) { |config| config.strict.nonet }
        [doc, doc.errors]
      rescue ::Nokogiri::XML::SyntaxError => e
        [nil, [e]]
      end

      # Byte-faithful serialization: AS_XML only, never FORMAT, which reindents
      # the tree and invalidates any signature over it (§6.3).
      def to_xml(node, declaration: true)
        options = ::Nokogiri::XML::Node::SaveOptions::AS_XML
        options |= ::Nokogiri::XML::Node::SaveOptions::NO_DECLARATION unless declaration
        node.to_xml(save_with: options)
      end

      # Runs +expression+ against +node+. On an XPath syntax error, returns
      # what the block returns (the block usually raises); without a block
      # the error propagates.
      def xpath(node, expression, namespaces)
        node.xpath(expression, namespaces)
      rescue ::Nokogiri::XML::XPath::SyntaxError
        raise unless block_given?

        yield
      end

      # Loads the XSD at +path+, with the path as the base URL so its
      # relative imports resolve (#61).
      def schema_from_file(path)
        require!("XML Schema validation")

        ::Nokogiri::XML::Schema.from_document(::Nokogiri::XML(::File.read(path), path))
      end

      # Validates a copy of +node+, as the root of a fresh document, against
      # +schema+. Returns the validation errors.
      def schema_errors(schema, node)
        doc = ::Nokogiri::XML::Document.new
        doc.add_child(node.dup)
        schema.validate(doc)
      end

      # Mixes +mod+ into Nokogiri's Document and Node. A no-op without
      # Nokogiri. Returns whether it was installed.
      def extend_nodes(mod)
        return false unless available?

        ::Nokogiri::XML::Document.include(mod)
        ::Nokogiri::XML::Node.include(mod)
        true
      end

      # What works in this process (API_CONTRACT.md §6.1). Verification, and
      # signing a template the document already holds, run on bytes through
      # the native layer, so they never need Nokogiri; the rest need a DOM.
      # #102.
      #
      # - verify: Verifier / HankoXml.valid? / verify! / signature_present?,
      #   including `schema: :default`.
      # - sign: Signer, HankoXml.sign / sign!.
      # - sign_existing_template: Signer#sign / HankoXml.sign of a document
      #   that already holds the <Signature> template, on bytes (#102).
      # - coverage_checks: Verification#signed?, #signed_nodes, #at_signed.
      # - schema: a caller's own Nokogiri::XML::Schema as `schema:`.
      # - parse: HankoXml.parse / serialize.
      # - template_build: Template, Signer#template.
      def capabilities
        {
          verify: true,
          sign: available?,
          sign_existing_template: true,
          coverage_checks: available?,
          schema: available?,
          parse: available?,
          template_build: available?
        }
      end
    end
  end
end
