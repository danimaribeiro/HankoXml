# frozen_string_literal: true

module HankoXml
  # DOM-free, unauthenticated view of a <ds:Signature>'s <SignedInfo> --
  # exactly the shape HankoXml::Native.inspect returns (§7 of
  # API_CONTRACT.md), and nothing more. Policy is checked against this, not
  # against Nokogiri nodes, so Policy enforcement works identically whether
  # or not Nokogiri is loaded (§6.1).
  #
  # Everything here is "what the document claims" -- it runs before any
  # cryptography, and is not proof of anything until a Verification says so.
  #
  # The library builds these; callers only read them, through
  # Verification#signed_info / #signature_info. The constructors are not
  # part of the public API.
  class SignatureInfo
    XPATH_FILTER2 = "http://www.w3.org/2002/06/xmldsig-filter2"
    # The whole document: without comments (""), and with them ("#xpointer(/)",
    # which allow_same_document_xpointer still governs).
    WHOLE_DOCUMENT_URIS = ["", "#xpointer(/)"].freeze
    DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

    ReferenceInfo = Struct.new(:uri, :digest_method, :transforms, :id, :type, :xpath_filters, keyword_init: true) do
      def initialize(uri:, digest_method:, transforms: [], id: nil, type: nil, xpath_filters: [])
        super
      end

      # Which <ds:Signature> elements an XPath Filter 2.0 transform takes out
      # of this Reference, for the one shape HankoXml accepts (#85): a
      # whole-document reference (WHOLE_DOCUMENT_URIS) whose first transform is a single `subtract` of
      # `/descendant::P:Signature` (every signature, :all) or `/*/P:Signature`
      # (the root's signature children, :root_children), with P bound to the
      # XML-DSig namespace on the <XPath> element. nil for anything else, which
      # Policy refuses. The expression is matched token for token (XPath
      # allows whitespace between tokens), never by its prefix's spelling:
      # `name()='ds:Signature'` would match any namespace bound to `ds`.
      def signature_exclusion
        return nil unless WHOLE_DOCUMENT_URIS.include?(uri.to_s) && transforms.first == XPATH_FILTER2
        return nil unless transforms.count(XPATH_FILTER2) == 1 && xpath_filters.size == 1

        filter = xpath_filters.first.transform_keys(&:to_sym)
        return nil unless filter[:filter] == "subtract"

        match = filter[:expression].to_s.gsub(/\s+/, "").match(%r{\A/(descendant::|\*/)([A-Za-z_][\w.-]*):Signature\z})
        return nil unless match && filter[:namespaces].to_h[match[2]] == DSIG_NS

        match[1] == "descendant::" ? :all : :root_children
      end

      def xpath_filter2?
        transforms.include?(XPATH_FILTER2)
      end

      def digest_method_name
        Algorithms.name_for(:digest, digest_method)
      end

      def transform_names
        transforms.map { |uri| Algorithms.name_for(:transform, uri) }
      end

      def fragment?
        uri.to_s.start_with?("#")
      end

      def external?
        !(uri.to_s.empty? || fragment?)
      end

      # The URI xmlsec reads an external reference from: everything before
      # any `#` fragment.
      def document_uri
        uri.to_s.split("#", 2).first.to_s
      end

      # Same-document XPointer, e.g. `#xpointer(/)` or `#xpointer(id('x'))` --
      # not a bare `#id` fragment (S-06, `allow_same_document_xpointer`).
      def same_document_xpointer?
        fragment? && uri[1..].to_s.include?("(")
      end
    end

    attr_reader :signature_method, :canonicalization_method, :signature_count,
                :key_names, :certificates, :references

    # @api private
    def initialize(signature_method:, canonicalization_method:, references:,
                   signature_count: 1, key_names: [], certificates: [], has_retrieval_method: false)
      @signature_method = signature_method
      @canonicalization_method = canonicalization_method
      @signature_count = signature_count
      @key_names = key_names.freeze
      @certificates = certificates.freeze
      @references = references.map { |r| r.is_a?(ReferenceInfo) ? r : ReferenceInfo.new(**r) }.freeze
      @has_retrieval_method = has_retrieval_method
      freeze
    end

    # Whether `<KeyInfo>` contains a `<RetrievalMethod>` (S-06,
    # `allow_retrieval_method`).
    def retrieval_method?
      @has_retrieval_method
    end

    def signature_method_name
      Algorithms.name_for(:signature, signature_method)
    end

    def canonicalization_method_name
      Algorithms.name_for(:canonicalization, canonicalization_method)
    end

    # Builds a SignatureInfo from the native Native.inspect Hash shape
    # (String keys/URIs throughout).
    #
    # @api private
    def self.from_native(hash)
      new(
        signature_method: fetch(hash, :signature_method),
        canonicalization_method: fetch(hash, :canonicalization_method),
        signature_count: fetch(hash, :signature_count) || 1,
        key_names: fetch(hash, :key_names) || [],
        certificates: fetch(hash, :certificates) || [],
        references: fetch(hash, :references) || [],
        has_retrieval_method: fetch(hash, :has_retrieval_method) || false
      )
    end

    def self.fetch(hash, key)
      hash[key] || hash[key.to_s]
    end
    private_class_method :fetch
  end
end
