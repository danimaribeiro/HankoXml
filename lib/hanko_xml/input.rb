# frozen_string_literal: true

module HankoXml
  # A document on its way to the native layer: always its bytes, plus the
  # caller's DOM when there is one (API_CONTRACT.md §6.1, #102).
  #
  # Every security check reads the bytes, through the native layer, so it
  # runs the same with or without Nokogiri. The DOM only serves what cannot
  # exist without one: Verification#signed? and friends, XPath signature
  # selection, a caller's own Nokogiri schema, a resolver:.
  class Input
    attr_reader :bytes, :document

    # +source+ is anything §6.2 accepts. A Nokogiri Document or Node is
    # serialized; anything else is read as bytes (+policy+'s
    # +max_document_size+ applies first, S-12) and, when Nokogiri is loaded,
    # also parsed, so the result carries a DOM either way.
    def self.read(source, policy: nil)
      if Dom.document?(source) || Dom.node?(source)
        document = Dom.document?(source) ? source : source.document
        return new(HankoXml.serialize(document).b, document, dom: true)
      end

      raw = HankoXml.read_source(source, policy: policy)
      document = Dom.available? ? HankoXml.parse(raw) : nil
      new(raw.b, document, dom: false)
    end

    def initialize(bytes, document, dom:)
      @bytes = bytes.frozen? ? bytes : bytes.dup.freeze
      @document = document
      @dom = dom
    end

    # Whether the caller handed over a DOM (rather than bytes).
    def dom?
      @dom
    end

    # Native.scan of the bytes, memoized per ID-attribute list. Input that
    # arrived as bytes is parsed strictly, as HankoXml.parse does with
    # Nokogiri; a DOM the caller already holds is taken as it is.
    def scan(id_attributes)
      @scans ||= {}
      @scans[id_attributes] ||= Native.scan(bytes, id_attributes, !dom?)
    end
  end
end
