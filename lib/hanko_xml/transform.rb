# frozen_string_literal: true

module HankoXml
  # A single <ds:Transform>, resolved to a URI at construction. Frozen value
  # object. See API_CONTRACT.md §5.2, §5.7.
  class Transform
    EXC_C14N_NS = "http://www.w3.org/2001/10/xml-exc-c14n#"
    EXCLUSIVE = %i[exc_c14n exc_c14n_with_comments].freeze
    # An NCName, or the "#default" token for the default namespace
    # (Exclusive XML Canonicalization §3).
    PREFIX = /\A(?:#default|[A-Za-z_][A-Za-z0-9_.-]*)\z/

    attr_reader :name, :uri, :xpath, :inclusive_prefixes

    # +algorithm+ is a Symbol looked up in Algorithms.transform, or a String
    # URI used verbatim. +xpath+ is required for :xpath / :xpath_filter2
    # transforms and carried through as the transform's textual content.
    # +inclusive_prefixes+ (exclusive c14n only) becomes an
    # <ec:InclusiveNamespaces PrefixList="..."/> child: namespace prefixes
    # canonicalized as in inclusive c14n, e.g. %w[xs] for SAML xsi:type values.
    def initialize(algorithm, xpath: nil, inclusive_prefixes: [])
      @name = algorithm.is_a?(Symbol) ? algorithm : Algorithms.name_for(:transform, algorithm)
      @uri = Algorithms.uri_for(:transform, algorithm)

      raise HankoXml::ConfigurationError, "unknown transform #{algorithm.inspect}" if @uri.nil?

      @xpath = xpath
      @inclusive_prefixes = coerce_inclusive_prefixes(inclusive_prefixes)
      freeze
    end

    # Exclusive c14n, optionally with an InclusiveNamespaces PrefixList.
    def self.exc_c14n(inclusive_prefixes: [], with_comments: false)
      new(with_comments ? :exc_c14n_with_comments : :exc_c14n, inclusive_prefixes: inclusive_prefixes)
    end

    def self.c14n
      new(:c14n)
    end

    def self.enveloped_signature
      new(:enveloped_signature)
    end

    def enveloped_signature?
      name == :enveloped_signature
    end

    def secure?
      Algorithms.secure?(:transform, uri)
    end

    def self.coerce(value)
      value.is_a?(Transform) ? value : new(value)
    end

    def ==(other)
      other.is_a?(Transform) &&
        other.uri == uri &&
        other.xpath == xpath &&
        other.inclusive_prefixes == inclusive_prefixes
    end

    alias eql? ==

    def hash
      [uri, xpath, inclusive_prefixes].hash
    end

    private

    def coerce_inclusive_prefixes(prefixes)
      prefixes = Array(prefixes).map(&:to_s)
      return prefixes.freeze if prefixes.empty?

      unless EXCLUSIVE.include?(name)
        raise HankoXml::ConfigurationError, "inclusive_prefixes: applies only to exclusive c14n transforms, not #{uri}"
      end

      invalid = prefixes.grep_v(PREFIX)
      unless invalid.empty?
        raise HankoXml::ConfigurationError,
          "inclusive_prefixes: #{invalid.inspect} are not namespace prefixes (NCName or \"#default\")"
      end

      prefixes.uniq.freeze
    end
  end
end
