# frozen_string_literal: true

module XmlsecRb
  # A single <ds:Transform>, resolved to a URI at construction. Frozen value
  # object. See API_CONTRACT.md §5.2, §5.7.
  class Transform
    attr_reader :name, :uri, :xpath

    # +algorithm+ is a Symbol looked up in Algorithms.transform, or a String
    # URI used verbatim. +xpath+ is required for :xpath / :xpath_filter2
    # transforms and carried through as the transform's textual content.
    def initialize(algorithm, xpath: nil)
      @name = algorithm.is_a?(Symbol) ? algorithm : Algorithms.name_for(:transform, algorithm)
      @uri = Algorithms.uri_for(:transform, algorithm)

      raise XmlsecRb::ConfigurationError, "unknown transform #{algorithm.inspect}" if @uri.nil?

      @xpath = xpath
      freeze
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
      other.is_a?(Transform) && other.uri == uri && other.xpath == xpath
    end
    alias eql? ==

    def hash
      [uri, xpath].hash
    end
  end
end
