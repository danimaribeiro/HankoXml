# frozen_string_literal: true

module XmlsecRb
  # A single <ds:Reference> a Signer will emit. Frozen value object. See
  # API_CONTRACT.md §5.2.
  class Reference
    attr_reader :uri, :transforms, :digest_method, :id, :type

    # +uri+: "" for the whole document (enveloped), "#id" for a fragment,
    #   or nil to default to "" when this is the only/default reference.
    # +transforms+: Array of Transform / Symbol / String, in order.
    # +digest_method+: Symbol or URI String, defaults to :sha256.
    def initialize(uri: "", transforms: [:enveloped_signature], digest_method: :sha256, id: nil, type: nil)
      @uri = uri.nil? ? "" : uri.to_s
      @transforms = Array(transforms).map { |t| Transform.coerce(t) }
      @digest_method = digest_method
      @id = id
      @type = type
      freeze
    end

    def digest_method_uri
      Algorithms.uri_for(:digest, digest_method)
    end

    def enveloped?
      transforms.any?(&:enveloped_signature?)
    end

    def fragment?
      uri.start_with?("#")
    end

    def target_id
      fragment? ? uri.sub(/\A#/, "") : nil
    end

    def self.coerce(value)
      case value
      when Reference then value
      when String then new(uri: value)
      when Hash then new(**value)
      else
        raise ArgumentError, "expected a XmlsecRb::Reference, URI String, or Hash of Reference " \
                              "keywords, got #{value.class}"
      end
    end
  end
end
