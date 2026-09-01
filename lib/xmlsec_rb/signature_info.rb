# frozen_string_literal: true

module XmlsecRb
  # DOM-free, unauthenticated view of a <ds:Signature>'s <SignedInfo> --
  # exactly the shape XmlsecRb::Native.inspect returns (§7 of
  # API_CONTRACT.md), and nothing more. Policy is checked against this, not
  # against Nokogiri nodes, so Policy enforcement works identically whether
  # or not Nokogiri is loaded (§6.1).
  #
  # Everything here is "what the document claims" -- it runs before any
  # cryptography, and is not proof of anything until a Verification says so.
  class SignatureInfo
    ReferenceInfo = Struct.new(:uri, :digest_method, :transforms, :id, :type, keyword_init: true) do
      def initialize(uri:, digest_method:, transforms: [], id: nil, type: nil)
        super
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
    end

    attr_reader :signature_method, :canonicalization_method, :signature_count,
                :key_names, :certificates, :references

    def initialize(signature_method:, canonicalization_method:, references:,
                   signature_count: 1, key_names: [], certificates: [])
      @signature_method = signature_method
      @canonicalization_method = canonicalization_method
      @signature_count = signature_count
      @key_names = key_names.freeze
      @certificates = certificates.freeze
      @references = references.map { |r| r.is_a?(ReferenceInfo) ? r : ReferenceInfo.new(**r) }.freeze
      freeze
    end

    def signature_method_name
      Algorithms.name_for(:signature, signature_method)
    end

    def canonicalization_method_name
      Algorithms.name_for(:canonicalization, canonicalization_method)
    end

    # Builds a SignatureInfo from the native Native.inspect Hash shape
    # (String keys/URIs throughout).
    def self.from_native(hash)
      new(
        signature_method: hash[:signature_method] || hash["signature_method"],
        canonicalization_method: hash[:canonicalization_method] || hash["canonicalization_method"],
        signature_count: hash[:signature_count] || hash["signature_count"] || 1,
        key_names: hash[:key_names] || hash["key_names"] || [],
        certificates: hash[:certificates] || hash["certificates"] || [],
        references: hash[:references] || hash["references"] || []
      )
    end
  end
end
