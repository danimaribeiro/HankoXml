# frozen_string_literal: true

module HankoXml
  # KeyInfo clauses a Signer emits into <ds:KeyInfo>, and the parsed,
  # unauthenticated view a Verification exposes as what the document
  # *claimed*. See API_CONTRACT.md §5.2, §5.4.
  module KeyInfo
    # Recognised clause names, and which <ds:X509Data> child (if any) they
    # map to when building a template.
    CLAUSES = %i[x509_certificate x509_subject_name x509_issuer_serial x509_ski key_name key_value].freeze

    # A single clause a Signer will emit, e.g. :x509_certificate. +value+ is
    # the text a clause writes itself rather than leaving to xmlsec: only
    # :key_name has one, the name for <KeyName> (#67).
    Clause = Struct.new(:name, :value) do
      def initialize(name, value = nil)
        name = name.to_sym
        unless KeyInfo::CLAUSES.include?(name)
          raise HankoXml::ConfigurationError,
            "unknown key_info clause #{name.inspect}, expected one of #{KeyInfo::CLAUSES.inspect}"
        end

        if !value.nil? && name != :key_name
          raise HankoXml::ConfigurationError, "key_info clause #{name.inspect} takes no value"
        end

        super(name, value&.to_s&.freeze)
        freeze
      end
    end

    class << self
      # Normalizes a Signer's key_info: value (an Array of Symbols/Clauses,
      # or a single one) into a frozen Array<Clause>. A Hash names a clause
      # with its value, e.g. `{ key_name: "idp-1" }`.
      def coerce(value)
        value = [value] if value.is_a?(Hash) # Array(hash) would split it into pairs
        Array(value).flat_map do |v|
          case v
          when Clause
            v
          when Hash
            v.map { |name, clause_value| Clause.new(name, clause_value) }
          else
            Clause.new(v)
          end
        end.freeze
      end
    end

    # What a document's <ds:KeyInfo> actually contained, read out (but not
    # yet authenticated -- see Verification#key_info in API_CONTRACT.md
    # §5.4). Populated starting Phase 3.
    class Parsed
      attr_reader :key_names, :certificates

      def initialize(key_names: [], certificates: [])
        @key_names = key_names.freeze
        @certificates = certificates.freeze
        freeze
      end
    end
  end
end
