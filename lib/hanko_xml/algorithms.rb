# frozen_string_literal: true

module HankoXml
  # Registry of algorithm URIs, keyed by short Symbol names, per slot
  # (:canonicalization, :digest, :signature, :transform). See
  # API_CONTRACT.md §5.7.
  #
  # Every algorithm slot elsewhere in the library accepts either a Symbol
  # (looked up here) or a String URI (used verbatim, subject to Policy).
  #
  # Registration is process-global and additive. It does NOT grant use --
  # a Policy allowlist must separately permit the algorithm. Built-in names
  # and URIs cannot be re-pointed, even with replace: true (S-16).
  module Algorithms
    Entry = Struct.new(:slot, :name, :uri, :secure, keyword_init: true) do
      def secure?
        !!secure
      end
    end

    # Name/URI lookup for a single algorithm slot (e.g. :digest).
    class Table
      def initialize(slot)
        @slot = slot
        @by_name = {}
        @by_uri = {}
        @builtin_names = {}.freeze
        @builtin_uris = {}.freeze
      end

      def register(name, uri, secure:, replace: false)
        name = name.to_sym
        uri = uri.to_s
        check_not_builtin!(name, uri)

        if @by_name.key?(name) && !replace
          raise ArgumentError,
                "#{@slot} algorithm #{name.inspect} is already registered " \
                "(pass replace: true to override)"
        end

        previous = @by_name[name]
        @by_uri.delete(previous.uri) if previous && @by_uri[previous.uri].equal?(previous)

        entry = Entry.new(slot: @slot, name: name, uri: uri, secure: secure).freeze
        @by_name[name] = entry
        @by_uri[uri] = entry
        entry
      end

      # Marks everything registered so far as built-in (S-16): those names
      # and URIs are what Policy presets are written in terms of, so
      # re-pointing one would silently change what, e.g., Policy.strict
      # accepts for every caller in the process.
      def seal_builtins!
        @builtin_names = @by_name.keys.to_h { |name| [name, true] }.freeze
        @builtin_uris = @by_uri.keys.to_h { |uri| [uri, true] }.freeze
        self
      end

      def [](name_or_uri)
        case name_or_uri
        when Symbol
          @by_name[name_or_uri]
        when String
          @by_uri[name_or_uri] || @by_name[name_or_uri.to_sym]
        end
      end

      def uri_for(name_or_uri)
        return name_or_uri if name_or_uri.is_a?(String) && !@by_name.key?(name_or_uri.to_sym)

        entry = self[name_or_uri]
        entry&.uri || (name_or_uri.is_a?(String) ? name_or_uri : nil)
      end

      def name_for(uri)
        @by_uri[uri.to_s]&.name
      end

      def secure?(name_or_uri)
        entry = self[name_or_uri]
        entry.nil? ? false : entry.secure?
      end

      def names
        @by_name.keys
      end

      private

      def check_not_builtin!(name, uri)
        if @builtin_names.key?(name)
          raise ArgumentError, "#{@slot} algorithm #{name.inspect} is built in and cannot be replaced"
        end
        return unless @builtin_uris.key?(uri)

        raise ArgumentError,
              "#{@slot} URI #{uri} is built in as #{@by_uri[uri].name.inspect} and cannot be re-registered"
      end
    end

    class << self
      def canonicalization
        @canonicalization ||= build_canonicalization_table
      end

      def digest
        @digest ||= build_digest_table
      end

      def signature
        @signature ||= build_signature_table
      end

      def transform
        @transform ||= build_transform_table
      end

      def register(slot, name, uri, secure:, replace: false)
        table_for(slot).register(name, uri, secure: secure, replace: replace)
      end

      def uri_for(slot, name_or_uri)
        table_for(slot).uri_for(name_or_uri)
      end

      def name_for(slot, uri)
        table_for(slot).name_for(uri)
      end

      def secure?(slot, name_or_uri)
        table_for(slot).secure?(name_or_uri)
      end

      private

      def table_for(slot)
        case slot.to_sym
        when :canonicalization then canonicalization
        when :digest then digest
        when :signature then signature
        when :transform then transform
        else
          raise ArgumentError, "unknown algorithm slot #{slot.inspect}"
        end
      end

      def build_canonicalization_table
        table = Table.new(:canonicalization)
        table.register(:c14n, "http://www.w3.org/TR/2001/REC-xml-c14n-20010315", secure: true)
        table.register(:c14n_with_comments,
                       "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments", secure: true)
        table.register(:exc_c14n, "http://www.w3.org/2001/10/xml-exc-c14n#", secure: true)
        table.register(:exc_c14n_with_comments,
                       "http://www.w3.org/2001/10/xml-exc-c14n#WithComments", secure: true)
        table.register(:c14n11, "http://www.w3.org/2006/12/xml-c14n11", secure: true)
        table.register(:c14n11_with_comments,
                       "http://www.w3.org/2006/12/xml-c14n11#WithComments", secure: true)
        table.seal_builtins!
      end

      def build_digest_table
        table = Table.new(:digest)
        table.register(:sha1, "http://www.w3.org/2000/09/xmldsig#sha1", secure: false)
        table.register(:sha224, "http://www.w3.org/2001/04/xmldsig-more#sha224", secure: true)
        table.register(:sha256, "http://www.w3.org/2001/04/xmlenc#sha256", secure: true)
        table.register(:sha384, "http://www.w3.org/2001/04/xmldsig-more#sha384", secure: true)
        table.register(:sha512, "http://www.w3.org/2001/04/xmlenc#sha512", secure: true)
        table.register(:ripemd160, "http://www.w3.org/2001/04/xmlenc#ripemd160", secure: false)
        # RFC 6931 SHA-3. xmlsec 1.3 implements these; xmlsec 1.2 (Ubuntu CI)
        # does not — Native.sign/verify then fails closed (#60).
        table.register(:sha3_224, "http://www.w3.org/2007/05/xmldsig-more#sha3-224", secure: true)
        table.register(:sha3_256, "http://www.w3.org/2007/05/xmldsig-more#sha3-256", secure: true)
        table.register(:sha3_384, "http://www.w3.org/2007/05/xmldsig-more#sha3-384", secure: true)
        table.register(:sha3_512, "http://www.w3.org/2007/05/xmldsig-more#sha3-512", secure: true)
        table.seal_builtins!
      end

      def build_signature_table
        table = Table.new(:signature)
        table.register(:rsa_sha1, "http://www.w3.org/2000/09/xmldsig#rsa-sha1", secure: false)
        table.register(:rsa_sha224, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224", secure: true)
        table.register(:rsa_sha256, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", secure: true)
        table.register(:rsa_sha384, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", secure: true)
        table.register(:rsa_sha512, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", secure: true)
        # RFC 6931 RSA-PSS (MGF1, default salt = hash length). xmlsec 1.3
        # implements these without <RSAPSSParams>; xmlsec 1.2 does not (#60).
        table.register(:rsa_pss_sha256, "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
                       secure: true)
        table.register(:rsa_pss_sha384, "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1",
                       secure: true)
        table.register(:rsa_pss_sha512, "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1",
                       secure: true)
        table.register(:ecdsa_sha256, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", secure: true)
        table.register(:ecdsa_sha384, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", secure: true)
        table.register(:ecdsa_sha512, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", secure: true)
        table.register(:ecdsa_sha3_256, "http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha3-256",
                       secure: true)
        table.register(:ecdsa_sha3_384, "http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha3-384",
                       secure: true)
        table.register(:ecdsa_sha3_512, "http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha3-512",
                       secure: true)
        table.register(:dsa_sha1, "http://www.w3.org/2000/09/xmldsig#dsa-sha1", secure: false)
        table.register(:hmac_sha256, "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", secure: true)
        table.seal_builtins!
      end

      def build_transform_table
        table = Table.new(:transform)
        # Every canonicalization algorithm is also a valid transform.
        canonicalization.names.each do |name|
          entry = canonicalization[name]
          table.register(entry.name, entry.uri, secure: entry.secure?)
        end
        table.register(:enveloped_signature, "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                       secure: true)
        table.register(:base64, "http://www.w3.org/2000/09/xmldsig#base64", secure: true)
        table.register(:xpath, "http://www.w3.org/TR/1999/REC-xpath-19991116", secure: false)
        table.register(:xpath_filter2, "http://www.w3.org/2002/06/xmldsig-filter2", secure: false)
        table.register(:xslt, "http://www.w3.org/TR/1999/REC-xslt-19991116", secure: false)
        table.seal_builtins!
      end
    end
  end
end
