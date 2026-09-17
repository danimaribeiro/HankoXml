# frozen_string_literal: true

require "openssl"

module HankoXml
  # Explicit wrapper around key/certificate material. See
  # API_CONTRACT.md §5.6.
  #
  # Everything crossing into the native layer is PEM, always -- Key
  # normalizes with OpenSSL::PKey#to_pem / OpenSSL::X509::Certificate#to_pem.
  #
  # A Key never appears in #inspect or #to_s, and its constructor filters
  # any value coming from a Key out of exception messages (see errors.rb).
  class Key
    # The label of each `-----BEGIN <label>-----` line.
    PEM_LABEL = /^-----BEGIN ([A-Z0-9 ]+)-----\s*$/

    class << self
      # Decides certificate vs key from the PEM block labels, not from
      # substrings anywhere in the text (S-15). A PEM holding both a
      # certificate and a key raises instead of silently keeping one.
      def from_pem(pem, password: nil)
        pem = pem.to_s
        material =
          if certificate_pem?(pem)
            begin
              ::OpenSSL::X509::Certificate.new(pem)
            rescue ::OpenSSL::X509::CertificateError => e
              raise HankoXml::KeyLoadError, "could not parse certificate PEM: #{e.message}"
            end
          else
            begin
              read_pkey(pem, password)
            rescue ::OpenSSL::PKey::PKeyError => e
              raise HankoXml::KeyLoadError,
                    "could not parse key PEM: #{e.message}#{encrypted_hint(pem, password)}#{path_hint(pem)}"
            end
          end

        new(material)
      end

      # OpenSSL::PKey.read with a nil password falls back to OpenSSL's
      # default callback, which prompts "Enter PEM pass phrase:" on the
      # controlling terminal and blocks the process until someone types.
      # An empty String never prompts: an encrypted key just fails to load.
      def read_pkey(material, password)
        ::OpenSSL::PKey.read(material, password.nil? ? "" : password.to_s)
      end

      def encrypted_hint(pem, password)
        return "" unless password.nil?
        return "" unless pem.include?("ENCRYPTED")

        ". The key is encrypted; pass password: (HankoXml::Key.from_pem(pem, password: ...))"
      end
      private :encrypted_hint

      # A String is always key material, never a filename (S-21): accepting
      # both would make "which one was meant" a guess. The hint never echoes
      # the input, which may be (malformed) key material.
      def path_hint(pem)
        return "" if pem.include?("-----BEGIN")

        ". A String is read as PEM/DER content, not a file path; to load a file, pass " \
          "Pathname.new(path) or use HankoXml::Key.from_file(path)"
      end
      private :path_hint

      def certificate_pem?(pem)
        labels = pem.scan(PEM_LABEL).flatten
        certificates = labels.count { |label| label.end_with?("CERTIFICATE") }
        keys = labels.count { |label| label.end_with?("KEY") }
        return false if certificates.zero?
        return true if keys.zero?

        raise HankoXml::KeyLoadError,
              "PEM contains both a certificate and a key; pass them separately as key: and certificate:"
      end
      private :certificate_pem?

      def from_der(der)
        material =
          begin
            ::OpenSSL::X509::Certificate.new(der)
          rescue ::OpenSSL::X509::CertificateError
            begin
              read_pkey(der, nil)
            rescue ::OpenSSL::PKey::PKeyError => e
              raise HankoXml::KeyLoadError, "could not parse DER key/certificate: #{e.message}"
            end
          end

        new(material)
      end

      def from_file(path, password: nil)
        from_pem(::File.binread(path.respond_to?(:to_path) ? path.to_path : path), password: password)
      end

      def from_pkcs12(path, password:)
        bytes = ::File.binread(path.respond_to?(:to_path) ? path.to_path : path)
        pkcs12 =
          begin
            ::OpenSSL::PKCS12.new(bytes, password)
          rescue ::OpenSSL::PKCS12::PKCS12Error => e
            raise HankoXml::KeyLoadError, "could not read PKCS#12 bundle: #{e.message}"
          end

        Bundle.new(
          key: new(pkcs12.key),
          certificate: new(pkcs12.certificate),
          certificates: [new(pkcs12.certificate), *Array(pkcs12.ca_certs).map { |c| new(c) }]
        )
      end
    end

    # key: / certificate: / certificates: -- coerces any of the accepted
    # input shapes (OpenSSL object, PEM String, path-like, or an existing
    # Key) into a Key. Returns +input+ unchanged if it is already a Key.
    def self.coerce(input, password: nil)
      case input
      when Key
        input
      when ::OpenSSL::PKey::PKey, ::OpenSSL::X509::Certificate
        new(input)
      when String
        from_pem(input, password: password)
      when ->(obj) { obj.respond_to?(:to_path) }
        from_file(input, password: password)
      else
        raise ArgumentError,
              "expected an OpenSSL::PKey::PKey, OpenSSL::X509::Certificate, PEM String, " \
              "path-like object, or HankoXml::Key, got #{input.class}"
      end
    end

    def initialize(material)
      @material = material
      @disposed = false
    end

    def certificate?
      @material.is_a?(::OpenSSL::X509::Certificate)
    end

    # True only for a key that has its private half (S-15). A public-only
    # OpenSSL::PKey::PKey is false.
    def private_key?
      return false unless @material.is_a?(::OpenSSL::PKey::PKey)
      return @material.private? if @material.respond_to?(:private?)

      # Generic PKey (e.g. Ed25519) has no #private?; only a private key
      # serializes its private half.
      @material.private_to_der
      true
    rescue ::OpenSSL::PKey::PKeyError
      false
    end

    def to_pem
      raise HankoXml::KeyLoadError, "this key has been disposed" if @disposed

      @material.to_pem
    end

    def to_openssl
      raise HankoXml::KeyLoadError, "this key has been disposed" if @disposed

      @material
    end

    # Drops this Key's reference to its OpenSSL object and makes #to_pem /
    # #to_openssl raise from then on. It does NOT zeroize anything (S-15):
    # the key bytes live in OpenSSL-owned memory freed whenever Ruby's GC
    # collects the object, and every String #to_pem already returned is the
    # caller's, untouched. Use it to stop later accidental use, not as a
    # memory-hygiene guarantee.
    def dispose!
      return if @disposed

      @disposed = true
      @material = nil
    end

    def disposed?
      @disposed
    end

    def inspect
      "#<#{self.class} #{certificate? ? "certificate" : "key"}=[FILTERED]>"
    end

    def to_s
      inspect
    end

    # key:, certificate:, certificates: bundle returned by .from_pkcs12.
    class Bundle
      attr_reader :key, :certificate, :certificates

      def initialize(key:, certificate:, certificates:)
        @key = key
        @certificate = certificate
        @certificates = certificates
      end

      def to_h
        { key: key, certificate: certificate, certificates: certificates }
      end
    end
  end
end
