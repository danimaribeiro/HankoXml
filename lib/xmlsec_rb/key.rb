# frozen_string_literal: true

require "openssl"

module XmlsecRb
  # Explicit wrapper around key/certificate material. See
  # API_CONTRACT.md §5.6.
  #
  # Everything crossing into the native layer is PEM, always -- Key
  # normalizes with OpenSSL::PKey#to_pem / OpenSSL::X509::Certificate#to_pem.
  #
  # A Key never appears in #inspect or #to_s, and its constructor filters
  # any value coming from a Key out of exception messages (see errors.rb).
  class Key
    class << self
      def from_pem(pem, password: nil)
        pem = pem.to_s
        material =
          if pem.include?("CERTIFICATE") && !pem.include?("PRIVATE KEY")
            begin
              ::OpenSSL::X509::Certificate.new(pem)
            rescue ::OpenSSL::X509::CertificateError => e
              raise XmlsecRb::KeyLoadError, "could not parse certificate PEM: #{e.message}"
            end
          else
            begin
              ::OpenSSL::PKey.read(pem, password)
            rescue ::OpenSSL::PKey::PKeyError => e
              raise XmlsecRb::KeyLoadError, "could not parse key PEM: #{e.message}"
            end
          end

        new(material)
      end

      def from_der(der)
        material =
          begin
            ::OpenSSL::X509::Certificate.new(der)
          rescue ::OpenSSL::X509::CertificateError
            begin
              ::OpenSSL::PKey.read(der)
            rescue ::OpenSSL::PKey::PKeyError => e
              raise XmlsecRb::KeyLoadError, "could not parse DER key/certificate: #{e.message}"
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
            raise XmlsecRb::KeyLoadError, "could not read PKCS#12 bundle: #{e.message}"
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
              "path-like object, or XmlsecRb::Key, got #{input.class}"
      end
    end

    def initialize(material)
      @material = material
      @disposed = false
    end

    def certificate?
      @material.is_a?(::OpenSSL::X509::Certificate)
    end

    def private_key?
      @material.is_a?(::OpenSSL::PKey::PKey) && !certificate?
    end

    def to_pem
      raise XmlsecRb::KeyLoadError, "this key has been disposed" if @disposed

      @material.to_pem
    end

    def to_openssl
      @material
    end

    # Overwrites the Ruby-side PEM buffer in place and marks the key
    # unusable, for callers who want to bound the window key material is
    # resident in memory. Best-effort: Ruby Strings are GC-managed and not
    # guaranteed zeroized.
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
