# frozen_string_literal: true

require "openssl"

module HankoXml
  # Base class for everything this gem raises. Rescue this to catch anything
  # hanko_xml-specific. See API_CONTRACT.md §5.10 for the full hierarchy and
  # the reasoning behind it (in particular: never KeyError/ArgumentError/
  # TypeError/IOError, which would shadow core Ruby constants inside this
  # module).
  class Error < StandardError
    # A private key in PEM form, including a truncated one. Redacted from
    # every message and log line (API_CONTRACT.md §5.10, #96).
    PRIVATE_KEY_PEM = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)/m
    FILTERED = "[FILTERED]"

    # The xmlsec1 error log lines captured for this failure, or libxml2's
    # diagnostics for a ParseError / SchemaError. Untrusted: they can quote
    # the document.
    attr_reader :xmlsec_errors

    # The <ds:Signature> Nokogiri::XML::Element this error relates to, when
    # one was located.
    attr_accessor :signature_node

    # Never carries key material: a HankoXml::Key or OpenSSL::PKey passed as
    # +message+ becomes [FILTERED], and private-key PEM text is redacted.
    # (NativeVersionMismatch can be raised before key.rb is loaded.)
    def self.filter(value)
      return nil if value.nil?
      return FILTERED if value.is_a?(OpenSSL::PKey::PKey) || (defined?(HankoXml::Key) && value.is_a?(HankoXml::Key))

      value.to_s.gsub(PRIVATE_KEY_PEM, FILTERED)
    end

    def initialize(message = nil, xmlsec_errors: [], signature_node: nil)
      super(Error.filter(message))
      self.xmlsec_errors = xmlsec_errors
      @signature_node = signature_node
    end

    def xmlsec_errors=(lines)
      @xmlsec_errors = Array(lines).map { |line| Error.filter(line) }
    end
  end

  # Invalid Signer/Verifier construction.
  class ConfigurationError < Error; end

  # A Policy allowlist was violated.
  class PolicyError < ConfigurationError; end

  # A Placement XPath matched zero or more than one node.
  class PlacementError < ConfigurationError; end

  # The requested capability needs a DOM, and Nokogiri is not loaded. See
  # API_CONTRACT.md §6.1.
  class NokogiriRequired < ConfigurationError; end

  # <Signature> failed XSD validation (Verifier schema: option).
  class SchemaError < ConfigurationError; end

  # The XML would not parse.
  class ParseError < Error; end

  # A key or certificate was unreadable or in an unsupported format.
  class KeyLoadError < Error; end

  # A Reference target does not exist, is ambiguous, or has no ID attribute.
  class ReferenceError < Error
    attr_accessor :reference_uri

    def initialize(message = nil, reference_uri: nil, **kwargs)
      super(message, **kwargs)
      @reference_uri = reference_uri
    end
  end

  # libxmlsec1 could not produce a signature.
  class SigningError < Error; end

  # Verification did not succeed (raised by #verify!).
  class VerificationError < Error; end

  # The signature verified as XML-DSig, but its XAdES signed properties do not
  # hold: they are not the ones xmlsec digested, or they do not commit to the
  # certificate that verified (#58).
  class XadesError < VerificationError; end

  # Cryptographic mismatch.
  class SignatureInvalid < VerificationError; end

  # No <ds:Signature> in the document.
  class SignatureMissing < VerificationError; end

  # Verifier#signature was :only and the document has more than one.
  class MultipleSignatures < VerificationError; end

  # Certificate/key trust resolution (chain or pinning) failed.
  class UntrustedCertificate < VerificationError; end

  # Certificate is outside notBefore/notAfter as of verification_time.
  class CertificateExpired < VerificationError; end

  # One <Reference>'s digest did not match.
  class DigestMismatch < VerificationError
    attr_accessor :reference_uri

    def initialize(message = nil, reference_uri: nil, **kwargs)
      super(message, **kwargs)
      @reference_uri = reference_uri
    end
  end

  # A caller-supplied `resolver:` and xmlsec's ID table disagreed on what a
  # Reference URI points to. See API_CONTRACT.md §5.9.
  class ResolutionMismatch < VerificationError; end

  # Verification#at_signed found a node the signature does not cover.
  class NotSignedError < Error; end

  # A mutator was called on a HankoXml::SignedDocument.
  class FrozenSignatureError < Error; end

  # libxmlsec1 failed in an unexpected way.
  class NativeError < Error; end

  # The loaded libxmlsec1 is not ABI compatible with the headers this
  # extension was compiled against. Raised at require time by
  # {HankoXml::NativeVersion}; see that file for why this cannot be a warning.
  class NativeVersionMismatch < NativeError; end
end
