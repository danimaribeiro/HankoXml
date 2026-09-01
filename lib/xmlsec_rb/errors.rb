# frozen_string_literal: true

module XmlsecRb
  # Base class for everything this gem raises. Rescue this to catch anything
  # xmlsec_rb-specific. See API_CONTRACT.md §5.10 for the full hierarchy and
  # the reasoning behind it (in particular: never KeyError/ArgumentError/
  # TypeError/IOError, which would shadow core Ruby constants inside this
  # module).
  class Error < StandardError
    # Structured xmlsec1 error log lines captured for this failure, when the
    # native layer produced any (populated starting Phase 2).
    attr_accessor :xmlsec_errors

    # The <ds:Signature> Nokogiri::XML::Element this error relates to, when
    # one was located.
    attr_accessor :signature_node

    def initialize(message = nil, xmlsec_errors: [], signature_node: nil)
      super(message)
      @xmlsec_errors = xmlsec_errors
      @signature_node = signature_node
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

  # A caller-supplied `resolver:` and xmlsec's own ID resolution disagreed on
  # what a Reference URI points to. See API_CONTRACT.md §5.9.
  class ResolutionMismatch < VerificationError; end

  # Verification#at_signed found a node the signature does not cover.
  class NotSignedError < Error; end

  # A mutator was called on a XmlsecRb::SignedDocument.
  class FrozenSignatureError < Error; end

  # libxmlsec1 failed in an unexpected way.
  class NativeError < Error; end
end
