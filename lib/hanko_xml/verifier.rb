# frozen_string_literal: true

module HankoXml
  # Orchestrates XML Digital Signature verification.
  # Handles fetching signatures, validating against a schema, verifying cryptographic integrity,
  # and enforcing security policies.
  class Verifier # rubocop:disable Metrics/ClassLength
    attr_reader :policy, :id_attributes, :namespaces, :signature, :verification_time, :schema, :referenced_documents,
                :resolver

    # Distinguishes "caller did not pass schema:" from "caller explicitly
    # passed schema: nil" so schema: can default to policy.schema (S-06)
    # without losing the ability to explicitly opt out.
    UNSET_SCHEMA = Object.new.freeze
    private_constant :UNSET_SCHEMA

    # Creates a new Verifier with the given trust anchors and configuration.
    # Exactly one trust source must be specified.
    #
    # @param certificate [Key, OpenSSL::X509::Certificate, String, Pathname] A single trusted certificate.
    # @param certificates [Array<Key, OpenSSL::X509::Certificate, String, Pathname>] A list of trusted certificates.
    # @param store [OpenSSL::X509::Store] An OpenSSL store of trusted root certificates.
    # @param key [Key, OpenSSL::PKey::PKey, String, Pathname] A trusted public key.
    # @param keys [Hash<String, Key>] A mapping of `<KeyName>` to trusted keys.
    # @param policy [Policy] The security policy to enforce (defaults to {Policy.strict}).
    # @param id_attributes [Array<String>] Attributes to consider as IDs for `#foo` references.
    # @param resolver [Proc, nil] Optional callable `(doc, uri_fragment) -> node` for fragment resolution in
    #   `Verification#references` / `#signed?`.
    # @param namespaces [Hash<String, String>] Namespaces for XPath signature selection.
    # @param signature [Symbol, Integer, String, nil] Which signature to verify:
    #   `:first` (explicitly take the first signature even if more exist), `:only`
    #   (require exactly one, raising {MultipleSignatures} otherwise), an
    #   integer index (document order, matching {Signer#sign!}'s `signature:`), or
    #   an XPath. Defaults to `nil`, which behaves like `:only`: with a single
    #   `<Signature>` it is verified, but with more than one {MultipleSignatures}
    #   is raised rather than silently verifying just the first (S-11) --
    #   pass `:first` to opt into the old unsafe default explicitly.
    # @param verification_time [Time, nil] The time to use for checking certificate expiration bounds.
    # @param schema [Symbol, String, Nokogiri::XML::Schema, nil] An XSD schema to
    #   pre-validate the signature node (e.g. `:default`). Defaults to
    #   `policy.schema` (S-06): `Policy.strict.schema == :default` turns on
    #   XSD validation without the caller passing `schema:` explicitly. Pass
    #   `schema: nil` explicitly to opt out regardless of the policy.
    # @param referenced_documents [Hash<String, String | Nokogiri::XML::Document>] The only source an external
    #   reference is read from, keyed by its URI (without any `#fragment`). Pass the exact bytes that were signed
    #   as a String; a Document is serialized first, which only matches if that reproduces those bytes. Nothing
    #   is ever fetched, and a URI not in the map fails with {ReferenceError} (#74).
    def initialize(certificate: nil, certificates: nil, store: nil, key: nil, keys: nil,
                   policy: HankoXml::Policy.strict, id_attributes: %w[Id ID id], resolver: nil,
                   namespaces: {}, signature: nil, verification_time: nil,
                   schema: UNSET_SCHEMA, referenced_documents: {}, certificate_subject: nil)
      supplied_trusts = [certificate, certificates, store, key, keys].compact
      if supplied_trusts.size != 1
        raise HankoXml::ConfigurationError,
              "Specify exactly one trust source: certificate, certificates, store, key, or keys"
      end

      @certificate = certificate && HankoXml::Key.coerce(certificate)
      @certificates = certificates&.map { |c| HankoXml::Key.coerce(c) }
      @store = store
      @key = key && HankoXml::Key.coerce(key)
      @keys = keys

      # resolver: is called with the caller's document, so it needs one.
      Dom.require!("Verifier resolver:") if resolver

      @policy = policy
      @id_attributes = id_attributes
      @resolver = resolver
      @namespaces = namespaces
      @signature = signature
      @verification_time = verification_time
      @schema = schema.equal?(UNSET_SCHEMA) ? policy.schema : schema
      @referenced_documents = coerce_referenced_documents(referenced_documents)
      @certificate_subject = coerce_certificate_subject(certificate_subject)

      freeze
    end

    # Verifies the target signature(s). Returns a single {Verification} object.
    # Does not raise cryptographic errors; instead, captures them in the returned object.
    #
    # @param xml [String, Nokogiri::XML::Node, Nokogiri::XML::Document, IO] The signed XML.
    # @return [HankoXml::Verification] The verification result.
    def verify(xml)
      input = HankoXml::Input.read(xml, policy: @policy)
      count = signature_count(input)

      # A missing signature is an error state: a Verification with
      # valid=false and a SignatureMissing error, never a raise.
      return missing_signature(input, "No <Signature> element found") if count.zero?

      # For :first, :only, integer, or xpath
      index = resolve_signature_target(input, count, @signature)
      return missing_signature(input, "Target signature not found") if index.nil?

      verify_single(input, index)
    end

    # Verifies the target signature(s) and raises an error if verification fails.
    #
    # @param xml [String, Nokogiri::XML::Node, Nokogiri::XML::Document, IO] The signed XML.
    # @raise [HankoXml::VerificationError] If the signature is invalid or violates policy.
    # @return [HankoXml::Verification] The valid verification result.
    def verify!(xml)
      result = verify(xml)
      unless result.valid?
        # Raise the first error, or a generic VerificationError
        error = result.errors.first || HankoXml::VerificationError.new("Signature verification failed")
        raise error
      end
      result
    end

    # Returns true if the document signature is valid.
    #
    # @param xml [String, Nokogiri::XML::Node, Nokogiri::XML::Document, IO] The signed XML.
    # @return [Boolean] True if valid, false otherwise.
    def valid?(xml)
      verify(xml).valid?
    end

    # Verifies all signatures in the document and returns an array of {Verification} results.
    #
    # @param xml [String, Nokogiri::XML::Node, Nokogiri::XML::Document, IO] The signed XML.
    # @return [Array<HankoXml::Verification>] An array of verification results.
    def verify_all(xml)
      input = HankoXml::Input.read(xml, policy: @policy)
      count = signature_count(input)

      Array.new(count) { |index| verify_single(input, index) }
    end

    # The bundled XML-DSig schema `schema: :default` validates against.
    DEFAULT_SCHEMA_PATH = File.expand_path("xmldsig-core-schema.xsd", __dir__).freeze

    # The bundled XML-DSig schema as a Nokogiri::XML::Schema, for callers who
    # validate other documents with it. `schema: :default` itself validates
    # natively and does not use this (#102). Parsed with its own path as the
    # base URL so its relative import of exc-c14n.xsd resolves (#61), and
    # only once: a racing first call just parses it twice.
    def self.default_schema
      @default_schema ||= Dom.schema_from_file(DEFAULT_SCHEMA_PATH)
    end

    private

    # A HankoXml::Error from the native layer already has its fixed message,
    # the class Rust chose, and #xmlsec_errors: keep it. Anything else gets a
    # fixed NativeError, never its own message (#96, S-13).
    def native_failure(error, message)
      return error if error.is_a?(HankoXml::Error)

      HankoXml::NativeError.new(message)
    end

    # xmlSecAddIDs (the native ID table verification resolves "#id" against)
    # matches by unqualified attribute name only -- it has no concept of the
    # namespace-qualified [ns, name] entries Verification's Ruby-side XPath
    # lookup accepts. Passing one of those arrays straight through would fail
    # Native.verify's String-array conversion, so only the local name crosses
    # the FFI boundary; namespace-qualified matching stays a Ruby-side-only
    # refinement over the same, broader native registration.
    def native_id_attributes
      @id_attributes.map { |attr| attr.is_a?(Array) ? attr[1].to_s : attr.to_s }
    end

    # The index of the <Signature> to verify among +count+ in document
    # order, or nil when the selection matches none.
    def resolve_signature_target(input, count, signature_option)
      case signature_option
      when nil, :only
        # No explicit selection: fail closed on ambiguity rather than
        # silently verifying only the first of several signatures (S-11).
        # Pass `signature: :first` to opt into the old, unsafe default.
        raise HankoXml::MultipleSignatures, "Expected exactly 1 signature, found #{count}" if count > 1

        0
      when :first
        0
      when Integer
        index = signature_option.negative? ? count + signature_option : signature_option
        index if index.between?(0, count - 1)
      when String
        xpath_signature_index(input, signature_option)
      when :all
        raise HankoXml::ConfigurationError,
              "signature: :all is not supported; use Verifier#verify_all for one Verification per <Signature> (#105)"
      else
        raise HankoXml::ConfigurationError, "Invalid signature: option"
      end
    end

    # XPath selection needs a DOM. It must pick exactly one <ds:Signature>:
    # taking the first of several matches would be `:first` again under
    # another name (S-11, #95).
    def xpath_signature_index(input, xpath)
      Dom.require!("Verifier signature: XPath selection")

      sigs = signature_nodes(input)
      namespaces = HankoXml::NS.merge(@namespaces.transform_keys(&:to_s))
      matches = input.document.xpath(xpath, namespaces).to_a & sigs
      if matches.size > 1
        raise HankoXml::MultipleSignatures,
              "signature: XPath must select exactly 1 <Signature>, selected #{matches.size}"
      end

      matches.first && sigs.index(matches.first)
    end

    # How many <ds:Signature> the document holds, from the native scan. A
    # caller's DOM over max_document_size is counted on the DOM instead, so
    # nothing native parses it (S-12); verify_single then fails each one on
    # size before any native call.
    def signature_count(input)
      return signature_nodes(input).size if input.dom? && input.bytes.bytesize > @policy.max_document_size

      input.scan(native_id_attributes)[:signature_count]
    end

    # The caller's <ds:Signature> nodes in document order, or [] without a
    # DOM. The same libxml2 walk as the native count, so indexes agree.
    def signature_nodes(input)
      return [] unless input.document

      input.document.xpath(".//ds:Signature", ds: NS["ds"]).to_a
    end

    def missing_signature(input, message)
      failed_verification(input, nil, [HankoXml::SignatureMissing.new(message)])
    end

    # The <Signature> errors run against: the XML-DSig schema natively for
    # `schema: :default`, or a caller's own Nokogiri::XML::Schema on the DOM.
    def schema_errors(input, sig_node, index)
      return Native.validate_schema(input.bytes, index, DEFAULT_SCHEMA_PATH) if @schema == :default

      Dom.require!("Verifier schema: with a custom schema")
      Dom.schema_errors(@schema, sig_node).map(&:message)
    end

    # One linear sequence of interdependent checks -- schema, policy,
    # certificate chain, time bounds, then crypto -- accumulating shared
    # state as it goes. Splitting it would thread that state through helpers
    # rather than genuinely simplify it, so the metrics cops are waived here
    # pending a deliberate refactor.
    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize
    # rubocop:disable Metrics/MethodLength, Metrics/PerceivedComplexity
    def verify_single(input, index)
      sig_node = signature_nodes(input)[index]

      # 1. max_document_size is checked before any native parse (S-12). An
      # unparsed input was already checked while it was read; this covers a
      # caller's DOM, measured by its serialized bytes.
      xml_bytes = input.bytes
      begin
        @policy.enforce_document_size!(xml_bytes.bytesize)
      rescue HankoXml::PolicyError => e
        return failed_verification(input, sig_node, [e], signature_info: nil)
      end

      # Schema validation before any crypto
      if @schema
        xsd_errors = schema_errors(input, sig_node, index)
        if xsd_errors.any?
          error = HankoXml::SchemaError.new("<Signature> does not validate against the XML-DSig schema",
                                            xmlsec_errors: xsd_errors)
          return failed_verification(input, sig_node, [error])
        end
      end

      # 2. Call Native.inspect_sig
      begin
        inspect_result = Native.inspect_sig(xml_bytes, index)
      rescue StandardError => e
        return failed_verification(input, sig_node,
                                   [native_failure(e, "the native layer could not read <SignedInfo>")])
      end

      sig_info = HankoXml::SignatureInfo.from_native(inspect_result)

      # Policy is a structural allowlist over inspect_sig output. Enforce it
      # before Native.verify so a file:// or http:// Reference is never
      # handed to libxml2 I/O (S-04). Native.verify also restricts
      # enabledReferenceUris as defense in depth. document:/sig_node:/
      # id_attributes:/xml_bytes: additionally enable require_signed_root,
      # reject_duplicate_ids, and max_document_size (S-06).
      begin
        @policy.enforce!(sig_info, id_attributes: @id_attributes,
                                   xml_bytes: xml_bytes, referenced_uris: @referenced_documents.keys)
      rescue HankoXml::PolicyError => e
        return failed_verification(input, sig_node, [e], signature_info: sig_info)
      end

      unresolved = unreferenced_external_uri(sig_info)
      if unresolved
        error = HankoXml::ReferenceError.new(
          "reference URI #{unresolved.inspect} is not in referenced_documents:, and nothing is ever fetched",
          reference_uri: unresolved
        )
        return failed_verification(input, sig_node, [error], signature_info: sig_info)
      end

      # 3. Resolve trust material and call Native.verify
      trusted, untrusted, trust_error, store_leaf = collect_trust(sig_info)
      return failed_verification(input, sig_node, [trust_error], signature_info: sig_info) if trust_error

      # min_rsa_key_bits / min_ec_key_bits (S-06): only the actually
      # resolved trust material can be checked, so this runs after
      # collect_trust rather than as part of the sig_info-only enforce!
      # above.
      begin
        @policy.enforce_key_size!(parsed_trust_keys(trusted))
      rescue HankoXml::PolicyError => e
        return failed_verification(input, sig_node, [e], signature_info: sig_info)
      end

      # Certificate expiration on the certificate:/certificates:/key: trust
      # paths (S-07). signKey pinning (S-01) means xmlsec never reads
      # KeyInfo to verify the embedded certificate, so it never checks these
      # dates either -- this Ruby-side check is the only one that runs here
      # (the store: path gets its own, equivalent check from
      # OpenSSL::X509::StoreContext above). check_certificate_validity, not
      # verification_time's presence, gates it -- an unset verification_time
      # means "now", not "skip the check" (S-07); Policy.permissive sets
      # check_certificate_validity: false to opt out entirely, matching the
      # store: path's semantics. Key PEMs are skipped: they have no
      # notBefore/notAfter. clock_skew (S-06) widens the window on both
      # ends, the same way NTP-adjacent clock drift is usually tolerated.
      if @policy.check_certificate_validity
        verification_time = @verification_time || Time.now
        skew = @policy.clock_skew
        trusted.each do |pem|
          next unless certificate_pem?(pem)

          cert = OpenSSL::X509::Certificate.new(pem)
          if verification_time < (cert.not_before - skew) || verification_time > (cert.not_after + skew)
            return failed_verification(
              input,
              sig_node,
              [HankoXml::CertificateExpired.new("Certificate expired at #{verification_time}")],
              signature_info: sig_info
            )
          end
        end
      end

      begin
        verify_result = Native.verify(xml_bytes, trusted, untrusted, native_id_attributes, index,
                                      @referenced_documents.to_a)
      rescue StandardError => e
        return failed_verification(input, sig_node,
                                   [native_failure(e, "the native layer failed unexpectedly while verifying")],
                                   signature_info: sig_info)
      end

      valid = (verify_result[:status] == :succeeded)
      errors = []

      unless valid
        # Fixed message: the xmlsec log can quote document text (S-13), so it
        # is only exposed through #xmlsec_errors.
        errors << HankoXml::VerificationError.new("Signature verification failed (#{verify_result[:status]})",
                                                  xmlsec_errors: verify_result[:errors], signature_node: sig_node)
      end

      HankoXml::Verification.new(
        valid: valid,
        errors: errors,
        signature_info: sig_info,
        signature_node: sig_node,
        document: input.document,
        namespaces: @namespaces,
        id_attributes: @id_attributes,
        resolver: @resolver,
        reference_element_indexes: verify_result[:reference_element_indexes],
        reference_valid: verify_result[:reference_valid],
        signature_element_index: input.scan(native_id_attributes)[:signature_element_indexes][index],
        certificate: valid ? verifying_certificate(trusted, verify_result[:trusted_index], store_leaf) : nil
      )
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize
    # rubocop:enable Metrics/MethodLength, Metrics/PerceivedComplexity

    # A Hash of URI => bytes, frozen. Keys drop any #fragment, the way xmlsec
    # opens the URI.
    def coerce_referenced_documents(documents)
      unless documents.is_a?(Hash)
        raise HankoXml::ConfigurationError, "referenced_documents: must be a Hash of URI => String or Document"
      end

      documents.to_h do |uri, document|
        bytes = if document.is_a?(String) then document.b
                elsif Dom.document?(document) then HankoXml.serialize(document).b
                else
                  raise HankoXml::ConfigurationError,
                        "referenced_documents: #{uri.to_s.inspect} must be a String of bytes or a " \
                        "Nokogiri::XML::Document, got #{document.class}"
                end
        [uri.to_s.split("#", 2).first.to_s.freeze, bytes.freeze]
      end.freeze
    end

    def unreferenced_external_uri(sig_info)
      sig_info.references.find { |ref| ref.external? && !@referenced_documents.key?(ref.document_uri) }&.uri
    end

    def failed_verification(input, sig_node, errors, signature_info: nil)
      HankoXml::Verification.new(
        valid: false,
        errors: errors,
        signature_info: signature_info,
        signature_node: sig_node,
        document: input.document,
        namespaces: @namespaces,
        id_attributes: @id_attributes,
        resolver: @resolver
      )
    end

    def collect_trust(sig_info)
      return keys_trust(sig_info) if @keys
      return store_trust(sig_info) if @store

      trusted = []
      trusted << @key.to_pem if @key
      trusted << @certificate.to_pem if @certificate
      trusted.concat(@certificates.map(&:to_pem)) if @certificates
      [trusted, [], nil]
    end

    def keys_trust(sig_info)
      key_name = sig_info.key_names.first
      unless key_name && @keys.key?(key_name)
        return [nil, nil,
                HankoXml::UntrustedCertificate.new("KeyName #{key_name.inspect} not found in keys: map")]
      end

      [[HankoXml::Key.coerce(@keys[key_name]).to_pem], [], nil]
    end

    def store_trust(sig_info)
      begin
        embedded = load_embedded_certificates(sig_info)
      rescue OpenSSL::X509::CertificateError => e
        return [nil, nil,
                HankoXml::UntrustedCertificate.new("Invalid X509Certificate in KeyInfo: #{e.message}")]
      end

      if embedded.empty?
        return [nil, nil,
                HankoXml::UntrustedCertificate.new("No X509Certificate found in KeyInfo for store verification")]
      end

      leaf, error = verified_leaf_from_store(embedded)
      error ||= signing_certificate_violation(leaf)
      return [nil, nil, error] if error

      # xmlsec treats trusted cert PEMs as CA anchors and still X509-verifies
      # every KeyInfo cert. A CA:FALSE leaf therefore cannot be "pinned" that
      # way. After Ruby has enforced chain policy, pin the leaf public key as
      # signKey (same path as `key:`) so KeyInfo is ignored. The leaf itself is
      # what trust resolved to, for Verification#certificate.
      [[leaf.public_key.to_pem], [], nil, leaf]
    end

    def load_embedded_certificates(sig_info)
      sig_info.certificates.map { |pem| OpenSSL::X509::Certificate.new(pem) }
    end

    def verified_leaf_from_store(certificates)
      candidates = end_entity_certificates(certificates)
      candidates = certificates if candidates.empty?

      verified = []
      last_error = "Certificate chain validation failed"

      candidates.each do |leaf|
        chain = certificates.reject { |cert| cert.equal?(leaf) }
        ctx = OpenSSL::X509::StoreContext.new(@store, leaf, chain)
        if @policy.check_certificate_validity
          ctx.time = @verification_time if @verification_time
        else
          ctx.flags = OpenSSL::X509::V_FLAG_NO_CHECK_TIME
        end

        if ctx.verify
          verified << leaf
        else
          message = ctx.error_string.to_s
          last_error = message.empty? ? last_error : "Certificate chain validation failed: #{message}"
        end
      end

      case verified.size
      when 1
        [verified.first, nil]
      when 0
        [nil, HankoXml::UntrustedCertificate.new(last_error)]
      else
        [nil, HankoXml::UntrustedCertificate.new(
          "Ambiguous KeyInfo: multiple certificates chain to the trust store"
        )]
      end
    end

    # End-entity certs in this KeyInfo set: nobody else in the set was issued
    # by them. Document order is not a leaf indicator (XML-DSig does not
    # require leaf-first X509Certificate).
    # KeyUsage bits (RFC 5280 §4.2.1.3), numbered from the most significant
    # bit of the BIT STRING.
    DIGITAL_SIGNATURE_BIT = 0
    NON_REPUDIATION_BIT = 1
    private_constant :DIGITAL_SIGNATURE_BIT, :NON_REPUDIATION_BIT

    def coerce_certificate_subject(subject)
      return nil if subject.nil?
      unless @store
        raise HankoXml::ConfigurationError,
              "certificate_subject: only applies to store: (the other trust sources already pin the key)"
      end
      return subject.dup.freeze if subject.is_a?(String)
      return subject if subject.is_a?(OpenSSL::X509::Name)

      raise HankoXml::ConfigurationError,
            "certificate_subject: must be a String (the CN) or an OpenSSL::X509::Name, got #{subject.class}"
    end

    # Certificate-usage policy on the leaf store: already validated (#63):
    # KeyUsage and the optional certificate_subject:.
    def signing_certificate_violation(leaf)
      if @policy.require_signing_key_usage && !signing_key_usage?(leaf)
        return HankoXml::UntrustedCertificate.new(
          "signing certificate's KeyUsage allows neither digitalSignature nor nonRepudiation " \
          "(require_signing_key_usage)"
        )
      end
      return nil if @certificate_subject.nil? || certificate_subject_matches?(leaf)

      HankoXml::UntrustedCertificate.new(
        "signing certificate subject #{leaf.subject} does not match certificate_subject: #{@certificate_subject}"
      )
    end

    # No KeyUsage extension means no restriction (RFC 5280). When present,
    # either bit is enough: qualified signing certificates (eIDAS/XAdES) often
    # carry nonRepudiation alone.
    def signing_key_usage?(cert)
      extension = cert.extensions.find { |ext| ext.oid == "keyUsage" }
      return true if extension.nil?

      bits = OpenSSL::ASN1.decode(extension.value_der).value.to_s.unpack1("B*").to_s
      [DIGITAL_SIGNATURE_BIT, NON_REPUDIATION_BIT].any? { |bit| bits[bit] == "1" }
    rescue OpenSSL::ASN1::ASN1Error
      false
    end

    # A String must be the certificate's only CN; an X509::Name must equal
    # the whole subject.
    def certificate_subject_matches?(cert)
      return cert.subject.cmp(@certificate_subject).zero? if @certificate_subject.is_a?(OpenSSL::X509::Name)

      common_names = cert.subject.to_a.filter_map { |name, value, _type| value if name == "CN" }
      common_names == [@certificate_subject]
    end

    def end_entity_certificates(certificates)
      certificates.select do |candidate|
        certificates.none? { |other| issued_by?(other, candidate) }
      end
    end

    def issued_by?(cert, issuer)
      !cert.equal?(issuer) && cert.issuer.to_der == issuer.subject.to_der
    end

    # API_CONTRACT.md §5.4 `v.certificate`: the certificate whose key verified
    # the signature. Native reports which trusted PEM that was; under store:
    # it is the chain leaf Ruby validated. nil for a bare key (key:, or a
    # public key in keys:).
    def verifying_certificate(trusted, trusted_index, store_leaf)
      return store_leaf if store_leaf
      return nil if trusted_index.nil?

      pem = trusted[trusted_index]
      pem && certificate_pem?(pem) ? OpenSSL::X509::Certificate.new(pem) : nil
    end

    def certificate_pem?(pem)
      pem.include?("BEGIN CERTIFICATE")
    end

    # Parses collect_trust's PEM Strings into OpenSSL objects for
    # Policy#enforce_key_size! (S-06). A PEM that fails to parse here would
    # already have failed identically inside Native.verify; skip it rather
    # than raise a second, redundant error.
    def parsed_trust_keys(trusted)
      trusted.filter_map do |pem|
        if certificate_pem?(pem)
          OpenSSL::X509::Certificate.new(pem)
        else
          HankoXml::Key.read_pkey(pem, nil)
        end
      rescue OpenSSL::OpenSSLError
        nil
      end
    end
  end
end
