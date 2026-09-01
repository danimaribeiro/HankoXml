# frozen_string_literal: true

module XmlsecRb
  # Orchestrates XML Digital Signature verification.
  # Handles fetching signatures, validating against a schema, verifying cryptographic integrity,
  # and enforcing security policies.
  class Verifier
    attr_reader :policy, :id_attributes, :namespaces, :signature, :verification_time, :schema, :referenced_documents
    
    # Creates a new Verifier with the given trust anchors and configuration.
    # Note: You must specify exactly one trust source.
    #
    # @param certificate [Key, OpenSSL::X509::Certificate, String, Pathname] A single trusted certificate.
    # @param certificates [Array<Key, OpenSSL::X509::Certificate, String, Pathname>] A list of trusted certificates.
    # @param store [OpenSSL::X509::Store] An OpenSSL store of trusted root certificates.
    # @param key [Key, OpenSSL::PKey::PKey, String, Pathname] A trusted public key.
    # @param keys [Hash<String, Key>] A mapping of `<KeyName>` to trusted keys.
    # @param policy [Policy] The security policy to enforce (defaults to {Policy.strict}).
    # @param id_attributes [Array<String>] Attributes to consider as IDs for `#foo` references.
    # @param namespaces [Hash<String, String>] Namespaces for XPath signature selection.
    # @param signature [Symbol, Integer, String] Which signature to verify: `:first`, `:only`, `:all`, an integer index, or an XPath.
    # @param verification_time [Time, nil] The time to use for checking certificate expiration bounds.
    # @param schema [Symbol, String, Nokogiri::XML::Schema, nil] An XSD schema to pre-validate the signature node (e.g. `:default`).
    # @param referenced_documents [Hash<String, Nokogiri::XML::Document>] Documents to resolve external references.
    def initialize(certificate: nil, certificates: nil, store: nil, key: nil, keys: nil,
                   policy: XmlsecRb::Policy.strict, id_attributes: %w[Id ID id],
                   namespaces: {}, signature: :first, verification_time: nil,
                   schema: nil, referenced_documents: {})
      supplied_trusts = [certificate, certificates, store, key, keys].compact
      if supplied_trusts.size > 1
        raise XmlsecRb::ConfigurationError, "Specify exactly one trust source: certificate, certificates, store, key, or keys"
      end
      
      @certificate = certificate && XmlsecRb::Key.coerce(certificate)
      @certificates = certificates && certificates.map { |c| XmlsecRb::Key.coerce(c) }
      @store = store
      @key = key && XmlsecRb::Key.coerce(key)
      @keys = keys
      
      @policy = policy
      @id_attributes = id_attributes
      @namespaces = namespaces
      @signature = signature
      @verification_time = verification_time
      @schema = schema
      @referenced_documents = referenced_documents
      
      freeze
    end

    # Verifies the target signature(s). Returns a single {Verification} object.
    # Does not raise cryptographic errors; instead, captures them in the returned object.
    #
    # @param xml [String, Nokogiri::XML::Node, Nokogiri::XML::Document, IO] The signed XML.
    # @return [XmlsecRb::Verification] The verification result.
    def verify(xml)
      doc = XmlsecRb.coerce_document(xml)
      # Find signatures
      sigs = doc.xpath(".//ds:Signature", ds: NS["ds"])
      
      if sigs.empty?
        # Verification requires a signature, but verify() is supposed to return a failed Verification.
        # Wait, if there are no signatures, what does Verification hold?
        # A missing signature is an error state, we can return a Verification with valid=false and a SignatureMissing error.
        return XmlsecRb::Verification.new(
          valid: false,
          errors: [XmlsecRb::SignatureMissing.new("No <Signature> element found")],
          signature_info: nil,
          signature_node: nil,
          document: doc
        )
      end

      # For :first, :only, integer, or xpath
      target_sig, index = resolve_signature_target(sigs, @signature)

      if target_sig.nil?
        return XmlsecRb::Verification.new(
          valid: false,
          errors: [XmlsecRb::SignatureMissing.new("Target signature not found")],
          signature_info: nil,
          signature_node: nil,
          document: doc
        )
      end

      verify_single(doc, target_sig, index)
    end

    # Verifies the target signature(s) and raises an error if verification fails.
    #
    # @param xml [String, Nokogiri::XML::Node, Nokogiri::XML::Document, IO] The signed XML.
    # @raise [XmlsecRb::VerificationError] If the signature is invalid or violates policy.
    # @return [XmlsecRb::Verification] The valid verification result.
    def verify!(xml)
      result = verify(xml)
      unless result.valid?
        # Raise the first error, or a generic VerificationError
        error = result.errors.first || XmlsecRb::VerificationError.new("Signature verification failed")
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
    # @return [Array<XmlsecRb::Verification>] An array of verification results.
    def verify_all(xml)
      doc = XmlsecRb.coerce_document(xml)
      sigs = doc.xpath(".//ds:Signature", ds: NS["ds"])
      
      return [] if sigs.empty?

      sigs.map.with_index do |sig, index|
        verify_single(doc, sig, index)
      end
    end

    private

    def resolve_signature_target(sigs, signature_option)
      case signature_option
      when :first
        [sigs.first, 0]
      when :only
        if sigs.size > 1
          raise XmlsecRb::MultipleSignatures, "Expected exactly 1 signature, found #{sigs.size}"
        end
        [sigs.first, 0]
      when Integer
        [sigs[signature_option], signature_option]
      when String
        # XPath
        node = sigs.document.at_xpath(signature_option)
        index = sigs.index(node)
        [node, index]
      else
        raise XmlsecRb::ConfigurationError, "Invalid signature: option"
      end
    end

    def verify_single(doc, sig_node, index)
      # Schema validation before any crypto
      if @schema
        xsd = if @schema == :default
                ::Nokogiri::XML::Schema(File.read(File.expand_path("xmldsig-core-schema.xsd", __dir__)))
              else
                @schema
              end
        tmp_doc = Nokogiri::XML::Document.new
        tmp_doc.add_child(sig_node.dup)
        xsd_errors = xsd.validate(tmp_doc)
        if xsd_errors.any?
          return XmlsecRb::Verification.new(
            valid: false,
            errors: [XmlsecRb::SchemaError.new(xsd_errors.map(&:message).join(", "))],
            signature_info: nil,
            signature_node: sig_node,
            document: doc
          )
        end
      end

      # 1. Serialize document to bytes
      xml_bytes = XmlsecRb.serialize(doc)

      # 2. Call Native.inspect_sig
      begin
        inspect_result = Native.inspect_sig(xml_bytes, index)
      rescue => e
        return XmlsecRb::Verification.new(
          valid: false,
          errors: [XmlsecRb::ParseError.new(e.message)],
          signature_info: nil,
          signature_node: sig_node,
          document: doc
        )
      end

      sig_info = XmlsecRb::SignatureInfo.from_native(inspect_result)

      # 3. Call Native.verify
      trusted = []
      untrusted = []
      
      # Select key from `keys:` if `keys` is provided
      if @keys
        key_name = sig_info.key_names.first
        if key_name && @keys.key?(key_name)
          cert_or_key = XmlsecRb::Key.coerce(@keys[key_name])
          if cert_or_key.certificate?
            trusted << cert_or_key.to_pem
          end
        else
          return XmlsecRb::Verification.new(
            valid: false,
            errors: [XmlsecRb::UntrustedCertificate.new("KeyName #{key_name.inspect} not found in keys: map")],
            signature_info: sig_info,
            signature_node: sig_node,
            document: doc
          )
        end
      end

      trusted << @certificate.to_pem if @certificate
      
      if @certificates
        trusted.concat(@certificates.map(&:to_pem))
      end

      # Check certificate expiration in Ruby if verification_time is set
      # (Ideally, we pass time to native store, but for now we do it here if possible)
      if @verification_time
        # For each trusted cert, check if verification_time is within bounds
        # If any is out of bounds, we could fail early or let xmlsec fail.
        # But xmlsec1 doesn't accept a time parameter in our API yet.
        # So we validate the parsed certs here.
        trusted.each do |pem|
          cert = OpenSSL::X509::Certificate.new(pem)
          if @verification_time < cert.not_before || @verification_time > cert.not_after
            return XmlsecRb::Verification.new(
              valid: false,
              errors: [XmlsecRb::CertificateExpired.new("Certificate expired at #{@verification_time}")],
              signature_info: sig_info,
              signature_node: sig_node,
              document: doc
            )
          end
        end
      end

      begin
        verify_result = Native.verify(xml_bytes, trusted, untrusted, @id_attributes, index)
      rescue => e
        return XmlsecRb::Verification.new(
          valid: false,
          errors: [XmlsecRb::NativeError.new(e.message)],
          signature_info: sig_info,
          signature_node: sig_node,
          document: doc
        )
      end

      valid = (verify_result[:status] == :succeeded)
      errors = []

      if !valid
        msg = verify_result[:errors].first || "Signature verification failed"
        errors << XmlsecRb::VerificationError.new(msg, xmlsec_errors: verify_result[:errors], signature_node: sig_node)
      end

      # TODO: Policy enforcement
      begin
        @policy.enforce!(sig_info)
      rescue XmlsecRb::PolicyError => e
        valid = false
        errors << e
      end

      XmlsecRb::Verification.new(
        valid: valid,
        errors: errors,
        signature_info: sig_info,
        signature_node: sig_node,
        document: doc
      )
    end
  end
end
