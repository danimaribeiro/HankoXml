# frozen_string_literal: true

module XmlsecRb
  class Verifier
    attr_reader :policy, :id_attributes, :namespaces, :signature, :verification_time, :schema, :referenced_documents
    
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

    def verify!(xml)
      result = verify(xml)
      unless result.valid?
        # Raise the first error, or a generic VerificationError
        error = result.errors.first || XmlsecRb::VerificationError.new("Signature verification failed")
        raise error
      end
      result
    end
    
    def valid?(xml)
      verify(xml).valid?
    end

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
      # We pass trusted and untrusted certificates.
      trusted = []
      untrusted = []

      # If certificate: is set, it's trusted.
      trusted << @certificate.to_pem if @certificate
      
      # If certificates: is set, they are trusted.
      if @certificates
        trusted.concat(@certificates.map(&:to_pem))
      end
      
      # If key: is set? Native.verify doesn't currently take a bare public key, but we can pass it as untrusted or trusted?
      # Wait, Native.verify expects certificates for trusted/untrusted. For a bare key, xmlsec1 handles it differently?
      # In Phase 3, we focus on certificates since `xmlsec_rb_spec.rb` tests `validate(xml, cert)`.

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
        # Extract native errors, map to VerificationError / SignatureInvalid / UntrustedCertificate
        # For Phase 3, we just use the first error message or generic.
        msg = verify_result[:errors].first || "Signature verification failed"
        errors << XmlsecRb::VerificationError.new(msg, xmlsec_errors: verify_result[:errors], signature_node: sig_node)
      end

      # TODO: Policy enforcement

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
