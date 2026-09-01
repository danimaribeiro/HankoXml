# frozen_string_literal: true

module XmlsecRb
  # Declares the parts of a signature -- references, transforms, KeyInfo
  # clauses, placement -- and builds the <Signature> template from them.
  # See API_CONTRACT.md §5.2.
  #
  # A Signer is frozen after construction: immutable, reusable, safe to
  # share across threads.
  #
  # Phase 1 implements everything needed to inspect what a Signer would
  # produce (#template, #to_h). Actually signing (#sign / #sign!) needs the
  # native rewrite (§14 Phase 2/3) and is not implemented yet.
  class Signer
    TEMPLATE_MODES = %i[adopt build require].freeze

    attr_accessor :key, :certificate, :certificates, :signature_method, :canonicalization_method,
                  :digest_method, :references, :placement, :id_attributes, :namespaces,
                  :signature_id, :policy, :key_info
    attr_reader :template_mode

    # Creates a new Signer with the given configuration.
    # Yields +self+ to a block if provided, allowing block-based configuration before freezing.
    #
    # @param key [Key, OpenSSL::PKey::PKey, String, Pathname] The private key used to sign the document.
    # @param certificate [Key, OpenSSL::X509::Certificate, String, Pathname, nil] The certificate corresponding to the key.
    # @param certificates [Array<Key, OpenSSL::X509::Certificate, String, Pathname>] Extra certificates for the chain.
    # @param signature_method [Symbol] The signature algorithm (e.g., :rsa_sha256).
    # @param digest_method [Symbol] The digest algorithm for references (e.g., :sha256).
    # @param canonicalization_method [Symbol] The canonicalization method for SignedInfo (e.g., :exc_c14n).
    # @param placement [Placement, Symbol] Where to insert the `<Signature>` node (e.g., :append_to_root).
    # @param references [Array<Reference, String, Hash>] The references to sign.
    # @param key_info [Array<Symbol>] The elements to include in `<KeyInfo>` (e.g., :x509_certificate, :key_name).
    # @param id_attributes [Array<String>] The attribute names considered as IDs for `#foo` references.
    # @param template [Symbol] Either :adopt (reuse existing signature template), :build, or :require.
    # @param signature_id [String, nil] The Id attribute to place on the `<Signature>` element itself.
    def initialize(key:, certificate: nil, certificates: nil, signature_method: :rsa_sha256,
                   canonicalization_method: :exc_c14n, digest_method: :sha256, references: [],
                   key_info: [:x509_certificate], placement: :append_to_root,
                   id_attributes: %w[Id ID id], namespaces: {}, signature_id: nil,
                   policy: XmlsecRb::Policy.strict, template: :adopt)
      unless key.is_a?(XmlsecRb::Key) || Dom.pkey?(key) || key.is_a?(String) ||
             key.respond_to?(:to_path)
        raise XmlsecRb::ConfigurationError,
              "key: must be key material or an XmlsecRb::Key (external signers are not supported " \
              "in v1 -- see API_CONTRACT.md §5.2)"
      end

      unless TEMPLATE_MODES.include?(template.to_sym)
        raise XmlsecRb::ConfigurationError, "template: must be one of #{TEMPLATE_MODES.inspect}"
      end

      @key = XmlsecRb::Key.coerce(key)
      @certificate = certificate && XmlsecRb::Key.coerce(certificate)
      @certificates = Array(certificates).map { |c| XmlsecRb::Key.coerce(c) }
      @signature_method = signature_method
      @canonicalization_method = canonicalization_method
      @digest_method = digest_method
      @references = Array(references).map { |r| XmlsecRb::Reference.coerce(r) }
      @key_info = XmlsecRb::KeyInfo.coerce(key_info)
      @placement = XmlsecRb::Placement.coerce(placement) || XmlsecRb::Placement.append_to_root
      @id_attributes = id_attributes
      @namespaces = namespaces
      @signature_id = signature_id
      @policy = policy
      @template_mode = template.to_sym

      yield self if block_given?

      freeze
    end

    # Adds a Reference. Block form only -- see API_CONTRACT.md §5.2.
    def reference(uri = "", **kwargs)
      references << XmlsecRb::Reference.new(uri: uri, **kwargs)
    end

    # With no args, the current KeyInfo clauses. With args, replaces them --
    # block-form usage per API_CONTRACT.md §5.2 (`s.key_info :x509_certificate`).
    def key_info(*clauses)
      return @key_info if clauses.empty?

      @key_info = XmlsecRb::KeyInfo.coerce(clauses.flatten)
    end

    # The unsigned <Signature> Nokogiri::XML::Element this Signer would
    # build and insert, given its current configuration. Does not insert
    # it into +doc_or_xml+ and performs no cryptography -- for inspection
    # and testing (§5.2).
    def template(doc_or_xml)
      doc = XmlsecRb.coerce_document(doc_or_xml)
      XmlsecRb::Template.build(doc, self)
    end

    def to_h
      {
        key: key, certificate: certificate, certificates: certificates,
        signature_method: signature_method, canonicalization_method: canonicalization_method,
        digest_method: digest_method, references: references, key_info: key_info,
        placement: placement, id_attributes: id_attributes, namespaces: namespaces,
        signature_id: signature_id, policy: policy, template: template_mode
      }
    end

    # Signs a document without modifying the original.
    # Returns a {SignedDocument} safe for serialization.
    #
    # @param doc_or_xml [String, Nokogiri::XML::Node, Nokogiri::XML::Document, IO] The document to sign.
    # @param force [Boolean] Whether to re-sign already signed signatures.
    # @param signature [Symbol, Integer, String, nil] The target signature to sign (defaults to all).
    # @return [XmlsecRb::SignedDocument] The new signed document.
    def sign(doc_or_xml, force: false, signature: nil)
      doc = XmlsecRb.coerce_document(doc_or_xml)
      # Deep clone the document to avoid mutating the input if it's already a document.
      cloned = doc.dup
      sign!(cloned, force: force, signature: signature)
      XmlsecRb::SignedDocument.new(cloned)
    end

    # Signs a Nokogiri XML document in place.
    # Mutates the provided document by appending/writing back signature bytes.
    #
    # @param doc_or_xml [Nokogiri::XML::Node, Nokogiri::XML::Document] The document to mutate.
    # @param force [Boolean] Whether to re-sign already signed signatures.
    # @param signature [Symbol, Integer, String, nil] The target signature to sign (defaults to all).
    # @return [Nokogiri::XML::Node, Nokogiri::XML::Document] The mutated document.
    def sign!(doc_or_xml, force: false, signature: nil)
      doc = XmlsecRb.coerce_document(doc_or_xml)
      Dom.require!("XmlsecRb::Signer#sign!")

      # 1. Find existing signatures or build one
      signatures = find_or_build_signatures(doc)

      # Sort by depth descending (innermost first)
      signatures.sort_by! { |node| -node.ancestors.size }

      signatures_to_sign = if signature
                             [signatures[signature]].compact
                           else
                             signatures
                           end

      # Filter out already signed if not forced
      unless force
        signatures_to_sign.reject! { |node| node_signed?(node) }
      end

      # If there's nothing to sign, return the doc as-is
      return doc if signatures_to_sign.empty?

      # 2. Serialize the DOM state to bytes
      xml_bytes = XmlsecRb.serialize(doc)

      # 3. For each signature to sign, we call the native layer sequentially.
      # Wait, Native.sign takes a single signature_index and returns a fully signed byte array.
      # But since Native.sign returns bytes, and we need to sign multiple, we can do it iteratively
      # on the byte string, but that changes the signature index if we re-parse!
      # Actually, since we only need to write back, we can just call Native.sign for all indices,
      # but Native.sign operates on one index at a time.
      # Let's do it correctly: for each signature node, find its index in document order,
      # sign it via Native.sign, update xml_bytes for the next iteration.
      signatures_to_sign.each do |sig_node|
        # In the *current* xml_bytes, we need the document-order index of this signature.
        # But wait, we can just sign it and update xml_bytes.
        # To find its index, we can search the Nokogiri document since we haven't changed the DOM structure.
        all_sigs_in_order = doc.xpath(".//ds:Signature", ds: NS["ds"])
        index = all_sigs_in_order.index(sig_node)
        
        cert_pems = @certificates.map(&:to_pem)
        cert_pems.unshift(@certificate.to_pem) if @certificate

        xml_bytes = Native.sign(
          xml_bytes,
          @key.to_pem,
          cert_pems,
          @id_attributes,
          index
        )

        # 4. Write back the signed values to the caller's node
        write_back_signature(doc, xml_bytes, index, sig_node)
      end

      doc
    end

    def inspect
      "#<#{self.class} key=[FILTERED] signature_method=#{signature_method.inspect} " \
        "canonicalization_method=#{canonicalization_method.inspect} digest_method=#{digest_method.inspect} " \
        "references=#{references.size}>"
    end

    private

    def find_or_build_signatures(doc)
      existing = doc.xpath(".//ds:Signature", ds: NS["ds"]).to_a
      
      if existing.empty?
        raise XmlsecRb::ConfigurationError, "template: :require but no <Signature> found" if @template_mode == :require
        
        # Build one
        template_node = template(doc)
        @placement.insert(doc, template_node)
        [template_node]
      else
        raise XmlsecRb::ConfigurationError, "template: :build but <Signature> already exists" if @template_mode == :build
        
        existing
      end
    end

    def node_signed?(sig_node)
      val = sig_node.at_xpath("./ds:SignatureValue", ds: NS["ds"])
      val && !val.content.strip.empty?
    end

    def write_back_signature(doc, signed_bytes, index, caller_sig_node)
      # Parse the signed bytes
      signed_doc = XmlsecRb.parse(signed_bytes)
      signed_sigs = signed_doc.xpath(".//ds:Signature", ds: NS["ds"])
      signed_sig_node = signed_sigs[index]

      # Copy ds:Reference/ds:DigestValue
      caller_refs = caller_sig_node.xpath(".//ds:Reference", ds: NS["ds"])
      signed_refs = signed_sig_node.xpath(".//ds:Reference", ds: NS["ds"])
      
      caller_refs.each_with_index do |caller_ref, i|
        signed_ref = signed_refs[i]
        caller_dv = caller_ref.at_xpath("./ds:DigestValue", ds: NS["ds"])
        signed_dv = signed_ref.at_xpath("./ds:DigestValue", ds: NS["ds"])
        
        if caller_dv && signed_dv
          caller_dv.content = signed_dv.content
        end
      end

      # Copy ds:SignatureValue
      caller_sv = caller_sig_node.at_xpath("./ds:SignatureValue", ds: NS["ds"])
      signed_sv = signed_sig_node.at_xpath("./ds:SignatureValue", ds: NS["ds"])
      if caller_sv && signed_sv
        caller_sv.content = signed_sv.content
      end

      # Copy KeyInfo//X509Certificate (and KeyValue leaves if applicable, though for now we just copy X509Certificate)
      caller_certs = caller_sig_node.xpath(".//ds:KeyInfo//ds:X509Certificate", ds: NS["ds"])
      signed_certs = signed_sig_node.xpath(".//ds:KeyInfo//ds:X509Certificate", ds: NS["ds"])
      
      # If caller has no X509Certificate but signed does, append it to X509Data
      if caller_certs.empty? && signed_certs.any?
        x509_data = caller_sig_node.at_xpath(".//ds:KeyInfo/ds:X509Data", ds: NS["ds"])
        if x509_data
          signed_certs.each do |signed_cert|
            new_cert = doc.create_element("X509Certificate")
            new_cert.namespace = x509_data.namespace
            x509_data.add_child(new_cert)
            new_cert.content = signed_cert.content
          end
        end
      else
        caller_certs.each_with_index do |caller_cert, i|
          signed_cert = signed_certs[i]
          if signed_cert
            caller_cert.content = signed_cert.content
          end
        end
      end
    end
  end
end
