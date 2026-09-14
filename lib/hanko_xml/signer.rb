# frozen_string_literal: true

module HankoXml
  # Declares the parts of a signature -- references, transforms, KeyInfo
  # clauses, placement -- and builds the <Signature> template from them.
  # See API_CONTRACT.md §5.2.
  #
  # A Signer is frozen after construction: immutable, reusable, safe to
  # share across threads.
  #
  # #template and #to_h inspect what a Signer would produce without signing;
  # #sign and #sign! perform the signature through the native extension.
  class Signer # rubocop:disable Metrics/ClassLength
    TEMPLATE_MODES = %i[adopt build require].freeze

    attr_accessor :key, :certificate, :certificates, :signature_method, :canonicalization_method,
                  :digest_method, :references, :placement, :id_attributes, :namespaces,
                  :signature_id, :policy
    attr_reader :template_mode
    # Reader only: #key_info below is a dual getter/setter (API_CONTRACT.md
    # §5.2), so an attr_accessor reader here would be dead code shadowed by it.
    attr_writer :key_info

    # Creates a new Signer with the given configuration.
    # Yields +self+ to a block if provided, allowing block-based configuration before freezing.
    #
    # @param key [Key, OpenSSL::PKey::PKey, String, Pathname] The private key used to sign the document.
    # @param certificate [Key, OpenSSL::X509::Certificate, String, Pathname, nil]
    #   The certificate corresponding to the key.
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
                   policy: HankoXml::Policy.strict, template: :adopt)
      unless key.is_a?(HankoXml::Key) || Dom.pkey?(key) || key.is_a?(String) ||
             key.respond_to?(:to_path)
        raise HankoXml::ConfigurationError,
              "key: must be key material or an HankoXml::Key (external signers are not supported " \
              "in v1 -- see API_CONTRACT.md §5.2)"
      end

      unless TEMPLATE_MODES.include?(template.to_sym)
        raise HankoXml::ConfigurationError, "template: must be one of #{TEMPLATE_MODES.inspect}"
      end

      @key = HankoXml::Key.coerce(key)
      @certificate = certificate && HankoXml::Key.coerce(certificate)
      @certificates = Array(certificates).map { |c| HankoXml::Key.coerce(c) }
      @signature_method = signature_method
      @canonicalization_method = canonicalization_method
      @digest_method = digest_method
      @references = Array(references).map { |r| HankoXml::Reference.coerce(r) }
      @key_info = HankoXml::KeyInfo.coerce(key_info)
      @placement = HankoXml::Placement.coerce(placement) || HankoXml::Placement.append_to_root
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
      references << HankoXml::Reference.new(uri: uri, **kwargs)
    end

    # With no args, the current KeyInfo clauses. With args, replaces them --
    # block-form usage per API_CONTRACT.md §5.2 (`s.key_info :x509_certificate`).
    def key_info(*clauses)
      return @key_info if clauses.empty?

      @key_info = HankoXml::KeyInfo.coerce(clauses.flatten)
    end

    # The unsigned <Signature> Nokogiri::XML::Element this Signer would
    # build and insert, given its current configuration. Does not insert
    # it into +doc_or_xml+ and performs no cryptography -- for inspection
    # and testing (§5.2).
    def template(doc_or_xml)
      doc = HankoXml.coerce_document(doc_or_xml)
      HankoXml::Template.build(doc, self)
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
    # @return [HankoXml::SignedDocument] The new signed document.
    def sign(doc_or_xml, force: false, signature: nil)
      doc = HankoXml.coerce_document(doc_or_xml)
      # Deep clone the document to avoid mutating the input if it's already a document.
      cloned = doc.dup
      sign!(cloned, force: force, signature: signature)
      HankoXml::SignedDocument.new(cloned)
    end

    # Signs a Nokogiri XML document in place.
    # Mutates the provided document by appending/writing back signature bytes.
    #
    # @param doc_or_xml [Nokogiri::XML::Node, Nokogiri::XML::Document] The document to mutate.
    # @param force [Boolean] Whether to re-sign already signed signatures.
    # @param signature [Symbol, Integer, String, nil] The target signature to sign
    #   (defaults to all). An Integer indexes document order, matching
    #   {Verifier}'s `signature:` Integer index (S-11).
    # @return [Nokogiri::XML::Node, Nokogiri::XML::Document] The mutated document.
    def sign!(doc_or_xml, force: false, signature: nil)
      doc = HankoXml.coerce_document(doc_or_xml)
      Dom.require!("HankoXml::Signer#sign!")

      signatures, adopted = find_or_build_signatures(doc)
      all_sigs_in_order = doc.xpath(".//ds:Signature", ds: NS["ds"])

      # Sort by depth descending (innermost first) so nested signatures are
      # signed before the ones that envelope them.
      depth_sorted = signatures.sort_by { |node| -node.ancestors.size }

      signatures_to_sign = if signature
                             # Document order, to agree with Verifier's Integer
                             # index -- not the depth-sorted signing order (S-11).
                             target = all_sigs_in_order[signature]
                             unless target
                               raise HankoXml::ConfigurationError, "signature: #{signature.inspect} not found"
                             end

                             [target]
                           else
                             depth_sorted
                           end

      signatures_to_sign.reject! { |node| node_signed?(node) } unless force

      return doc if signatures_to_sign.empty?

      xml_bytes = HankoXml.serialize(doc)

      # Policy + reference-URI checks run on every template before any
      # Native.sign (S-05). inspect_sig does not fetch; Native.sign would.
      # Two loops on purpose: a later template must not be signed after an
      # earlier one already passed, if a subsequent one is hostile.
      # rubocop:disable Style/CombinableLoops
      signatures_to_sign.each do |sig_node|
        index = all_sigs_in_order.index(sig_node)
        enforce_before_native_sign!(xml_bytes, index, adopted: adopted)
      end

      signatures_to_sign.each do |sig_node|
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

        write_back_signature(doc, xml_bytes, index, sig_node)
      end
      # rubocop:enable Style/CombinableLoops

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
        raise HankoXml::ConfigurationError, "template: :require but no <Signature> found" if @template_mode == :require

        template_node = template(doc)
        @placement.insert(doc, template_node)
        [[template_node], false]
      else
        if @template_mode == :build
          raise HankoXml::ConfigurationError,
                "template: :build but <Signature> already exists"
        end

        [existing, true]
      end
    end

    # Policy is a structural allowlist over inspect_sig output. Enforce it
    # before Native.sign so a hostile adopted template cannot choose
    # algorithms, external URIs, or XSLT (S-05). On :adopt/:require, the
    # template's Reference URIs must also match this Signer's references
    # (empty references means whole-document URI=""); that is the
    # chosen-message opt-in.
    def enforce_before_native_sign!(xml_bytes, index, adopted:)
      sig_info = HankoXml::SignatureInfo.from_native(Native.inspect_sig(xml_bytes, index))
      @policy.enforce!(sig_info)
      ensure_adopted_references_match!(sig_info) if adopted
    end

    def ensure_adopted_references_match!(sig_info)
      expected = effective_reference_uris
      actual = sig_info.references.map(&:uri)
      return if expected == actual

      raise HankoXml::ConfigurationError,
            "template: #{@template_mode} would sign reference URIs #{actual.inspect}, " \
            "which do not match this Signer's references #{expected.inspect}"
    end

    def effective_reference_uris
      refs = @references
      refs = [HankoXml::Reference.new(uri: "")] if refs.empty?
      refs.map(&:uri)
    end

    def node_signed?(sig_node)
      val = sig_node.at_xpath("./ds:SignatureValue", ds: NS["ds"])
      val && !val.content.strip.empty?
    end

    # rubocop:disable Metrics/PerceivedComplexity
    def write_back_signature(doc, signed_bytes, index, caller_sig_node)
      # Parse the signed bytes
      signed_doc = HankoXml.parse(signed_bytes)
      signed_sigs = signed_doc.xpath(".//ds:Signature", ds: NS["ds"])
      signed_sig_node = signed_sigs[index]

      # Copy ds:Reference/ds:DigestValue
      caller_refs = caller_sig_node.xpath(".//ds:Reference", ds: NS["ds"])
      signed_refs = signed_sig_node.xpath(".//ds:Reference", ds: NS["ds"])

      caller_refs.each_with_index do |caller_ref, i|
        signed_ref = signed_refs[i]
        caller_dv = caller_ref.at_xpath("./ds:DigestValue", ds: NS["ds"])
        signed_dv = signed_ref.at_xpath("./ds:DigestValue", ds: NS["ds"])

        caller_dv.content = signed_dv.content if caller_dv && signed_dv
      end

      # Copy ds:SignatureValue
      caller_sv = caller_sig_node.at_xpath("./ds:SignatureValue", ds: NS["ds"])
      signed_sv = signed_sig_node.at_xpath("./ds:SignatureValue", ds: NS["ds"])
      caller_sv.content = signed_sv.content if caller_sv && signed_sv

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
          caller_cert.content = signed_cert.content if signed_cert
        end
      end
    end
    # rubocop:enable Metrics/PerceivedComplexity
  end
end
