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

    # The key class xmlsec needs for each built-in signature method, by the
    # method name's prefix (:rsa_sha256 -> RSA). HMAC takes no asymmetric key
    # and custom registered methods are left to xmlsec.
    SIGNATURE_KEY_TYPES = {
      "rsa" => ::OpenSSL::PKey::RSA,
      "ecdsa" => ::OpenSSL::PKey::EC,
      "dsa" => ::OpenSSL::PKey::DSA
    }.freeze
    private_constant :SIGNATURE_KEY_TYPES

    # What to suggest for each key class when it does not fit the method.
    SIGNATURE_METHOD_FOR_KEY = {
      ::OpenSSL::PKey::RSA => :rsa_sha256,
      ::OpenSSL::PKey::EC => :ecdsa_sha256,
      ::OpenSSL::PKey::DSA => :dsa_sha1
    }.freeze
    private_constant :SIGNATURE_METHOD_FOR_KEY

    # KeyInfo leaves xmlsec derives from the signing key. It fills only empty
    # ones, so an adopted template's stale values must be emptied first (#72).
    KEY_DERIVED_LEAVES = %w[
      ds:X509Data/ds:X509Certificate ds:X509Data/ds:X509SubjectName
      ds:X509Data/ds:X509IssuerSerial ds:X509Data/ds:X509SKI ds:KeyValue
    ].map { |path| "./#{path}" }.join(" | ").freeze
    private_constant :KEY_DERIVED_LEAVES

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
    # @param key_info [Array<Symbol, Hash>] The elements to include in `<KeyInfo>` (e.g., :x509_certificate).
    #   `<KeyName>` needs its text: `{ key_name: "idp-1" }`.
    # @param id_attributes [Array<String, Array(String, String)>] The attribute names considered as IDs for
    #   `#foo` references, optionally as `[namespace_href, name]` pairs.
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

      # After the block, which may reassign key/certificate (S-14, S-15).
      check_key_material!
      check_key_matches_certificate!

      freeze
    end

    # Adds a Reference. Block form only -- see API_CONTRACT.md §5.2.
    def reference(uri = "", **kwargs)
      @references << HankoXml::Reference.new(uri: uri, **kwargs)
    end

    # With no args, the current KeyInfo clauses. With args, replaces them --
    # block-form usage per API_CONTRACT.md §5.2 (`s.key_info :x509_certificate`,
    # `s.key_info :key_name, name: "idp-1"`).
    def key_info(*clauses, name: nil)
      return @key_info if clauses.empty? && name.nil?

      clauses = clauses.flatten
      if name
        unless clauses.any? { |c| c.to_s == "key_name" }
          raise HankoXml::ConfigurationError, "key_info name: only applies to the :key_name clause"
        end

        clauses = clauses.map { |c| c.to_s == "key_name" ? { key_name: name } : c }
      end
      @key_info = HankoXml::KeyInfo.coerce(clauses)
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
      doc = HankoXml.coerce_document(doc_or_xml, policy: policy)
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
      doc = HankoXml.coerce_document(doc_or_xml, policy: policy)
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
      enforce_document_and_key_size!(xml_bytes)

      # Policy + reference-URI checks run on every template before any
      # Native.sign (S-05). inspect_sig does not fetch; Native.sign would.
      # Two loops on purpose: a later template must not be signed after an
      # earlier one already passed, if a subsequent one is hostile.
      signatures_to_sign.each do |sig_node|
        index = all_sigs_in_order.index(sig_node)
        enforce_before_native_sign!(doc, xml_bytes, index, sig_node: sig_node, adopted: adopted)
      end

      xml_bytes = prepare_key_infos!(doc, xml_bytes, signatures_to_sign, adopted: adopted)

      signatures_to_sign.each do |sig_node|
        index = all_sigs_in_order.index(sig_node)

        cert_pems = @certificates.map(&:to_pem)
        cert_pems.unshift(@certificate.to_pem) if @certificate

        xml_bytes = Native.sign(xml_bytes, @key.to_pem, cert_pems, native_id_attributes, index)

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

    # A certificate or public key as key: can only fail later inside xmlsec,
    # and a key as certificate: would send private key PEM down the
    # certificate path (S-15, F5/F7). Only checks what coercion produced;
    # raw values assigned in the block are left to the native layer.
    def check_key_material!
      # A disposed Key raises KeyLoadError here rather than being misreported
      # as the wrong kind of key below.
      [key, certificate].grep(HankoXml::Key).each(&:to_openssl)

      if key.is_a?(HankoXml::Key) && !key.private_key?
        raise HankoXml::ConfigurationError, "key: must be a private key (got a #{key_kind(key)})"
      end

      check_key_type!
      return unless certificate.is_a?(HankoXml::Key) && !certificate.certificate?

      raise HankoXml::ConfigurationError, "certificate: must be an X.509 certificate (got a #{key_kind(certificate)})"
    end

    # No XML-DSig signature method here takes an Ed25519/Ed448 key, which
    # otherwise failed as a NoMethodError from inside the library (#69).
    def check_key_type!
      pkey = key.is_a?(HankoXml::Key) ? key.to_openssl : key
      return unless pkey.is_a?(::OpenSSL::PKey::PKey)
      return if SIGNATURE_METHOD_FOR_KEY.key?(pkey.class)

      raise HankoXml::ConfigurationError,
            "key: is an unsupported #{pkey.oid} key; signing supports RSA, EC and DSA keys"
    end

    # xmlsec reports a key that does not fit the signature method only as
    # "xmlSecDSigCtxSign failed" (#70). Checked against the method actually
    # being signed, which for an adopted template is the template's.
    def check_key_fits_signature_method!(sig_info)
      name = HankoXml::Algorithms.name_for(:signature, sig_info.signature_method)
      needed = SIGNATURE_KEY_TYPES[signature_key_kind(name)]
      pkey = @key.to_openssl
      return if needed.nil? || pkey.is_a?(needed)

      raise HankoXml::ConfigurationError,
            "signature method #{name.inspect} needs #{key_type_name(needed)} key, but key: is " \
            "#{key_type_name(pkey.class)} key; use signature_method: #{SIGNATURE_METHOD_FOR_KEY[pkey.class].inspect}"
    end

    # Built-in method names encode the key class in the prefix: rsa_sha256
    # and rsa_pss_sha256 are RSA, ecdsa_sha256 and ecdsa_sha3_256 are EC.
    # HMAC and custom registrations are left to xmlsec (needed is nil).
    def signature_key_kind(name)
      method = name.to_s
      return "ecdsa" if method.start_with?("ecdsa")
      return "rsa" if method.start_with?("rsa")
      return "dsa" if method.start_with?("dsa")

      nil
    end

    def key_type_name(klass)
      type = klass.name.split("::").last
      "#{type == "DSA" ? "a" : "an"} #{type}"
    end

    def key_kind(key)
      return "certificate" if key.certificate?

      key.private_key? ? "private key" : "public key"
    end

    # A key that does not belong to certificate: produces a signature that
    # verifies against neither that certificate nor any other (S-14). Only
    # checks a private key against an X.509 certificate; other shapes are
    # left to Key coercion and the native layer.
    def check_key_matches_certificate!
      pkey = key.is_a?(HankoXml::Key) ? key.to_openssl : key
      cert = certificate.is_a?(HankoXml::Key) ? certificate.to_openssl : certificate
      return unless pkey.is_a?(::OpenSSL::PKey::PKey) && cert.is_a?(::OpenSSL::X509::Certificate)
      return if cert.check_private_key(pkey)

      raise HankoXml::ConfigurationError,
            "key: does not match certificate: (subject #{cert.subject}); " \
            "the signature would not verify against that certificate"
    end

    def find_or_build_signatures(doc)
      existing = doc.xpath(".//ds:Signature", ds: NS["ds"]).to_a

      if existing.empty?
        raise HankoXml::ConfigurationError, "template: :require but no <Signature> found" if @template_mode == :require

        # API_CONTRACT.md §5.5: detached builds a <Signature> but inserts
        # nothing, so there is nothing in the document to sign. Without this
        # the unplaced node fell through to a TypeError (#52 G6).
        if @placement.detached?
          raise HankoXml::ConfigurationError,
                "placement: :detached inserts no <Signature>, so there is nothing to sign; use " \
                "Signer#template(doc) and insert it yourself, or Placement.custom"
        end

        template_node = template(doc)
        @placement.insert(doc, template_node, namespaces: @namespaces)
        [[template_node], false]
      else
        if @template_mode == :build
          raise HankoXml::ConfigurationError,
                "template: :build but <Signature> already exists"
        end

        [existing, true]
      end
    end

    # Before inspect_sig, which is itself a native parse (S-12).
    def enforce_document_and_key_size!(xml_bytes)
      @policy.enforce_document_size!(xml_bytes.bytesize)
      @policy.enforce_key_size!([@key.to_openssl])
    end

    # Policy is a structural allowlist over inspect_sig output. Enforce it
    # before Native.sign so a hostile adopted template cannot choose
    # algorithms, external URIs, or XSLT (S-05). On :adopt/:require, the
    # template's Reference URIs must also match this Signer's references
    # (empty references means whole-document URI=""); that is the
    # chosen-message opt-in.
    def enforce_before_native_sign!(doc, xml_bytes, index, sig_node:, adopted:)
      sig_info = HankoXml::SignatureInfo.from_native(Native.inspect_sig(xml_bytes, index))
      # require_signed_root is a verification-time XSW defence, not a
      # constraint on what is legitimate to sign (see Policy#violations) --
      # Signer deliberately does not check it, so a caller-chosen fragment
      # signature (references:, R5) still signs under Policy.strict.
      @policy.enforce!(sig_info, document: doc, sig_node: sig_node, id_attributes: @id_attributes,
                                 xml_bytes: xml_bytes, check_root_signed: false)
      ensure_adopted_references_match!(sig_info) if adopted
      check_key_fits_signature_method!(sig_info)
    end

    # Same mapping as Verifier#native_id_attributes: xmlSecAddIDs matches by
    # local name only, so a [href, name] pair crosses the FFI as its name (#68).
    def native_id_attributes
      @id_attributes.map { |attr| attr.is_a?(Array) ? attr[1].to_s : attr.to_s }
    end

    # Readies each template's KeyInfo for xmlsec, and returns the bytes to
    # sign. Runs only once every check passed, so a refused template leaves
    # the caller's document untouched.
    def prepare_key_infos!(doc, xml_bytes, signatures_to_sign, adopted:)
      changed = signatures_to_sign.map do |sig_node|
        key_info = sig_node.at_xpath("./ds:KeyInfo", ds: NS["ds"])
        next false unless key_info

        # Both run: | does not short-circuit.
        name_empty_key_names!(key_info) | (adopted && empty_key_derived_leaves!(key_info))
      end
      changed.any? ? HankoXml.serialize(doc) : xml_bytes
    end

    # xmlsec writes the key's own name into <KeyName>, and a key loaded from
    # PEM has none (#67). Returns whether anything was named.
    def name_empty_key_names!(key_info)
      empty = key_info.xpath("./ds:KeyName", ds: NS["ds"]).select { |node| node.content.strip.empty? }
      return false if empty.empty?

      key_name = @key_info.find { |c| c.name == :key_name && c.value }&.value
      unless key_name
        raise HankoXml::ConfigurationError,
              "<KeyName> would be signed empty: a key has no name of its own; pass " \
              "key_info: [{ key_name: \"...\" }] or, in the block form, s.key_info :key_name, name: \"...\""
      end

      empty.each { |node| node.content = key_name }
      true
    end

    # xmlsec fills only empty key-derived leaves, so an adopted template's
    # stale certificate stayed in the signed document (#72). Returns whether
    # anything was emptied.
    def empty_key_derived_leaves!(key_info)
      stale = key_info.xpath(KEY_DERIVED_LEAVES, ds: NS["ds"]).reject { |leaf| leaf.children.empty? }
      stale.each { |leaf| leaf.children.each(&:unlink) }
      stale.any?
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

      write_back_key_info(doc, caller_sig_node, signed_sig_node)
    end

    # xmlsec fills KeyInfo from the key: certificates (possibly several, for
    # a certificates: chain), <RSAKeyValue>/<ECKeyValue>, X509SubjectName and
    # the rest. Copying individual leaves missed everything but
    # X509Certificate, so the caller's document kept an empty <KeyValue/>
    # that no longer matched what was signed (#52 E5/E6/E8). Mirror the
    # signed KeyInfo's children wholesale instead.
    def write_back_key_info(doc, caller_sig_node, signed_sig_node)
      caller_key_info = caller_sig_node.at_xpath("./ds:KeyInfo", ds: NS["ds"])
      signed_key_info = signed_sig_node.at_xpath("./ds:KeyInfo", ds: NS["ds"])
      return unless caller_key_info && signed_key_info

      caller_key_info.children.each(&:unlink)
      signed_key_info.children.each { |child| caller_key_info.add_child(child.dup(1, doc)) }
    end
  end
end
