# frozen_string_literal: true

module HankoXml
  module Xades
    # Adds unsigned properties to a XAdES signature that already exists
    # (#167): a <xades:SignatureTimeStamp> (B to T), the validation data of
    # XAdES-LT (T to LT), and a <xades141:ArchiveTimeStamp> (LT to LTA,
    # #169; again later to renew it). Revocation data is best collected after the
    # signature timestamp exists, so LT is usually added later, by the
    # holder of the signed document rather than the signer.
    #
    #   augmenter = HankoXml::Xades::Augmenter.new(
    #     validation_data: { certificates: chain, ocsp_responses: [ocsp_der] }
    #   )
    #   lt = augmenter.augment(signed_xml)
    #
    # Nothing a Reference covers changes: the new elements go into
    # UnsignedSignatureProperties, found along the same fixed path
    # Xades::Verifier reads (Xades::Locator), and the document is written
    # back with HankoXml.serialize, so the existing digests and
    # SignatureValue still verify.
    #
    # The Augmenter does not verify the signature it extends, and embedding
    # material vouches for nothing: verify first, and a verifier treats the
    # embedded values as untrusted (S-22). It never fetches: the timestamper:
    # callable and the caller's validation data are its only inputs.
    #
    # Writes XAdES 1.3.2 only, and needs Nokogiri.
    class Augmenter
      attr_reader :timestamper, :timestamp_digest_method, :timestamp_canonicalization_method, :validation_data,
                  :archive_timestamp, :archive_canonicalization_method, :policy

      # @param timestamper [#call, nil] As for {Xades::Signer}: adds a SignatureTimeStamp.
      # @param timestamp_digest_method [Symbol] The imprint digest.
      # @param timestamp_canonicalization_method [Symbol] How <ds:SignatureValue> is canonicalized for the
      #   imprint.
      # @param validation_data [ValidationData, Hash, nil] Adds CertificateValues and RevocationValues; the
      #   signature must have a SignatureTimeStamp, or timestamper: adds one first.
      # @param archive_timestamp [Boolean] Adds an ArchiveTimeStamp, last, from timestamper:, over the signature
      #   and all its validation data. timestamper: then adds a SignatureTimeStamp only when the signature has
      #   none. The signature must carry LT values, or validation_data: adds them first.
      # @param archive_canonicalization_method [Symbol] The ArchiveTimeStamp's CanonicalizationMethod. Inclusive
      #   c14n by default: a Reference that leaves a node set (as Xades::Signer's enveloped one does) is
      #   covered with xmlsec's inclusive c14n, so any other method is refused for such a signature.
      # @param policy [Policy] Checks the imprint algorithms and limits the document size.
      def initialize(timestamper: nil, timestamp_digest_method: :sha256, timestamp_canonicalization_method: :exc_c14n,
                     validation_data: nil, archive_timestamp: false, archive_canonicalization_method: :c14n,
                     policy: HankoXml::Policy.strict)
        SignatureTimeStamper.check_timestamper!(timestamper)
        @timestamper = timestamper
        @timestamp_digest_method = timestamp_digest_method
        @timestamp_canonicalization_method = timestamp_canonicalization_method
        @validation_data = ValidationData.coerce(validation_data)
        @policy = policy
        @archive_timestamp = archive_timestamp ? true : false
        @archive_canonicalization_method = archive_canonicalization_method
        nothing = !timestamper && !@validation_data
        raise HankoXml::ConfigurationError, "pass timestamper:, validation_data: or both" if nothing
        if @archive_timestamp && !timestamper
          raise HankoXml::ConfigurationError, "archive_timestamp: needs timestamper:, which obtains it"
        end

        if timestamper
          SignatureTimeStamper.check_algorithms!(policy, digest: timestamp_digest_method,
                                                         canonicalization: timestamp_canonicalization_method)
        end
        check_archive_canonicalization_method! if @archive_timestamp
        freeze
      end

      # A copy of the document with the nth signature augmented.
      #
      # @param source [String, Nokogiri::XML::Document, IO, Pathname] The signed document.
      # @param signature [Integer, nil] The document-order index of the <ds:Signature>; nil when the
      #   document has exactly one.
      # @return [SignedDocument]
      # @raise [XadesError] when the signature's XAdES structure cannot take the properties.
      # @raise [SigningError] when the TSA's answer does not hold (as for Xades::Signer).
      def augment(source, signature: nil)
        Dom.require!("HankoXml::Xades::Augmenter")
        doc = HankoXml.coerce_document(source, policy: policy).dup
        signatures = doc.xpath("//ds:Signature", "ds" => HankoXml::NS["ds"])
        index = signature_index(signatures.size, signature)
        node = signatures[index]
        value = node.at_xpath("ds:SignatureValue", "ds" => HankoXml::NS["ds"])
        if value.nil? || value.text.strip.empty?
          raise HankoXml::ConfigurationError, "the <Signature> is not signed yet; augment a signed document"
        end

        augment_signature(doc, node, index)
        SignedDocument.new(doc)
      end

      def inspect
        "#<#{self.class} timestamper=#{!timestamper.nil?} validation_data=#{!validation_data.nil?}>"
      end

      private

      def check_archive_canonicalization_method!
        unless HankoXml::Algorithms.uri_for(:canonicalization, archive_canonicalization_method)
          raise HankoXml::ConfigurationError, "archive_canonicalization_method: " \
                                              "#{archive_canonicalization_method.inspect} is not a registered " \
                                              "canonicalization algorithm"
        end

        policy.enforce_algorithm!(:canonicalization, archive_canonicalization_method)
      end

      def signature_index(count, signature)
        raise HankoXml::ConfigurationError, "the document has no <ds:Signature> to augment" if count.zero?

        if signature.nil?
          return 0 if count == 1

          raise HankoXml::ConfigurationError, "the document has #{count} signatures; pass signature: (an index)"
        end
        unless signature.is_a?(Integer) && signature.between?(-count, count - 1)
          raise HankoXml::ConfigurationError, "signature: #{signature.inspect} not found"
        end

        signature % count
      end

      def augment_signature(doc, signature, index)
        qualifying, ns = Locator.qualifying_properties(signature)
        Locator.fail!("Xades::Augmenter writes only XAdES 1.3.2 QualifyingProperties") unless ns["xades"] == NS

        properties = Locator.unsigned_signature_properties(qualifying, ns) || create_unsigned(qualifying)
        timestamped = properties.at_xpath("xades:SignatureTimeStamp", ns)
        if timestamper && !(archive_timestamp && timestamped)
          add_signature_timestamp(doc, signature, index, qualifying, properties)
        end
        add_validation_data(properties, qualifying, ns) if validation_data
        add_archive_timestamp(doc, signature, index, qualifying, properties) if archive_timestamp
      end

      def add_validation_data(properties, qualifying, ns)
        unless properties.at_xpath("xades:SignatureTimeStamp", ns)
          raise HankoXml::ConfigurationError,
                "XAdES-LT builds on XAdES-T: the signature has no <xades:SignatureTimeStamp>; pass timestamper: too"
        end

        validation_data.append_to(properties, qualifying.namespace)
      end

      # The skeleton goes in first, so xmlsec reads its CanonicalizationMethod;
      # its input (ArchiveTimeStampCheck.input) is everything before it. The
      # References' data comes from xmlsec verifying the signature with a
      # certificate of its own KeyInfo: that vouches for nothing, but a signature
      # that does not hold is not archived.
      def add_archive_timestamp(doc, signature, index, qualifying, properties)
        if properties.xpath("xades:CertificateValues | xades:RevocationValues", "xades" => NS).empty?
          raise HankoXml::ConfigurationError,
                "XAdES-LTA builds on XAdES-LT: the signature has no CertificateValues or RevocationValues; " \
                "pass validation_data: too"
        end

        position = properties.xpath("xades141:ArchiveTimeStamp", "xades141" => NS141).size
        archive = properties.add_child(element(doc, "ArchiveTimeStamp"))
        attach(archive, archive.add_namespace_definition("xades141", NS141))
        archive["Id"] = unique_id(doc, "#{signature["Id"]}-ats")
        method = attach(archive.add_child(element(doc, "CanonicalizationMethod")), signature.namespace)
        method["Algorithm"] = HankoXml::Algorithms.uri_for(:canonicalization, archive_canonicalization_method)
        encapsulated = attach(archive.add_child(element(doc, "EncapsulatedTimeStamp")), qualifying.namespace)

        bytes = HankoXml.serialize(doc)
        path = Locator.unsigned_path(signature, qualifying, NS)
        method_path = [*path, [NS141, "ArchiveTimeStamp", position],
                       [HankoXml::NS["ds"], "CanonicalizationMethod", nil]]
        check_node_set_references!(bytes, index, method["Algorithm"])
        input = ArchiveTimeStampCheck.input(bytes, index, reference_data(bytes, index, signature),
                                            ArchiveTimeStampCheck.element_paths(signature, qualifying, properties,
                                                                                archive, path),
                                            method_path)
        encapsulated.content = [SignatureTimeStamper.new(self).token_for(input)].pack("m0")
      end

      def check_node_set_references!(bytes, index, method)
        info = HankoXml::SignatureInfo.from_native(Native.inspect_sig(bytes, index))
        unless ArchiveTimeStampCheck.node_set_references?(info) && method != ArchiveTimeStampCheck::INCLUSIVE_C14N
          return
        end

        raise HankoXml::ConfigurationError,
              "a Reference of this signature leaves a node set, which an ArchiveTimeStamp covers with inclusive " \
              "c14n only: pass archive_canonicalization_method: :c14n"
      end

      def reference_data(bytes, index, signature)
        certificates = signature.xpath("ds:KeyInfo/ds:X509Data/ds:X509Certificate", "ds" => HankoXml::NS["ds"])
                                .map { |node| OpenSSL::X509::Certificate.new(node.text.gsub(/\s/, "").unpack1("m")).to_pem }
        Native.reference_data(bytes, certificates, %w[Id ID id], index, [], policy.allows?(:transform, :xpath_filter2))
      rescue HankoXml::NativeError, OpenSSL::X509::CertificateError, ArgumentError
        Locator.fail!("an ArchiveTimeStamp needs the signature to verify with a <ds:X509Certificate> of its KeyInfo")
      end

      # UnsignedProperties (last in QualifyingProperties) and its
      # UnsignedSignatureProperties (first in UnsignedProperties).
      def create_unsigned(qualifying)
        doc = qualifying.document
        namespace = qualifying.namespace
        unsigned = qualifying.at_xpath("xades:UnsignedProperties", "xades" => NS) ||
                   attach(qualifying.add_child(element(doc, "UnsignedProperties")), namespace)
        properties = element(doc, "UnsignedSignatureProperties")
        first = unsigned.children.first
        attach(first ? first.add_previous_sibling(properties) : unsigned.add_child(properties), namespace)
      end

      # The skeleton goes in first, so xmlsec reads its CanonicalizationMethod
      # (#161) from the bytes, as for Xades::Signer; then the token is filled in.
      def add_signature_timestamp(doc, signature, index, qualifying, properties)
        position = properties.xpath("xades:SignatureTimeStamp", "xades" => NS).size
        timestamp = attach(properties.add_child(element(doc, "SignatureTimeStamp")), qualifying.namespace)
        timestamp["Id"] = unique_id(doc, "#{signature["Id"]}-sigts")
        method = attach(timestamp.add_child(element(doc, "CanonicalizationMethod")), signature.namespace)
        method["Algorithm"] = HankoXml::Algorithms.uri_for(:canonicalization, timestamp_canonicalization_method)
        encapsulated = attach(timestamp.add_child(element(doc, "EncapsulatedTimeStamp")), qualifying.namespace)

        path = [*Locator.unsigned_path(signature, qualifying, NS), [NS, "SignatureTimeStamp", position],
                [HankoXml::NS["ds"], "CanonicalizationMethod", nil]]
        token = SignatureTimeStamper.new(self).token(HankoXml.serialize(doc), index, path)
        encapsulated.content = [token].pack("m0")
      end

      def unique_id(doc, base)
        taken = ->(id) { doc.at_xpath("//*[@Id=$id]", nil, id: id) }
        return base unless taken.call(base)

        (2..).each do |n|
          candidate = "#{base}-#{n}"
          return candidate unless taken.call(candidate)
        end
      end

      def element(doc, name)
        doc.create_element(name)
      end

      # The namespace is set once the node is in the tree, as
      # QualifyingProperties#xades does, so no redundant declaration appears.
      def attach(node, namespace)
        node.namespace = namespace
        node
      end
    end
  end
end
