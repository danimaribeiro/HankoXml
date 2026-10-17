# frozen_string_literal: true

module HankoXml
  module Xades
    # Adds unsigned properties to a XAdES signature that already exists
    # (#167): a <xades:SignatureTimeStamp> (B to T) and the validation data
    # of XAdES-LT (T to LT). Revocation data is best collected after the
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
                  :policy

      # @param timestamper [#call, nil] As for {Xades::Signer}: adds a SignatureTimeStamp.
      # @param timestamp_digest_method [Symbol] The imprint digest.
      # @param timestamp_canonicalization_method [Symbol] How <ds:SignatureValue> is canonicalized for the
      #   imprint.
      # @param validation_data [ValidationData, Hash, nil] Adds CertificateValues and RevocationValues; the
      #   signature must have a SignatureTimeStamp, or timestamper: adds one first.
      # @param policy [Policy] Checks the imprint algorithms and limits the document size.
      def initialize(timestamper: nil, timestamp_digest_method: :sha256, timestamp_canonicalization_method: :exc_c14n,
                     validation_data: nil, policy: HankoXml::Policy.strict)
        SignatureTimeStamper.check_timestamper!(timestamper)
        @timestamper = timestamper
        @timestamp_digest_method = timestamp_digest_method
        @timestamp_canonicalization_method = timestamp_canonicalization_method
        @validation_data = ValidationData.coerce(validation_data)
        @policy = policy
        nothing = !timestamper && !@validation_data
        raise HankoXml::ConfigurationError, "pass timestamper:, validation_data: or both" if nothing

        if timestamper
          SignatureTimeStamper.check_algorithms!(policy, digest: timestamp_digest_method,
                                                         canonicalization: timestamp_canonicalization_method)
        end
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
        add_signature_timestamp(doc, signature, index, qualifying, properties) if timestamper
        return unless validation_data

        unless properties.at_xpath("xades:SignatureTimeStamp", ns)
          raise HankoXml::ConfigurationError,
                "XAdES-LT builds on XAdES-T: the signature has no <xades:SignatureTimeStamp>; pass timestamper: too"
        end

        validation_data.append_to(properties, qualifying.namespace)
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
