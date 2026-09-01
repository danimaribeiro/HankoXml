# frozen_string_literal: true

module HankoXml
  # Builds the unsigned <ds:Signature> Nokogiri tree for a Signer's
  # configuration -- DigestValue/SignatureValue/certificate leaves are left
  # empty for the native layer (Phase 2+) to fill in. See API_CONTRACT.md
  # §5.2, §6.4.
  #
  # Needs a DOM: this is the one thing that cannot be built DOM-free,
  # because doing it by string concatenation would put attacker-influenced
  # values into hand-assembled markup (§6.1).
  class Template
    def self.build(doc, config)
      new(doc, config).build
    end

    def initialize(doc, config)
      Dom.require!("HankoXml::Template")

      @doc = doc
      @config = config
    end

    def build
      signature = element("Signature")
      signature.default_namespace = HankoXml::NS["ds"]
      signature["Id"] = @config.signature_id.to_s if @config.signature_id

      signature.add_child(build_signed_info)
      signature.add_child(element("SignatureValue"))

      key_info = build_key_info
      signature.add_child(key_info) if key_info

      signature
    end

    private

    def build_signed_info
      signed_info = element("SignedInfo")

      c14n = element("CanonicalizationMethod")
      c14n["Algorithm"] = Algorithms.uri_for(:canonicalization, @config.canonicalization_method)
      signed_info.add_child(c14n)

      signature_method = element("SignatureMethod")
      signature_method["Algorithm"] = Algorithms.uri_for(:signature, @config.signature_method)
      signed_info.add_child(signature_method)

      effective_references.each { |ref| signed_info.add_child(build_reference(ref)) }

      signed_info
    end

    def effective_references
      refs = @config.references
      refs = [Reference.new(uri: "", digest_method: @config.digest_method)] if refs.empty?
      refs
    end

    def build_reference(ref)
      reference = element("Reference")
      reference["URI"] = ref.uri
      reference["Id"] = ref.id.to_s if ref.id
      reference["Type"] = ref.type.to_s if ref.type

      unless ref.transforms.empty?
        transforms = element("Transforms")
        ref.transforms.each { |t| transforms.add_child(build_transform(t)) }
        reference.add_child(transforms)
      end

      digest_method = element("DigestMethod")
      digest_method["Algorithm"] = ref.digest_method_uri
      reference.add_child(digest_method)

      reference.add_child(element("DigestValue"))

      reference
    end

    def build_transform(transform)
      node = element("Transform")
      node["Algorithm"] = transform.uri

      if transform.xpath
        xpath_node = element("XPath")
        xpath_node.content = transform.xpath
        node.add_child(xpath_node)
      end

      node
    end

    def build_key_info
      clauses = @config.key_info
      return nil if clauses.empty?

      key_info = element("KeyInfo")

      key_info.add_child(element("X509Data")) if clauses.any? { |c| c.name.to_s.start_with?("x509") }

      clauses.each do |c|
        case c.name
        when :key_name
          key_info.add_child(element("KeyName"))
        when :key_value
          key_info.add_child(element("KeyValue"))
        end
      end

      key_info
    end

    def element(name)
      @doc.create_element(name)
    end
  end
end
