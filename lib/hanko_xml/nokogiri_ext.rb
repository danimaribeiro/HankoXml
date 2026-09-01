# frozen_string_literal: true

require_relative "../hanko_xml"

# Core extensions for Nokogiri::XML::Document and Nokogiri::XML::Node to
# support direct #sign, #sign!, #signature_valid?, #signatures, and #signed?
# See API_CONTRACT.md §6.6.
module HankoXml
  module NokogiriExt
    def sign(**kwargs)
      HankoXml.sign(self, **kwargs)
    end

    def sign!(**kwargs)
      HankoXml.sign!(self, **kwargs)
    end

    def signature_valid?(**kwargs)
      HankoXml.verify(self, **kwargs).valid?
    end

    def signatures
      xpath(".//ds:Signature", ds: NS["ds"])
    end

    def signed?
      HankoXml.signed?(self)
    end
  end
end

if defined?(::Nokogiri::XML::Document)
  ::Nokogiri::XML::Document.include(HankoXml::NokogiriExt)
  ::Nokogiri::XML::Node.include(HankoXml::NokogiriExt)
end
