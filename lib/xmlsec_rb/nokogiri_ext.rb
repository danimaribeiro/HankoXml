# frozen_string_literal: true

require_relative "../xmlsec_rb"

# Core extensions for Nokogiri::XML::Document and Nokogiri::XML::Node to
# support direct #sign, #sign!, #signature_valid?, #signatures, and #signed?
# See API_CONTRACT.md §6.6.
module XmlsecRb
  module NokogiriExt
    def sign(**kwargs)
      XmlsecRb.sign(self, **kwargs)
    end

    def sign!(**kwargs)
      XmlsecRb.sign!(self, **kwargs)
    end

    def signature_valid?(**kwargs)
      XmlsecRb.verify(self, **kwargs).valid?
    end

    def signatures
      xpath(".//ds:Signature", ds: NS["ds"])
    end

    def signed?
      XmlsecRb.signed?(self)
    end
  end
end

if defined?(::Nokogiri::XML::Document)
  ::Nokogiri::XML::Document.include(XmlsecRb::NokogiriExt)
  ::Nokogiri::XML::Node.include(XmlsecRb::NokogiriExt)
end
