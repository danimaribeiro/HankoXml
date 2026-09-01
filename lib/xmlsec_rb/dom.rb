# frozen_string_literal: true

module XmlsecRb
  # The single place that probes for Nokogiri. Nothing else in the library
  # references the Nokogiri constant directly -- see API_CONTRACT.md §6.1.
  #
  # The rule: a missing Nokogiri may remove a capability, it may never weaken
  # one. Every check that runs with Nokogiri present runs identically in its
  # absence; the capabilities that disappear are the ones that cannot be
  # expressed at all without a DOM, and each of them raises
  # XmlsecRb::NokogiriRequired rather than quietly returning a less careful
  # answer.
  module Dom
    class << self
      def available?
        defined?(::Nokogiri::XML::Document) ? true : false
      end

      def document?(obj)
        available? && obj.is_a?(::Nokogiri::XML::Document)
      end

      def node?(obj)
        available? && obj.is_a?(::Nokogiri::XML::Node)
      end

      def certificate?(obj)
        defined?(::OpenSSL::X509::Certificate) && obj.is_a?(::OpenSSL::X509::Certificate)
      end

      def pkey?(obj)
        defined?(::OpenSSL::PKey::PKey) && obj.is_a?(::OpenSSL::PKey::PKey)
      end

      # Raises XmlsecRb::NokogiriRequired, naming +capability+ and the fix,
      # unless Nokogiri is loaded.
      def require!(capability)
        return if available?

        raise XmlsecRb::NokogiriRequired,
              "#{capability} needs a DOM to run, and Nokogiri is not loaded. " \
              "Add `gem \"nokogiri\"` to your Gemfile, or use a capability that " \
              "does not require a DOM -- see XmlsecRb.capabilities."
      end

      def capabilities
        {
          verify: true,
          sign: available? || :template_only,
          coverage_checks: available?,
          schema: available?,
          parse: available?,
          template_build: available?
        }
      end
    end
  end
end
