# frozen_string_literal: true

module HankoXml
  # Guards the one failure mode a bindgen-built extension cannot detect on its
  # own: being loaded against a libxmlsec1 whose structs are laid out
  # differently from the headers the bindings were generated from.
  #
  # +ext/hanko_xml/build.rs+ runs bindgen at compile time, which bakes xmlsec's
  # and libxml2's struct layouts into the compiled extension. Nothing about a
  # later layout change is visible to the dynamic linker: every symbol still
  # resolves, the library still loads, and then a field is read at the offset
  # our headers claimed rather than the one the loaded library actually used.
  # In a library whose entire job is deciding whether a signature can be
  # trusted, that has to be a hard failure at require time rather than a wrong
  # answer at verify time.
  #
  # For a source-installed gem this check passes by construction -- the machine
  # that compiled the extension is the machine loading it. It earns its keep
  # for precompiled platform gems, and for an extension that outlives an OS
  # package upgrade of libxmlsec1.
  module NativeVersion
    # Downgrades a mismatch from a raise to a warning when set to any non-empty
    # value. This is an escape hatch for someone who has established that their
    # two versions really are compatible; it is not a supported configuration,
    # and a wrong call here is silent memory corruption rather than an error.
    SKIP_ENV = "HANKO_XML_SKIP_VERSION_CHECK"

    class << self
      # Verifies the loaded libxmlsec1 against the compiled-in one.
      #
      # @return [Symbol] +:ok+ when they match exactly, +:abi_compatible+ when
      #   they differ only in a way xmlsec considers ABI safe, or +:skipped+
      #   when {SKIP_ENV} suppressed the check.
      # @raise [HankoXml::NativeVersionMismatch] when they are not ABI compatible.
      def check!
        return :ok if Native.check_version

        unless Native.abi_compatible?
          raise NativeVersionMismatch, mismatch_message if skip.nil?

          warn("hanko_xml: #{mismatch_message}")
          return :skipped
        end

        :abi_compatible
      end

      # The xmlsec1, libxml2, and crypto backend versions this extension was
      # compiled against.
      #
      # @return [Hash{Symbol => String}]
      def build_versions
        Native.versions
      end

      private

      def skip
        value = ENV[SKIP_ENV]
        value unless value.nil? || value.empty?
      end

      def mismatch_message
        built = build_versions
        "the loaded libxmlsec1 is not ABI compatible with the one this " \
          "extension was compiled against (xmlsec1 #{built[:xmlsec]}, " \
          "libxml2 #{built[:libxml2]}). Reinstall hanko_xml so the extension " \
          "is rebuilt against the libxmlsec1 currently on this machine " \
          "(`gem pristine hanko_xml`, or `bundle exec rake compile` from a " \
          "checkout). Set #{SKIP_ENV}=1 to downgrade this to a warning if you " \
          "have established the two are compatible."
      end
    end
  end
end
