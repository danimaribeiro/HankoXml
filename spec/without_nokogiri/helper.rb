# frozen_string_literal: true

# Loaded instead of spec_helper by the Nokogiri-free suite (#102,
# API_CONTRACT.md §12). Runs in its own process, see
# spec/hanko_xml/without_nokogiri_spec.rb and `rake spec:without_nokogiri`.
#
# Nokogiri is installed in the bundle, so it is hidden rather than absent:
# any attempt to load it fails loudly, so nothing here passes by quietly
# picking it up.
module HideNokogiri
  private

  def require(path)
    name = path.to_s
    if name == "nokogiri" || name.start_with?("nokogiri/")
      raise LoadError, "Nokogiri is hidden in the Nokogiri-free suite (#102)"
    end

    super
  end
end
Kernel.prepend(HideNokogiri)

require "pathname"
require "stringio"
require "hanko_xml"

RSpec.configure do |config|
  config.disable_monkey_patching!
  config.expect_with(:rspec) { |c| c.syntax = :expect }

  config.after(:suite) do
    raise "Nokogiri was loaded during the Nokogiri-free suite" if defined?(::Nokogiri)
  end
end

module WithoutNokogiri
  FIXTURES = Pathname.new(__dir__).join("../fixtures").expand_path
end
