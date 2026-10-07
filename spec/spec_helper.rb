# frozen_string_literal: true

require "English"
require "hanko_xml"

# Repo files (Rust sources, RBS, docs) are UTF-8. Read them that way under any
# locale, as CI's C.UTF-8 runners do, rather than as US-ASCII in a bare
# container.
Encoding.default_external = Encoding::UTF_8

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
