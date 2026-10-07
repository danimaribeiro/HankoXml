# frozen_string_literal: true

require "open3"
require "rbconfig"

# Runs spec/without_nokogiri in its own process, where Nokogiri is hidden,
# so the regular `rspec` run covers both configurations (#102,
# API_CONTRACT.md §12). `rake spec:without_nokogiri` runs it alone.
RSpec.describe "the Nokogiri-free suite" do
  it "passes in a process that never loads Nokogiri" do
    root = File.expand_path("../..", __dir__)
    files = Dir.glob(File.join(root, "spec/without_nokogiri/*_nokogiri_free.rb"))
    command = [RbConfig.ruby, "-I", File.join(root, "lib"), Gem.bin_path("rspec-core", "rspec"),
               "--options", File::NULL, *files]
    output, status = Open3.capture2e({ "LANG" => "C.UTF-8" }, *command, chdir: root)

    expect(files).not_to be_empty
    expect(status).to be_success, output
    expect(output).to match(/[1-9]\d* examples, 0 failures/)
  end
end
