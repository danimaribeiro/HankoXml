# frozen_string_literal: true

require "spec_helper"
require "pathname"

# #93: the RBS error hierarchy is what a typed caller's `rescue` is checked
# against, so it has to say what errors.rb says.
RSpec.describe "RBS error hierarchy" do
  let(:declared) do
    Pathname.new(__dir__).join("..", "..", "sig").glob("**/*.rbs").flat_map do |file|
      file.read.scan(/^  class (\w+) < (\w+)/)
    end.to_h
  end

  let(:actual) do
    HankoXml.constants.map { |name| HankoXml.const_get(name) }.select do |const|
      const.is_a?(Class) && const <= HankoXml::Error && const != HankoXml::Error
    end
  end

  it "declares every error class with the superclass it really has" do
    expect(actual).not_to be_empty
    actual.each do |klass|
      name = klass.name.split("::").last
      expect(declared[name]).to eq(klass.superclass.name.split("::").last), "sig/ is wrong about #{klass}"
    end
  end

  it "keeps PolicyError a ConfigurationError, not a VerificationError" do
    expect(declared["PolicyError"]).to eq("ConfigurationError")
    expect(HankoXml::PolicyError.ancestors).not_to include(HankoXml::VerificationError)
  end
end
