# frozen_string_literal: true

require "spec_helper"

RSpec.describe HankoXml::Verifier do
  describe "#native_id_attributes" do
    it "passes plain string id_attributes through unchanged" do
      verifier = described_class.new(id_attributes: %w[Id ID id])

      expect(verifier.send(:native_id_attributes)).to eq(%w[Id ID id])
    end

    it "reduces namespace-qualified [ns, name] entries to their local name" do
      verifier = described_class.new(id_attributes: [["http://example.com/ns", "CustomId"], "Id"])

      expect(verifier.send(:native_id_attributes)).to eq(%w[CustomId Id])
    end
  end
end
