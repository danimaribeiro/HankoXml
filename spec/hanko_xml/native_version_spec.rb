# frozen_string_literal: true

RSpec.describe HankoXml::NativeVersion do
  # The three Native predicates are stubbed rather than exercised for real:
  # the whole point of this guard is the case where the loaded libxmlsec1
  # disagrees with the compiled-in one, which cannot be produced in-process.
  def stub_native(exact:, abi:)
    allow(HankoXml::Native).to receive(:check_version).and_return(exact)
    allow(HankoXml::Native).to receive(:abi_compatible?).and_return(abi)
  end

  around do |example|
    original = ENV.fetch(described_class::SKIP_ENV, nil)
    example.run
  ensure
    ENV[described_class::SKIP_ENV] = original
  end

  before { ENV.delete(described_class::SKIP_ENV) }

  describe ".check!" do
    it "returns :ok when the loaded xmlsec matches exactly" do
      stub_native(exact: true, abi: true)

      expect(described_class.check!).to eq(:ok)
    end

    it "returns :abi_compatible when the versions differ but remain ABI safe" do
      stub_native(exact: false, abi: true)

      expect(described_class.check!).to eq(:abi_compatible)
    end

    it "raises NativeVersionMismatch when the versions are not ABI compatible" do
      stub_native(exact: false, abi: false)

      expect { described_class.check! }
        .to raise_error(HankoXml::NativeVersionMismatch, /not ABI compatible/)
    end

    it "names the compiled-against versions in the failure" do
      stub_native(exact: false, abi: false)
      allow(HankoXml::Native).to receive(:versions)
        .and_return({ xmlsec: "1.2.37", libxml2: "2.9.14", crypto: "openssl" })

      expect { described_class.check! }
        .to raise_error(HankoXml::NativeVersionMismatch, /xmlsec1 1\.2\.37, libxml2 2\.9\.14/)
    end

    it "warns instead of raising when the skip variable is set" do
      stub_native(exact: false, abi: false)
      ENV[described_class::SKIP_ENV] = "1"

      expect(described_class).to receive(:warn).with(/not ABI compatible/)
      expect(described_class.check!).to eq(:skipped)
    end

    it "ignores an empty skip variable" do
      stub_native(exact: false, abi: false)
      ENV[described_class::SKIP_ENV] = ""

      expect { described_class.check! }.to raise_error(HankoXml::NativeVersionMismatch)
    end

    it "does not consult the ABI check when the exact match already passed" do
      allow(HankoXml::Native).to receive(:check_version).and_return(true)
      expect(HankoXml::Native).not_to receive(:abi_compatible?)

      described_class.check!
    end
  end

  describe ".build_versions" do
    it "reports the xmlsec, libxml2, and crypto backend compiled into the extension" do
      versions = described_class.build_versions

      expect(versions[:xmlsec]).to match(/\A\d+\.\d+\.\d+/)
      expect(versions[:libxml2]).to match(/\A\d+\.\d+\.\d+/)
      expect(versions[:crypto]).to eq("openssl")
    end
  end

  describe "HankoXml::NativeVersionMismatch" do
    it "is a NativeError, so an existing rescue of HankoXml::Error still catches it" do
      expect(HankoXml::NativeVersionMismatch.ancestors)
        .to include(HankoXml::NativeError, HankoXml::Error)
    end
  end
end
