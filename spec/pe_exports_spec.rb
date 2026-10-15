# frozen_string_literal: true

require_relative "../.github/scripts/check_pe_exports"

# The Windows leg of spec/symbols_spec.rb (#20). The check itself runs in
# cross-gem.yml against the built x64-mingw-ucrt gem; this pins down the
# objdump parsing it relies on, against output captured from a real build.
RSpec.describe PeExports do
  let(:clean) { File.read(File.join(__dir__, "fixtures/pe/hanko_xml-x64-mingw-ucrt.objdump.txt")) }

  it "reads the exports and imported DLLs of the real x64-mingw-ucrt extension" do
    parsed = described_class.parse(clean)

    expect(parsed[:exports]).to eq(%w[Init_hanko_xml ruby_abi_version])
    expect(parsed[:dlls]).to include("x64-ucrt-ruby340.dll", "bcrypt.dll", "CRYPT32.dll")
    expect(described_class.problems(parsed)).to be_empty
  end

  it "flags a vendored symbol in the export table" do
    leaky = clean.sub("0001 ruby_abi_version\n", "0001 ruby_abi_version\n\t[   2] +base[   3]  0002 xmlReadMemory\n")

    expect(described_class.problems(described_class.parse(leaky)))
      .to contain_exactly(a_string_including("xmlReadMemory"))
  end

  it "flags a vendored library imported from a DLL instead of linked statically" do
    dynamic = clean.sub("\tDLL Name: bcrypt.dll\n", "\tDLL Name: libcrypto-3-x64.dll\n\tDLL Name: libxml2-2.dll\n")

    expect(described_class.problems(described_class.parse(dynamic)))
      .to contain_exactly(a_string_including("libcrypto-3-x64.dll", "libxml2-2.dll"))
  end

  it "fails when no export table parses, instead of passing on nothing" do
    expect(described_class.problems(described_class.parse("file format pei-x86-64\n")))
      .to contain_exactly(a_string_including("Init_hanko_xml"))
  end
end
