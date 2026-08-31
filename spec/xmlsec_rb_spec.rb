# frozen_string_literal: true

RSpec.describe XmlsecRb do
  it "has a version number" do
    expect(XmlsecRb::VERSION).not_to be nil
  end

  it "confirms the linked libxmlsec1 matches the version bindgen ran against" do
    expect(described_class.check_version).to be true
  end

  it "initializes and shuts down the xmlsec + OpenSSL crypto backend" do
    expect(described_class.init!).to be_nil
    expect(described_class.shutdown!).to be_nil
  end
end
