# frozen_string_literal: true

require "nokogiri"

RSpec.describe HankoXml::Placement do
  let(:doc) { Nokogiri::XML("<Envelope xmlns=\"urn:x\"><Data>hi</Data></Envelope>") }
  let(:signature) { doc.create_element("Signature") }

  it ".append_to_root inserts as the last child of the root" do
    described_class.append_to_root.insert(doc, signature)
    expect(doc.root.children.last).to eq(signature)
  end

  it ".prepend_to_root inserts as the first child of the root" do
    described_class.prepend_to_root.insert(doc, signature)
    expect(doc.root.children.first).to eq(signature)
  end

  it ".after inserts after the resolved XPath target" do
    described_class.after("/x:Envelope/x:Data", namespaces: { "x" => "urn:x" }).insert(doc, signature)
    expect(doc.root.children[1]).to eq(signature)
  end

  it ".before inserts before the resolved XPath target" do
    described_class.before("/x:Envelope/x:Data", namespaces: { "x" => "urn:x" }).insert(doc, signature)
    expect(doc.root.children[0]).to eq(signature)
  end

  it "raises HankoXml::PlacementError when the XPath matches nothing" do
    placement = described_class.append_to("/x:Nope", namespaces: { "x" => "urn:x" })
    expect { placement.insert(doc, signature) }.to raise_error(HankoXml::PlacementError)
  end

  it "raises HankoXml::PlacementError when the XPath matches more than one node" do
    doc.root.add_child(doc.create_element("Data"))
    placement = described_class.append_to("//x:Data", namespaces: { "x" => "urn:x" })
    expect { placement.insert(doc, signature) }.to raise_error(HankoXml::PlacementError)
  end

  it ".detached does not insert anything" do
    described_class.detached.insert(doc, signature)
    expect(doc.root.children).not_to include(signature)
  end

  it ".custom runs the given block" do
    inserted = nil
    described_class.custom { |d, sig| inserted = [d, sig] }.insert(doc, signature)
    expect(inserted).to eq([doc, signature])
  end

  it ".coerce accepts a Symbol" do
    expect(described_class.coerce(:detached)).to be_detached
  end

  it ".coerce raises for an unsupported type" do
    expect { described_class.coerce(42) }.to raise_error(ArgumentError)
  end
end
