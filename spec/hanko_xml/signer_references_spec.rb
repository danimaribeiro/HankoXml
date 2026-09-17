# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "pathname"

# #52 / SIGNING_TEST_COVERAGE.md group C: references and transforms
# configured through the Ruby Signer. C3 (root-element Id) lives in
# id_resolution_spec.rb and C15 (external URI) in signer_policy_spec.rb.
RSpec.describe "HankoXml::Signer references and transforms" do
  let(:fixtures) { Pathname.new(__dir__).join("..", "fixtures") }
  let(:key_pem) { fixtures.join("signer.key").read }
  let(:cert_pem) { fixtures.join("signer.crt").read }
  let(:xml) do
    %(<Envelope xmlns="urn:x"><Data Id="a">A</Data><Other Id="b">B</Other><Third ID="c">C</Third></Envelope>)
  end
  let(:fragment) { HankoXml::Policy.fragment }
  let(:ds) { { "ds" => HankoXml::NS["ds"] } }

  def signer(**options)
    HankoXml::Signer.new(key: key_pem, certificate: cert_pem, **options)
  end

  def verify(signed, **options)
    HankoXml::Verifier.new(certificate: cert_pem, **options).verify(signed.to_s)
  end

  it "C1 defaults to one URI=\"\" reference with the enveloped-signature transform" do
    signed = signer.sign(xml).to_s
    references = Nokogiri::XML(signed).xpath("//ds:Reference", ds)

    expect(references.map { |r| r["URI"] }).to eq([""])
    expect(references.first.xpath("ds:Transforms/ds:Transform/@Algorithm", ds).map(&:value))
      .to eq([HankoXml::Algorithms.uri_for(:transform, :enveloped_signature)])
    expect(verify(signed).valid?).to be true
  end

  it "C2 signs a non-root fragment" do
    result = verify(signer(references: ["#b"], policy: fragment).sign(xml), policy: fragment)

    expect(result.valid?).to be true
    expect(result.references.first.node.name).to eq("Other")
    expect(result.covers_root?).to be false
    expect(result.partial?).to be true
  end

  it "C4 signs two references, and only those" do
    signed = signer(references: ["#a", "#b"], policy: fragment).sign(xml).to_s
    result = verify(signed, policy: fragment)
    doc = result.document

    expect(signed.scan(%r{<DigestValue>[^<]+</DigestValue>}).size).to eq(2)
    expect(result.valid?).to be true
    expect(result.signed?(doc.at_xpath("//*[@Id='a']"))).to be true
    expect(result.signed?(doc.at_xpath("//*[@Id='b']"))).to be true
    expect(result.signed?(doc.at_xpath("//*[@ID='c']"))).to be false
  end

  it "C5 resolves each default id attribute: Id, ID and id" do
    { "#a" => xml, "#c" => xml, "#d" => xml.sub('<Other Id="b">', '<Other id="d">') }.each do |uri, source|
      expect(verify(signer(references: [uri], policy: fragment).sign(source), policy: fragment).valid?)
        .to be(true), uri
    end
  end

  describe "C6 namespaced id attributes" do
    let(:wsu) { "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" }
    let(:soap) { %(<Envelope xmlns="urn:x" xmlns:wsu="#{wsu}"><Body wsu:Id="body-1">B</Body></Envelope>) }

    it "signs a wsu:Id target through its local name" do
      signed = signer(references: ["#body-1"], id_attributes: ["Id"], policy: fragment).sign(soap)
      expect(verify(signed, id_attributes: ["Id"], policy: fragment).valid?).to be true
    end

    it "accepts a [href, name] pair on the Signer (#68)" do
      signed = signer(references: ["#body-1"], id_attributes: [[wsu, "Id"]], policy: fragment).sign(soap)
      expect(verify(signed, id_attributes: [[wsu, "Id"]], policy: fragment).valid?).to be true
    end
  end

  it "C7 a reference to a missing Id is a SigningError, not an empty digest" do
    expect { signer(references: ["#nope"], policy: fragment).sign(xml) }.to raise_error(HankoXml::SigningError)
  end

  describe "C8 duplicate target Id" do
    let(:duplicated) { xml.sub('Id="b"', 'Id="a"') }

    it "is a PolicyError under reject_duplicate_ids" do
      expect { signer(references: ["#a"], policy: fragment).sign(duplicated) }
        .to raise_error(HankoXml::PolicyError, /reject_duplicate_ids/)
    end

    it "signs the first element in document order with the check off" do
      policy = fragment.with(reject_duplicate_ids: false)
      result = verify(signer(references: ["#a"], policy: policy).sign(duplicated), policy: policy)

      expect(result.valid?).to be true
      expect(result.references.first.node.name).to eq("Data")
    end
  end

  it "C9 needs enveloped-signature before c14n; the reverse order fails in xmlsec" do
    enveloped_first = HankoXml::Reference.new(uri: "", transforms: %i[enveloped_signature exc_c14n])
    c14n_first = HankoXml::Reference.new(uri: "", transforms: %i[exc_c14n enveloped_signature])

    expect(verify(signer(references: [enveloped_first]).sign(xml)).valid?).to be true
    expect { signer(references: [c14n_first]).sign(xml) }.to raise_error(HankoXml::SigningError)
  end

  describe "C10/C11 XPath, XPath Filter 2 and XSLT transforms" do
    {
      xpath: HankoXml::Transform.new(:xpath, xpath: "not(ancestor-or-self::*[local-name()='Signature'])"),
      xpath_filter2: HankoXml::Transform.new(:xpath_filter2, xpath: "//*"),
      xslt: HankoXml::Transform.new(:xslt)
    }.each do |name, transform|
      it "#{name}: refused by Policy.strict, and by the native transform allowlist (S-10) under permissive" do
        reference = HankoXml::Reference.new(uri: "", transforms: [transform])

        expect { signer(references: [reference]).sign(xml) }.to raise_error(HankoXml::PolicyError, /transform/)
        expect { signer(references: [reference], policy: HankoXml::Policy.permissive).sign(xml) }
          .to raise_error(HankoXml::SigningError)
      end
    end

    it "emits the XPath expression as the transform's <XPath> child" do
      transform = HankoXml::Transform.new(:xpath, xpath: "count(//x) = 1")
      template = signer(references: [HankoXml::Reference.new(uri: "", transforms: [transform])])
                 .template(Nokogiri::XML(xml))

      expect(template.at_xpath(".//ds:Transform/ds:XPath", ds).text).to eq("count(//x) = 1")
    end
  end

  it "C12/C16 signs an enveloping <Object> through an adopted template" do
    signed = signer(references: ["#object-1"], policy: fragment).sign(fixtures.join("template_enveloping.xml").read)
    result = verify(signed, policy: fragment)

    expect(result.valid?).to be true
    expect(result.references.first.node.name).to eq("Object")
  end

  it "C12 signs a base64 transform over an enveloping <Object>" do
    template = fixtures.join("template_enveloping.xml").read
                       .sub(%(<Data xmlns="urn:xmlsec_rb:example">Hello, enveloping world!</Data>),
                            ["Hello, base64 world!"].pack("m0"))
                       .sub(%(<Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>),
                            %(<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/>))
    signed = signer(references: ["#object-1"], policy: fragment).sign(template)

    expect(verify(signed, policy: fragment).valid?).to be true
  end

  it "C13 keeps Reference Id and Type through write-back" do
    reference = HankoXml::Reference.new(uri: "", id: "ref-1", type: "urn:x:type")
    signed = signer(references: [reference]).sign(xml).to_s
    node = Nokogiri::XML(signed).at_xpath("//ds:Reference", ds)

    expect([node["Id"], node["Type"]]).to eq(["ref-1", "urn:x:type"])
    expect(verify(signed).valid?).to be true
  end

  describe "C14 URIs that need escaping" do
    it "escapes & in the template and resolves it" do
      signed = signer(references: ["#a&b"], policy: fragment).sign(xml.sub('Id="a"', 'Id="a&amp;b"')).to_s

      expect(signed).to include(%(URI="#a&amp;b"))
      expect(verify(signed, policy: fragment).valid?).to be true
    end

    it "signs an Id containing an apostrophe (#71)" do
      signed = signer(references: ["#a'b"], policy: fragment).sign(xml.sub('Id="a"', %(Id="a'b")))
      expect(verify(signed, policy: fragment).valid?).to be true
    end

    # A bare name is looked up as one Id, not as XPath id(), which would
    # split "a b" and select both elements.
    it "does not resolve a space-separated list of Ids" do
      expect { signer(references: ["#a b"], policy: fragment).sign(xml) }.to raise_error(HankoXml::SigningError)
    end
  end
end
