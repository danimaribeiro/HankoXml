# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require "pathname"

# #85: XPath Filter 2.0, in the one shape EU DSS writes for enveloped XAdES: a
# whole-document reference whose single filter subtracts the signatures. xmlsec
# runs the transform; HankoXml checks the shape so #signed? can model it.
RSpec.describe "XPath Filter 2.0 (#85)" do
  let(:dss) do
    Pathname.new(__dir__).join("..", "interop", "xades", "dss", "validation", "evidence-record", "incorporation")
  end
  let(:xml) { dss.join("X-B-B.xml").binread }
  let(:two_sigs) { dss.join("X-B-LT-two-sigs.xml").binread }
  let(:ns) { { "ds" => HankoXml::NS["ds"], "h" => "http://www.w3.org/TR/html4/" } }

  def embedded_certificate(document, signature = 0)
    signature_node = Nokogiri::XML(document).xpath("//ds:Signature", ns)[signature]
    base64 = signature_node.at_xpath("ds:KeyInfo//ds:X509Certificate", ns).text
    OpenSSL::X509::Certificate.new(base64.unpack1("m"))
  end

  def verify(document, policy: HankoXml::Policy.xades, signature: 0, certificate: embedded_certificate(document))
    midpoint = Time.at((certificate.not_before.to_i + certificate.not_after.to_i) / 2)
    HankoXml::Verifier.new(certificate: certificate, policy: policy, verification_time: midpoint,
                           signature: signature).verify(document)
  end

  it "verifies a subtract of /descendant::ds:Signature under Policy.xades" do
    result = verify(xml)

    expect(result.errors).to be_empty
    expect(result.signature_info.references.first.signature_exclusion).to eq(:all)
    expect(result).to be_covers_root
  end

  it "fails when the signed content changes" do
    result = verify(xml.sub("<h:td>Hello</h:td>", "<h:td>Bye</h:td>"))

    expect(result).not_to be_valid
    expect(result.errors.first).to be_a(HankoXml::VerificationError)
  end

  describe "#signed?" do
    it "leaves out every <Signature>, and only those" do
      result = verify(xml)
      document = result.document

      expect(result.signed?(document.at_xpath("//h:td", ns))).to be true
      expect(result.signed?(document.at_xpath("//ds:Signature", ns))).to be false
    end

    it "leaves out content an attacker wraps in a <Signature> of their own, which the digest never saw" do
      fake = %(<ds:Signature xmlns:ds="#{HankoXml::NS["ds"]}"><h:td>Pay Mallory</h:td></ds:Signature>)
      forged = xml.sub("</h:table>", "#{fake}</h:table>")
      result = verify(forged)
      mallory = result.document.at_xpath("//h:td[.='Pay Mallory']", ns)

      expect(result).to be_valid
      expect(result.signed?(mallory)).to be false
    end

    it "handles /*/ds:Signature (root children only) beside /descendant::ds:Signature" do
      policy = HankoXml::Policy.xades.with(allow_same_document_xpointer: true)
      first = verify(two_sigs, policy: policy, signature: 0)
      second = verify(two_sigs, policy: policy, signature: 1, certificate: embedded_certificate(two_sigs, 1))

      expect(first.errors).to be_empty
      expect(second.errors).to be_empty
      expect(first.signature_info.references.first.signature_exclusion).to eq(:root_children)
      expect(second.signature_info.references.first.signature_exclusion).to eq(:all)
      [first, second].each do |result|
        expect(result.signed?(result.document.at_xpath("//h:td", ns))).to be true
        expect(result.document.xpath("//ds:Signature", ns).map { |s| result.signed?(s) }).to eq([false, false])
      end
    end
  end

  describe "the shapes Policy refuses" do
    it "refuses it under Policy.strict, which doesn't list :xpath_filter2" do
      expect(verify(xml, policy: HankoXml::Policy.strict).errors.first)
        .to be_a(HankoXml::PolicyError).and(have_attributes(message: /xpath_filter2/))
    end

    it "refuses a prefix bound to another namespace, which would subtract nothing xmlsec calls a signature" do
      rebound = xml.sub("<dsig-filter2:XPath ", %(<dsig-filter2:XPath xmlns:ds="urn:evil" ))
      error = verify(rebound).errors.first

      expect(error).to be_a(HankoXml::PolicyError)
      expect(error.message).to match(/XPath Filter 2.0/)
    end

    {
      "intersect" => ->(s) { s.sub('Filter="subtract"', 'Filter="intersect"') },
      "union" => ->(s) { s.sub('Filter="subtract"', 'Filter="union"') },
      "a name() comparison" => lambda { |s|
        s.sub("/descendant::ds:Signature</", "//*[name()='ds:Signature']</")
      },
      "any other expression" => ->(s) { s.sub("/descendant::ds:Signature</", "/descendant::h:td</") },
      "a second XPath" => lambda { |s|
        s.sub(%r{<dsig-filter2:XPath [^>]*>[^<]*</dsig-filter2:XPath>}) { |xpath| xpath * 2 }
      }
    }.each do |name, edit|
      it "refuses #{name}" do
        edited = edit.call(xml)
        expect(edited).not_to eq(xml)

        error = verify(edited).errors.first
        expect(error).to be_a(HankoXml::PolicyError)
        expect(error.message).to match(/XPath Filter 2.0/)
      end
    end

    it "refuses it on a reference that isn't the whole document" do
      ref = %(<ds:Reference Id="r-id-b922f76108a1fe54051e562afb8678b9-1" URI="">)
      edited = xml.sub(ref, ref.sub('URI=""', 'URI="#xades-id-b922f76108a1fe54051e562afb8678b9"'))
      expect(edited).not_to eq(xml)

      expect(verify(edited).errors.first.message).to match(/XPath Filter 2.0/)
    end
  end

  describe "Native.verify" do
    let(:pem) { embedded_certificate(xml).to_pem }

    it "runs the transform only when the caller enables it" do
      enabled = HankoXml::Native.verify(xml, [pem], [], %w[Id ID id], 0, [], true)
      disabled = HankoXml::Native.verify(xml, [pem], [], %w[Id ID id], 0, [], false)

      expect(enabled[:status]).to eq(:succeeded)
      expect(disabled[:status]).not_to eq(:succeeded)
    end
  end

  it "exposes the filters through Native.inspect_sig" do
    reference = HankoXml::Native.inspect_sig(xml, 0)[:references].first

    expect(reference[:xpath_filters]).to match(
      [{ filter: "subtract", expression: "/descendant::ds:Signature",
         namespaces: a_hash_including("ds" => HankoXml::NS["ds"]) }]
    )
  end
end
