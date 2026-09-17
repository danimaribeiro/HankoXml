# frozen_string_literal: true

require "spec_helper"
require "nokogiri"
require "openssl"
require "pathname"

# #62: signatures HankoXml did not produce. The W3C interop vectors
# merlin-xmldsig-twenty-three and phaos-xmldsig-three (see vectors/README.md)
# are verified under Policy.interop, and every vector's outcome is pinned
# with its reason. xmlsec's own expectation for each comes from
# tests/testDSig.sh in the xmlsec1 1.3.12 tarball.
#
# The outcomes that matter are the ones where xmlsec would accept a signature
# and HankoXml does not. Each is a deliberate policy choice (external
# references, HMAC, RetrievalMethod, XPath), a schema violation, or an issue.
module InteropVectors
  ROOT = Pathname.new(__dir__).join("vectors")
  MERLIN = "merlin-xmldsig-twenty-three"
  PHAOS = "phaos-xmldsig-three"

  # Every certificate here expired long ago; verify at a time inside its validity.
  VERIFICATION_TIME = { MERLIN => Time.utc(2005, 1, 1), PHAOS => Time.utc(2009, 1, 1) }.freeze

  EXTERNAL = [:policy, /is external, and allow_external_references is false/].freeze
  HMAC = [:policy, /hmac-(sha1|md5) is not in this policy's signature_methods/].freeze
  RETRIEVAL_METHOD = [:policy, /<RetrievalMethod>, and allow_retrieval_method is false/].freeze

  # name => [trust, outcome]. Trust is :key_value (the key the vector's own
  # <KeyValue> carries, standing in for a key the verifier already holds),
  # [:certificate, file] or [:store, file]. The outcome is :valid,
  # [:policy | :schema, message] or [:native, xmlsec log], the last meaning
  # xmlsec itself refused while Policy let the signature through.
  EXPECTED = {
    MERLIN => {
      "signature-enveloped-dsa" => %i[key_value valid],
      "signature-enveloping-b64-dsa" => %i[key_value valid],
      "signature-enveloping-dsa" => %i[key_value valid],
      "signature-enveloping-rsa" => %i[key_value valid],
      "signature-enveloping-hmac-sha1" => [[:certificate, "certs/merlin.pem"], HMAC],
      "signature-enveloping-hmac-sha1-40" => [[:certificate, "certs/merlin.pem"], HMAC],
      # #74: these reference http://www.w3.org/TR/xml-stylesheet.
      "signature-external-dsa" => [:key_value, EXTERNAL],
      "signature-external-b64-dsa" => [:key_value, EXTERNAL],
      "signature-keyname" => [[:certificate, "certs/lugh-cert.pem"], EXTERNAL],
      "signature-x509-crt" => [[:store, "certs/ca.pem"], EXTERNAL],
      # xmlsec expects this one to fail: the CRL revokes the signer.
      "signature-x509-crt-crl" => [[:store, "certs/ca.pem"], EXTERNAL],
      "signature-x509-is" => [[:certificate, "certs/macha.pem"], EXTERNAL],
      "signature-x509-ski" => [[:certificate, "certs/nemain.pem"], EXTERNAL],
      "signature-x509-sn" => [[:certificate, "certs/badb.pem"], EXTERNAL],
      "signature-retrievalmethod-rawx509crt" => [[:store, "certs/ca.pem"], RETRIEVAL_METHOD],
      # A SignatureProperty holds a no-namespace element, where the XML-DSig
      # schema's ##other wildcard only admits namespaced ones.
      "signature" => [[:certificate, "certs/merlin.pem"], [:schema, /NonCommentandus/]]
    },
    PHAOS => {
      "signature-dsa-enveloped" => [[:store, "certs/dsa-ca-cert.der"], :valid],
      "signature-dsa-enveloping" => [[:store, "certs/dsa-ca-cert.der"], :valid],
      "signature-rsa-enveloped" => [[:store, "certs/rsa-ca-cert.der"], :valid],
      "signature-rsa-enveloping" => [[:store, "certs/rsa-ca-cert.der"], :valid],
      # xmlsec expects both of these to fail too.
      "signature-rsa-enveloped-bad-digest-val" => [[:certificate, "certs/rsa-cert.der"],
                                                   [:native, /data and digest do not match/]],
      "signature-rsa-enveloped-bad-sig" => [[:certificate, "certs/rsa-cert.der"],
                                            [:schema, /Reference': Missing child/]],
      "signature-hmac-md5-c14n-enveloping" => [[:certificate, "certs/rsa-cert.der"], HMAC],
      "signature-hmac-sha1-40-c14n-comments-detached" => [[:certificate, "certs/rsa-cert.der"], HMAC],
      "signature-hmac-sha1-40-exclusive-c14n-comments-detached" => [[:certificate, "certs/rsa-cert.der"], HMAC],
      "signature-hmac-sha1-exclusive-c14n-comments-detached" => [[:certificate, "certs/rsa-cert.der"], HMAC],
      "signature-hmac-sha1-exclusive-c14n-enveloped" => [[:certificate, "certs/rsa-cert.der"], HMAC],
      # #74: these reference http://www.ietf.org/rfc/rfc3161.txt.
      "signature-dsa-detached" => [[:certificate, "certs/dsa-cert.der"], EXTERNAL],
      "signature-rsa-detached" => [[:certificate, "certs/rsa-cert.der"], EXTERNAL],
      "signature-big" => [[:certificate, "certs/rsa-cert.der"], [:policy, /more than this policy's max_references/]],
      "signature-rsa-xpath-transform-enveloped" => [[:certificate, "certs/rsa-cert.der"],
                                                    [:policy, /\(:xpath\) .* not in this policy's transforms/]],
      # With a pinned key, a wrong RetrievalMethod would not matter, but
      # Policy refuses RetrievalMethod before that. xmlsec fails the "bad" one.
      "signature-rsa-detached-xslt-transform-retrieval-method" => [[:certificate, "certs/rsa-cert.der"],
                                                                   RETRIEVAL_METHOD],
      "signature-rsa-detached-xslt-transform-bad-retrieval-method" => [[:certificate, "certs/rsa-cert.der"],
                                                                       RETRIEVAL_METHOD],
      # #75: SignedInfo signs a <Manifest> whose own references are external
      # (and some carry XPath or XSLT). Policy never sees them; xmlsec's
      # same-document URI restriction (S-04) refuses them. #74 alone would not
      # make these pass.
      "signature-dsa-manifest" => [[:certificate, "certs/dsa-cert.der"], [:native, /document\.xml/]],
      "signature-rsa-manifest" => [[:certificate, "certs/rsa-cert.der"], [:native, /document\.xml/]],
      "signature-rsa-manifest-x509-data-cert" => [[:certificate, "certs/rsa-cert.der"], [:native, /document\.xml/]],
      "signature-rsa-manifest-x509-data-cert-chain" => [[:certificate, "certs/rsa-cert.der"],
                                                        [:native, /document\.xml/]],
      "signature-rsa-manifest-x509-data-issuer-serial" => [[:certificate, "certs/rsa-cert.der"],
                                                           [:native, /document\.xml/]],
      "signature-rsa-manifest-x509-data-ski" => [[:certificate, "certs/rsa-cert.der"], [:native, /document\.xml/]],
      "signature-rsa-manifest-x509-data-subject-name" => [[:certificate, "certs/rsa-cert.der"],
                                                          [:native, /document\.xml/]],
      # xmlsec expects this one to fail: the CRL revokes the signer.
      "signature-rsa-~x509-data-crl" => [[:certificate, "certs/rsa-cert.der"], [:native, /document\.xml/]],
      "signature-rsa-detached-b64-transform" => [[:certificate, "certs/rsa-cert.der"], [:native, /document\.b64/]],
      "signature-rsa-detached-xpath-transform" => [[:certificate, "certs/rsa-cert.der"], [:native, /document\.xml/]],
      "signature-rsa-detached-xslt-transform" => [[:certificate, "certs/rsa-cert.der"],
                                                  [:native, /document-stylesheet\.xml/]]
    }
  }.freeze

  module_function

  def certificate(suite, file)
    OpenSSL::X509::Certificate.new(ROOT.join(suite, file).binread)
  end

  # The RSA or DSA public key in the vector's <KeyValue>, as SubjectPublicKeyInfo.
  def key_value(doc)
    ds = { "ds" => HankoXml::NS["ds"] }
    int = ->(name) { OpenSSL::ASN1::Integer(OpenSSL::BN.new(doc.at_xpath("//ds:KeyValue//ds:#{name}", ds).text.unpack1("m"), 2)) }

    algorithm, parameters, public_key =
      if doc.at_xpath("//ds:DSAKeyValue", ds)
        ["DSA", OpenSSL::ASN1::Sequence([int["P"], int["Q"], int["G"]]), int["Y"]]
      else
        ["rsaEncryption", OpenSSL::ASN1::Null(nil), OpenSSL::ASN1::Sequence([int["Modulus"], int["Exponent"]])]
      end
    spki = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId(algorithm), parameters]),
                                    OpenSSL::ASN1::BitString(public_key.to_der)])
    OpenSSL::PKey.read(spki.to_der)
  end

  def trust(suite, source, doc)
    kind, file = source
    case kind
    when :key_value then { key: key_value(doc) }
    when :certificate then { certificate: certificate(suite, file) }
    when :store then { store: OpenSSL::X509::Store.new.tap { |store| store.add_cert(certificate(suite, file)) } }
    end
  end
end

RSpec.describe "Interop vectors (#62)" do
  it "has an expectation for every vendored signature" do
    InteropVectors::EXPECTED.each do |suite, vectors|
      files = Dir.glob(InteropVectors::ROOT.join(suite, "signature*.xml").to_s).map { |f| File.basename(f, ".xml") }
      expect(vectors.keys).to match_array(files), suite
    end
  end

  InteropVectors::EXPECTED.each do |suite, vectors|
    describe suite do
      vectors.each do |name, (source, outcome)|
        it "#{name}: #{outcome == :valid ? "valid" : outcome.first}" do
          xml = InteropVectors::ROOT.join(suite, "#{name}.xml").binread
          verification = HankoXml::Verifier.new(
            **InteropVectors.trust(suite, source, Nokogiri::XML(xml)),
            policy: HankoXml::Policy.interop,
            verification_time: InteropVectors::VERIFICATION_TIME[suite]
          ).verify(xml)

          if outcome == :valid
            expect(verification.errors).to be_empty
            expect(verification.valid?).to be true
            next
          end

          kind, pattern = outcome
          error = verification.errors.first
          expect(verification.valid?).to be false
          case kind
          when :policy then expect(error).to be_a(HankoXml::PolicyError)
          when :schema then expect(error).to be_a(HankoXml::SchemaError)
          when :native then expect(error).to be_a(HankoXml::VerificationError)
          end
          text = kind == :native ? Array(error.xmlsec_errors).join("\n") : error.message
          expect(text).to match(pattern)
        end
      end
    end
  end

  # The four phaos x509 signatures also verify against their pinned leaf
  # certificate, not only through the CA store.
  %w[dsa rsa].product(%w[enveloped enveloping]).each do |algorithm, shape|
    it "phaos signature-#{algorithm}-#{shape} verifies against its pinned certificate" do
      suite = InteropVectors::PHAOS
      xml = InteropVectors::ROOT.join(suite, "signature-#{algorithm}-#{shape}.xml").binread
      result = HankoXml::Verifier.new(certificate: InteropVectors.certificate(suite, "certs/#{algorithm}-cert.der"),
                                      policy: HankoXml::Policy.interop,
                                      verification_time: InteropVectors::VERIFICATION_TIME[suite]).verify(xml)

      expect(result.valid?).to be true
    end
  end

  it "Policy.strict refuses the SHA-1 signatures that Policy.interop verifies" do
    suite = InteropVectors::PHAOS
    xml = InteropVectors::ROOT.join(suite, "signature-rsa-enveloped.xml").binread
    result = HankoXml::Verifier.new(certificate: InteropVectors.certificate(suite, "certs/rsa-cert.der"),
                                    verification_time: InteropVectors::VERIFICATION_TIME[suite]).verify(xml)

    expect(result.errors.first).to be_a(HankoXml::PolicyError)
  end
end
