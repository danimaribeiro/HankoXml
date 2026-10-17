# frozen_string_literal: true

require "openssl"

# A local RFC 3161 TSA for specs (#162, #163): a CA and a TSA certificate
# made at load time, and OpenSSL::Timestamp::Factory to answer requests.
# Nothing touches the network.
class FakeTsa
  attr_reader :ca_certificate, :certificate, :requests

  def initialize(gen_time: Time.utc(2026, 9, 17, 14, 33, 0), serial: 1,
                 allowed_digests: %w[sha1 sha256 sha384 sha512 sha3-256 sha3-384 sha3-512])
    @gen_time = gen_time
    @allowed_digests = allowed_digests
    @serial = serial
    @requests = []
    @ca_key = OpenSSL::PKey::RSA.new(2048)
    @ca_certificate = build_certificate("CN=HankoXml Test TSA Root", @ca_key, @ca_key, authority: true)
    @key = OpenSSL::PKey::RSA.new(2048)
    @certificate = build_certificate("CN=HankoXml Test TSA", @key, @ca_key, issuer: @ca_certificate)
  end

  # A timestamper: for Xades::Signer. +tamper+ may rewrite the parsed
  # request before it is answered, or the DER response after.
  def timestamper(&tamper)
    lambda do |request_der|
      request = OpenSSL::Timestamp::Request.new(request_der)
      @requests << request
      answer = tamper ? tamper.call(request) : request
      answer.is_a?(String) ? answer : respond(answer).to_der
    end
  end

  def respond(request)
    factory = OpenSSL::Timestamp::Factory.new
    factory.gen_time = @gen_time
    factory.serial_number = @serial
    factory.default_policy_id = "1.2.3.4.1"
    factory.allowed_digests = @allowed_digests
    factory.create_timestamp(@key, @certificate, request)
  end

  def store
    OpenSSL::X509::Store.new.tap { |store| store.add_cert(@ca_certificate) }
  end

  private

  def build_certificate(subject, key, signing_key, authority: false, issuer: nil)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = OpenSSL::BN.rand(64)
    cert.subject = OpenSSL::X509::Name.parse(subject)
    cert.issuer = issuer ? issuer.subject : cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.utc(2020, 1, 1)
    cert.not_after = Time.utc(2040, 1, 1)
    extensions = OpenSSL::X509::ExtensionFactory.new(issuer || cert, cert)
    if authority
      cert.add_extension(extensions.create_extension("basicConstraints", "CA:TRUE", true))
      cert.add_extension(extensions.create_extension("keyUsage", "keyCertSign,cRLSign", true))
    else
      cert.add_extension(extensions.create_extension("extendedKeyUsage", "timeStamping", true))
    end
    cert.sign(signing_key, OpenSSL::Digest.new("SHA256"))
    cert
  end
end
