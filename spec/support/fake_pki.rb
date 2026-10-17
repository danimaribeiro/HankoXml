# frozen_string_literal: true

require "openssl"

# A small CA for XAdES-LT specs (#168): a root, a signing certificate with
# the validity window the spec asks for, a delegated OCSP responder, and
# OCSP responses and CRLs about any certificate it issued. Nothing touches
# the network.
class FakePki
  attr_reader :root, :root_key, :leaf, :leaf_key, :responder, :responder_key

  def initialize(leaf_from:, leaf_to:, name: "HankoXml Test", responder_from: Time.utc(2020, 1, 1))
    forever = Time.utc(2040, 1, 1)
    @root_key = OpenSSL::PKey::RSA.new(2048)
    ca = [%w[basicConstraints CA:TRUE], %w[keyUsage keyCertSign,cRLSign]]
    @root = certificate("CN=#{name} Root", @root_key, @root_key, from: Time.utc(2020, 1, 1), to: forever,
                                                                 extensions: ca)
    @leaf_key = OpenSSL::PKey::RSA.new(2048)
    @leaf = certificate("CN=#{name} Signer", @leaf_key, @root_key, issuer: @root, from: leaf_from, to: leaf_to,
                                                                   extensions: [%w[keyUsage digitalSignature]])
    @responder_key = OpenSSL::PKey::RSA.new(2048)
    ocsp = [%w[extendedKeyUsage OCSPSigning]]
    @responder = certificate("CN=#{name} OCSP", @responder_key, @root_key, issuer: @root, from: responder_from,
                                                                           to: forever, extensions: ocsp)
  end

  def store
    OpenSSL::X509::Store.new.tap { |store| store.add_cert(@root) }
  end

  # An OCSP response about +subject+ (the leaf by default), signed by the
  # delegated responder (or +signer+ / +signer_key+).
  def ocsp(this_update:, subject: @leaf, revoked_at: nil, signer: @responder, signer_key: @responder_key)
    basic = OpenSSL::OCSP::BasicResponse.new
    id = OpenSSL::OCSP::CertificateId.new(subject, @root, OpenSSL::Digest.new("SHA256"))
    status = revoked_at ? OpenSSL::OCSP::V_CERTSTATUS_REVOKED : OpenSSL::OCSP::V_CERTSTATUS_GOOD
    basic.add_status(id, status, revoked_at ? OpenSSL::OCSP::REVOKED_STATUS_KEYCOMPROMISE : 0, revoked_at,
                     this_update, nil, [])
    basic.sign(signer, signer_key, [signer], 0)
    OpenSSL::OCSP::Response.create(OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL, basic)
  end

  # A CRL from the root; +revoked+ maps certificates to revocation times.
  def crl(last_update:, revoked: {}, key: @root_key)
    OpenSSL::X509::CRL.new.tap do |crl|
      crl.version = 1
      crl.issuer = @root.subject
      crl.last_update = last_update
      crl.next_update = last_update + (7 * 86_400)
      revoked.each do |certificate, time|
        entry = OpenSSL::X509::Revoked.new
        entry.serial = certificate.serial
        entry.time = time
        crl.add_revoked(entry)
      end
      crl.sign(key, OpenSSL::Digest.new("SHA256"))
    end
  end

  def certificate(subject, key, signing_key, from:, to:, issuer: nil, extensions: [])
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = OpenSSL::BN.rand(64)
    cert.subject = OpenSSL::X509::Name.parse(subject)
    cert.issuer = issuer ? issuer.subject : cert.subject
    cert.public_key = key.public_key
    cert.not_before = from
    cert.not_after = to
    factory = OpenSSL::X509::ExtensionFactory.new(issuer || cert, cert)
    extensions.each { |oid, value| cert.add_extension(factory.create_extension(oid, value, true)) }
    cert.sign(signing_key, OpenSSL::Digest.new("SHA256"))
    cert
  end
end
