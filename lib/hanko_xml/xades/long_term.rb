# frozen_string_literal: true

require "openssl"

module HankoXml
  module Xades
    # The revocation evidence one certificate of the chain passed with (#168),
    # on LongTermValidation#revocation.
    # +source+ is :ocsp or :crl; +issued_at+ its thisUpdate; +status+ :good, or
    # :revoked_later when it was revoked after the validation time.
    RevocationStatus = Struct.new(:certificate, :source, :issued_at, :status, keyword_init: true) do
      def initialize(**)
        super
        freeze
      end
    end

    # A passed XAdES-LT validation (#168), on
    # Xades::Verification#long_term_validation: the validation +time+ (the
    # earliest verified SignatureTimeStamp), the signing +certificate_chain+
    # (leaf first, ending at the caller's trust anchor), and the +revocation+
    # evidence for each certificate below the anchor.
    LongTermValidation = Struct.new(:time, :certificate_chain, :revocation, keyword_init: true) do
      def initialize(**)
        super
        freeze
      end
    end

    # The embedded <xades:CertificateValues> and <xades:RevocationValues> of
    # one signature, parsed. Attacker-supplied until LongTermCheck uses them
    # (S-22, S-23).
    #
    # @api private
    class LongTermValues
      attr_reader :certificates, :crls, :ocsp_responses

      PATHS = {
        certificates: "xades:CertificateValues/xades:EncapsulatedX509Certificate",
        crls: "xades:RevocationValues/xades:CRLValues/xades:EncapsulatedCRLValue",
        ocsp_responses: "xades:RevocationValues/xades:OCSPValues/xades:EncapsulatedOCSPValue"
      }.freeze

      # The values in +properties+ (an UnsignedSignatureProperties), or nil
      # when it holds no CertificateValues or RevocationValues.
      def self.read(properties, ns)
        return nil unless properties
        return nil if properties.xpath("xades:CertificateValues | xades:RevocationValues", ns).empty?

        Locator.fail!("XAdES-LT values are verified only in the XAdES 1.3.2 namespace") unless ns["xades"] == NS
        new(**PATHS.to_h { |kind, path| [kind, properties.xpath(path, ns).map { |node| parse(kind, node.text) }] })
      end

      def self.parse(kind, base64)
        der = base64.gsub(/\s/, "").unpack1("m0")
        case kind
        when :certificates then OpenSSL::X509::Certificate.new(der)
        when :crls then OpenSSL::X509::CRL.new(der)
        else
          OpenSSL::OCSP::Response.new(der).tap do |response|
            unless response.status == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL && response.basic
              Locator.fail!("an <xades:EncapsulatedOCSPValue> is not a successful OCSP response")
            end
          end
        end
      rescue ArgumentError, OpenSSL::X509::CertificateError, OpenSSL::X509::CRLError, OpenSSL::OCSP::OCSPError
        Locator.fail!("an embedded XAdES-LT value is not Base64 DER of its type (#{kind})")
      end
      private_class_method :parse

      def initialize(certificates:, crls:, ocsp_responses:)
        @certificates = certificates.freeze
        @crls = crls.freeze
        @ocsp_responses = ocsp_responses.freeze
        freeze
      end
    end

    # Validates the signing certificate chain at the time of the earliest
    # verified SignatureTimeStamp, with the embedded revocation data (#168).
    #
    # The chain itself has already been built and verified at that time by
    # {HankoXml::Verifier} (store:, StoreContext with time=). Here, each
    # certificate below the trust anchor needs revocation evidence that:
    #
    # - verifies: an OCSP response through OpenSSL::OCSP::BasicResponse#verify
    #   (the responder's signature, its chain to the same anchor, and its
    #   authorization for that certificate), with the responder's chain then
    #   checked at the response's producedAt; or a CRL signed by the
    #   certificate's issuer (CRL#verify), an issuer allowed to sign CRLs;
    # - is fresh: issued (thisUpdate) no earlier than the validation time
    #   minus +grace+, and not in the future;
    # - does not show the certificate revoked at or before the validation
    #   time. Revoked later is accepted: the timestamp proves the signature
    #   existed before.
    #
    # Evidence that does not verify or is stale is not used; a certificate
    # left without usable evidence fails, and so does any usable evidence of
    # an earlier revocation (fail closed, S-23).
    #
    # @api private
    class LongTermCheck
      CRL_SIGN_BIT = 6

      def initialize(grace:, clock_skew:)
        @grace = grace
        @clock_skew = clock_skew
      end

      # @return [LongTermValidation]
      # @raise [XadesError]
      def verify(time:, chain:, values:)
        @time = time
        @anchor = chain.last
        @pool = (chain + values.certificates).uniq(&:to_der)
        @values = values
        revocation = chain.each_cons(2).with_index.map { |(certificate, issuer), i| status(certificate, issuer, i) }
        LongTermValidation.new(time: time, certificate_chain: chain.freeze, revocation: revocation.freeze)
      end

      private

      # +position+ names the certificate in messages: its subject comes from
      # the document, so it goes to #xmlsec_errors, not the message (S-13).
      def status(certificate, issuer, position)
        evidence = ocsp_evidence(certificate, issuer) + crl_evidence(certificate, issuer)
        revoked = evidence.find { |item| item.status == :revoked }
        if revoked
          fail!("the embedded #{revoked.source.upcase} shows #{name(position)} revoked at or before the " \
                "validation time", certificate)
        end
        found = evidence.min_by { |item| item.status == :good ? 0 : 1 }
        fail!("no embedded revocation data verifies and is fresh for #{name(position)}", certificate) unless found

        found
      end

      def name(position)
        position.zero? ? "the signing certificate" : "chain certificate #{position}"
      end

      def ocsp_evidence(certificate, issuer)
        @values.ocsp_responses.flat_map do |response|
          basic = response.basic
          singles = basic.responses.select { |single| about?(single.certid, certificate, issuer) }
          next [] if singles.empty? || !responder_verified?(basic)

          singles.filter_map { |single| ocsp_status(certificate, single) }
        end
      end

      def about?(certid, certificate, issuer)
        return false unless certid.serial == certificate.serial

        OpenSSL::OCSP::CertificateId.new(certificate, issuer, OpenSSL::Digest.new(certid.hash_algorithm)).cmp(certid)
      rescue OpenSSL::OCSP::OCSPError, RuntimeError
        false
      end

      def ocsp_status(certificate, single)
        return nil unless fresh?(single.this_update)

        status = case single.cert_status
                 when OpenSSL::OCSP::V_CERTSTATUS_GOOD then :good
                 when OpenSSL::OCSP::V_CERTSTATUS_REVOKED then revoked_status(single.revocation_time)
                 end
        status && RevocationStatus.new(certificate: certificate, source: :ocsp, issued_at: single.this_update,
                                       status: status)
      end

      def revoked_status(revoked_at)
        revoked_at > @time ? :revoked_later : :revoked
      end

      # OpenSSL checks the signature, the responder's chain to the anchor and
      # its authorization; it cannot take a verification time, so it runs
      # without time checks and the responder's chain is then verified at
      # producedAt.
      def responder_verified?(basic)
        response_certificates, responder_id, produced_at = ocsp_fields(basic)
        pool = (@pool + response_certificates).uniq(&:to_der)
        return false unless basic.verify(pool, anchor_store(OpenSSL::X509::V_FLAG_NO_CHECK_TIME))

        signer = pool.find { |candidate| responder?(candidate, responder_id) }
        return false unless signer

        context = OpenSSL::X509::StoreContext.new(anchor_store, signer, pool)
        context.time = produced_at
        context.verify
      end

      # BasicOCSPResponse (RFC 6960 §4.2.1): its certs, ResponderID and
      # producedAt, which OpenSSL::OCSP::BasicResponse does not expose.
      def ocsp_fields(basic)
        sequence = OpenSSL::ASN1.decode(basic.to_der).value
        fields = sequence[0].value
        fields = fields.drop(1) if fields.first.tag_class == :CONTEXT_SPECIFIC && fields.first.tag.zero?
        certificates = sequence[3]&.value&.first&.value.to_a.map { |cert| OpenSSL::X509::Certificate.new(cert.to_der) }
        [certificates, fields[0], fields[1].value]
      end

      # ResponderID: byName [1] or byKey [2] (SHA-1 of the public key bits).
      def responder?(certificate, responder_id)
        value = responder_id.value.first
        if responder_id.tag == 1
          certificate.subject.to_der == value.to_der
        else
          key_bits = OpenSSL::ASN1.decode(certificate.public_key.to_der).value[1].value
          OpenSSL::Digest.digest("SHA1", key_bits) == value.value
        end
      end

      def crl_evidence(certificate, issuer)
        return [] unless crl_signer?(issuer)

        @values.crls.filter_map do |crl|
          next unless crl.issuer.to_der == issuer.subject.to_der && crl.verify(issuer.public_key)
          next unless fresh?(crl.last_update)

          entry = crl.revoked.find { |revoked| revoked.serial == certificate.serial }
          status = entry ? revoked_status(entry.time) : :good
          RevocationStatus.new(certificate: certificate, source: :crl, issued_at: crl.last_update, status: status)
        end
      end

      # No KeyUsage means no restriction (RFC 5280); otherwise cRLSign.
      def crl_signer?(issuer)
        extension = issuer.extensions.find { |ext| ext.oid == "keyUsage" }
        return true if extension.nil?

        OpenSSL::ASN1.decode(extension.value_der).value.to_s.unpack1("B*").to_s[CRL_SIGN_BIT] == "1"
      rescue OpenSSL::ASN1::ASN1Error
        false
      end

      def fresh?(issued_at)
        issued_at >= @time - @grace && issued_at <= Time.now + @clock_skew
      end

      def anchor_store(flags = nil)
        OpenSSL::X509::Store.new.tap do |store|
          store.add_cert(@anchor)
          store.flags = flags if flags
        end
      end

      def fail!(message, certificate)
        raise HankoXml::XadesError.new(message, xmlsec_errors: ["subject: #{certificate.subject}"])
      end
    end
  end
end
