abstract class OpenSSL::SSL::SuperContext < OpenSSL::SSL::Context
  class Client < SuperContext
    @hostname : String?

    def self.new
      new SuperContext.default_method
    end

    protected def set_cert_verify_callback(hostname : String)
      # Sanitize the hostname with PunyCode
      hostname = URI::Punycode.to_ascii hostname

      # Keep a reference so the GC doesn't collect it after sending it to C land
      @hostname = hostname
      LibSSL.ssl_ctx_set_cert_verify_callback(@handle, ->(x509_ctx, arg) {
        if LibCrypto.x509_verify_cert(x509_ctx) != 0_i32
          cert = LibCrypto.x509_store_ctx_get_current_cert(x509_ctx)
          HostnameValidation.validate_hostname(arg.as(String), cert) == HostnameValidation::Result::MatchFound ? 1_i32 : 0_i32
        else
          0_i32
        end
      }, hostname.as(Void*))
    end
  end

  class Server < SuperContext
    def self.new
      new SuperContext.default_method
    end

    # Set the CA certificate by string, in PEM format, used to
    # validate the peers certificate.
    def set_ca_certificate_text(certificate : String, sync_free : Bool = false)
      certificate = OpenSSL::X509::SuperCertificate.parse certificate

      begin
        self.ca_certificate_text = certificate
      ensure
        certificate.free if sync_free
      end
    end

    # Set the CA certificate by string, in PEM format, used to
    # validate the peers certificate.
    def ca_certificate_text=(certificate : OpenSSL::X509::SuperCertificate)
      ret = LibSSL.ssl_ctx_use_certificate @handle, certificate
      raise OpenSSL::Error.new "SSL_CTX_use_certificate" unless ret == 1_i32
    end

    def set_private_key_text(private_key : String, sync_free : Bool = false)
      parse = OpenSSL::PKey.parse_private_key private_key

      begin
        self.private_key_text = parse.pkey
      ensure
        parse.free if sync_free
      end
    end

    # Set the private key by string, The key must in PEM format.
    def private_key_text=(pkey : LibCrypto::EVP_PKEY)
      ret = LibSSL.ssl_ctx_use_privatekey @handle, pkey
      raise OpenSSL::Error.new "SSL_CTX_use_PrivateKey" unless ret == 1_i32
    end
  end

  def freed?
    @freed
  end

  def freed=(value : Bool)
    @freed = value
  end

  def free
    return if freed?
    free!
  end

  def free!
    @freed = true
    LibSSL.ssl_ctx_free self
  end

  def finalize
  end
end
