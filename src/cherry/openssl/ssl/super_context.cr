abstract class OpenSSL::SSL::SuperContext < OpenSSL::SSL::Context
  class Client < SuperContext
    @hostname : String?

    def self.new
      new SuperContext.default_method
    end
  end

  class Server < SuperContext
    def self.new
      new SuperContext.default_method
    end

    # Set the CA certificate by string, in PEM format, used to
    # validate the peers certificate.
    def ca_certificate_text=(certificate : String)
      certificate = OpenSSL::X509::SuperCertificate.parse certificate

      self.ca_certificate_text = certificate ensure certificate.free
    end

    # Set the CA certificate by string, in PEM format, used to
    # validate the peers certificate.
    def ca_certificate_text=(certificate : OpenSSL::X509::SuperCertificate)
      ret = LibSSL.ssl_ctx_use_certificate @handle, certificate
      raise OpenSSL::Error.new "SSL_CTX_use_certificate" unless ret == 1_i32
    end

    def private_key_text=(private_key : String)
      parse = OpenSSL::PKey.parse_private_key private_key

      self.private_key_text = parse ensure parse.free
    end

    # Set the private key by string, The key must in PEM format.
    def private_key_text=(pkey : LibCrypto::EVP_PKEY | OpenSSL::PKey)
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
