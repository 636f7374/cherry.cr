abstract class OpenSSL::SSL::Context
  class Server < Context
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

    # Set the private key by string, The key must in PEM format.
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
end
