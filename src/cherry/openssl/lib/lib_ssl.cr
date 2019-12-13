lib LibSSL
  fun ssl_ctx_use_certificate = SSL_CTX_use_certificate(ctx : SSLContext, x509 : LibCrypto::X509) : Int
  fun ssl_ctx_use_privatekey = SSL_CTX_use_PrivateKey(ctx : SSLContext, pkey : LibCrypto::EVP_PKEY) : Int
end
