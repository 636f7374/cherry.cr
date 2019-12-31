lib LibCrypto
  alias UChar = LibC::UChar
  alias BIO = Bio*
  alias BIO_Method = BioMethod*

  type PasswordCallback = (Char*, Int, Int, Void*) -> Int
  type EVP_PKEY = Void*
  type RSA = Void*
  type DSA = Void*
  type ASN1_INTEGER = Void*
  type ASN1_TIME = Void*
  type X509_REQ = Void*
  type X509_CRL = Void*

  BIO_CTRL_RESET = 1_i32

  struct X509V3_CTX
    flags : Int32
    issuer_cert : Void*
    subject_cert : Void*
    subject_req : Void*
    crl : Void*
    db_meth : Void*
    db : Void*
  end

  fun bio_s_mem = BIO_s_mem : BIO_Method
  fun bio_new = BIO_new(type : BIO_Method) : BIO
  fun bio_read = BIO_read(b : BIO, buf : Void*, len : Int) : Int
  fun bio_write = BIO_write(b : BIO, buf : Void*, len : Int) : Int
  fun bio_free = BIO_free(a : BIO) : Int
  fun bio_free_all = BIO_free_all(a : BIO) : Int
  fun bio_ctrl = BIO_ctrl(bp : BIO, cmd : Int, larg : Long, parg : Void*) : Long

  fun evp_pkey_assign = EVP_PKEY_assign(pkey : EVP_PKEY, type : Int, key : Void*) : Int
  fun evp_pkey_new = EVP_PKEY_new : EVP_PKEY
  fun evp_pkey_free = EVP_PKEY_free(key : EVP_PKEY)
  fun evp_pkey_get1_rsa = EVP_PKEY_get1_RSA(pkey : EVP_PKEY) : RSA
  fun evp_pkey_get1_dsa = EVP_PKEY_get1_DSA(pkey : EVP_PKEY) : DSA
  fun evp_pkey_size = EVP_PKEY_size(pkey : EVP_PKEY) : Int
  fun evp_md_null = EVP_md_null : EVP_MD
  fun evp_md2 = EVP_md2 : EVP_MD
  fun evp_md5 = EVP_md5 : EVP_MD
  fun evp_sha1 = EVP_sha1 : EVP_MD
  fun evp_mdc2 = EVP_mdc2 : EVP_MD
  fun evp_ripemd160 = EVP_ripemd160 : EVP_MD
  fun evp_blake2b512 = EVP_blake2b512 : EVP_MD
  fun evp_blake2s256 = EVP_blake2s256 : EVP_MD
  fun evp_sha224 = EVP_sha224 : EVP_MD
  fun evp_sha256 = EVP_sha256 : EVP_MD
  fun evp_sha384 = EVP_sha384 : EVP_MD
  fun evp_sha512 = EVP_sha512 : EVP_MD

  fun evp_enc_null = EVP_enc_null : EVP_CIPHER
  fun evp_aes_128_cbc = EVP_aes_128_cbc : EVP_CIPHER
  fun evp_aes_128_ecb = EVP_aes_128_ecb : EVP_CIPHER
  fun evp_aes_128_cfb = EVP_aes_128_cfb : EVP_CIPHER
  fun evp_aes_128_ofb = EVP_aes_128_ofb : EVP_CIPHER
  fun evp_aes_192_cbc = EVP_aes_192_cbc : EVP_CIPHER
  fun evp_aes_192_ecb = EVP_aes_192_ecb : EVP_CIPHER
  fun evp_aes_192_cfb = EVP_aes_192_cfb : EVP_CIPHER
  fun evp_aes_192_ofb = EVP_aes_192_ofb : EVP_CIPHER
  fun evp_aes_256_cbc = EVP_aes_256_cbc : EVP_CIPHER
  fun evp_aes_256_ecb = EVP_aes_256_ecb : EVP_CIPHER
  fun evp_aes_256_cfb = EVP_aes_256_cfb : EVP_CIPHER
  fun evp_aes_256_ofb = EVP_aes_256_ofb : EVP_CIPHER
  fun evp_des_cbc = EVP_des_cbc : EVP_CIPHER
  fun evp_des_ecb = EVP_des_ecb : EVP_CIPHER
  fun evp_des_cfb = EVP_des_cfb : EVP_CIPHER
  fun evp_des_ofb = EVP_des_ofb : EVP_CIPHER
  fun evp_des_ede_cbc = EVP_des_ede_cbc : EVP_CIPHER
  fun evp_des_ede = EVP_des_ede : EVP_CIPHER
  fun evp_des_ede_ofb = EVP_des_ede_ofb : EVP_CIPHER
  fun evp_des_ede_cfb = EVP_des_ede_cfb : EVP_CIPHER
  fun evp_des_ede3_cbc = EVP_des_ede3_cbc : EVP_CIPHER
  fun evp_des_ede3 = EVP_des_ede3 : EVP_CIPHER
  fun evp_des_ede3_ofb = EVP_des_ede3_ofb : EVP_CIPHER
  fun evp_des_ede3_cfb = EVP_des_ede3_cfb : EVP_CIPHER
  fun evp_desx_cbc = EVP_desx_cbc : EVP_CIPHER
  fun evp_rc4 = EVP_rc4 : EVP_CIPHER
  fun evp_rc4_40 = EVP_rc4_40 : EVP_CIPHER
  fun evp_idea_cbc = EVP_idea_cbc : EVP_CIPHER
  fun evp_idea_ecb = EVP_idea_ecb : EVP_CIPHER
  fun evp_idea_cfb = EVP_idea_cfb : EVP_CIPHER
  fun evp_idea_ofb = EVP_idea_ofb : EVP_CIPHER
  fun evp_rc2_cbc = EVP_rc2_cbc : EVP_CIPHER
  fun evp_rc2_ecb = EVP_rc2_ecb : EVP_CIPHER
  fun evp_rc2_cfb = EVP_rc2_cfb : EVP_CIPHER
  fun evp_rc2_ofb = EVP_rc2_ofb : EVP_CIPHER
  fun evp_rc2_40_cbc = EVP_rc2_40_cbc : EVP_CIPHER
  fun evp_rc2_64_cbc = EVP_rc2_64_cbc : EVP_CIPHER
  fun evp_bf_cbc = EVP_bf_cbc : EVP_CIPHER
  fun evp_bf_ecb = EVP_bf_ecb : EVP_CIPHER
  fun evp_bf_cfb = EVP_bf_cfb : EVP_CIPHER
  fun evp_bf_ofb = EVP_bf_ofb : EVP_CIPHER
  fun evp_cast5_cbc = EVP_cast5_cbc : EVP_CIPHER
  fun evp_cast5_ecb = EVP_cast5_ecb : EVP_CIPHER
  fun evp_cast5_cfb = EVP_cast5_cfb : EVP_CIPHER
  fun evp_cast5_ofb = EVP_cast5_ofb : EVP_CIPHER
  fun evp_rc5_32_12_16_cbc = EVP_rc5_32_12_16_cbc : EVP_CIPHER
  fun evp_rc5_32_12_16_ecb = EVP_rc5_32_12_16_ecb : EVP_CIPHER
  fun evp_rc5_32_12_16_cfb = EVP_rc5_32_12_16_cfb : EVP_CIPHER
  fun evp_rc5_32_12_16_ofb = EVP_rc5_32_12_16_ofb : EVP_CIPHER
  fun evp_aes_128_gcm = EVP_aes_128_gcm : EVP_CIPHER
  fun evp_aes_192_gcm = EVP_aes_192_gcm : EVP_CIPHER
  fun evp_aes_256_gcm = EVP_aes_256_gcm : EVP_CIPHER
  fun evp_aes_128_ocb = EVP_aes_128_ocb : EVP_CIPHER
  fun evp_aes_192_ocb = EVP_aes_192_ocb : EVP_CIPHER
  fun evp_aes_256_ocb = EVP_aes_256_ocb : EVP_CIPHER
  fun evp_aes_128_ccm = EVP_aes_128_ccm : EVP_CIPHER
  fun evp_aes_192_ccm = EVP_aes_192_ccm : EVP_CIPHER
  fun evp_aes_256_ccm = EVP_aes_256_ccm : EVP_CIPHER
  fun evp_chacha20 = EVP_chacha20 : EVP_CIPHER
  fun evp_chacha20_poly1305 = EVP_chacha20_poly1305 : EVP_CIPHER

  fun rsa_generate_key = RSA_generate_key(bits : Int, e : ULong, callback : (Int, Int, Void*) ->, cb_arg : Void*) : RSA
  fun rsa_free = RSA_free(rsa : RSA) : Void
  fun rsapublickey_dup = RSAPublicKey_dup(rsa : RSA) : RSA
  fun rsaprivateKey_dup = RSAPrivateKey_dup(rsa : RSA) : RSA
  fun rsa_size = RSA_size(rsa : RSA) : Int

  fun dsa_generate_parameters = DSA_generate_parameters(bit : Int, seed : UChar*, seed_len : Int, counter_ret : Int*, h_ret : ULong*, callback : (Int, Int, Void*) ->, cb_arg : Void*) : DSA
  fun dsa_generate_key = DSA_generate_key(a : DSA) : Int
  fun dsa_free = DSA_free(dsa : DSA) : Void
  fun dsa_size = DSA_size(dsa : DSA) : Int
  fun dsapublickey_dup = DSAPublicKey_dup(rsa : DSA) : DSA
  fun dsaprivateKey_dup = DSAPrivateKey_dup(rsa : DSA) : DSA

  fun pem_read_bio_rsaprivatekey = PEM_read_bio_RSAPrivateKey(bp : BIO, x : RSA, cb : PasswordCallback, u : Void*) : RSA
  fun pem_read_bio_dsaprivatekey = PEM_read_bio_DSAPrivateKey(bp : BIO, x : DSA, cb : PasswordCallback, u : Void*) : DSA
  fun pem_read_bio_pubkey = PEM_read_bio_PUBKEY(bp : BIO, x : EVP_PKEY, cb : PasswordCallback, u : Void*) : EVP_PKEY
  fun pem_read_bio_privatekey = PEM_read_bio_PrivateKey(bp : BIO, x : EVP_PKEY, cb : PasswordCallback, u : Void*) : EVP_PKEY
  fun pem_read_bio_x509 = PEM_read_bio_X509(bp : BIO, x : X509, cb : PasswordCallback, u : Void*) : X509
  fun pem_read_bio_x509_req = PEM_read_bio_X509_REQ(bp : BIO, x : X509_REQ, cb : PasswordCallback, u : Void*) : X509_REQ
  fun pem_write_bio_x509 = PEM_write_bio_X509(bp : BIO, x : X509) : Int
  fun pem_write_bio_x509_req = PEM_write_bio_X509_REQ(bp : BIO, x : X509_REQ) : X509_REQ
  fun pem_write_bio_rsa_pubkey = PEM_write_bio_RSA_PUBKEY(bp : BIO, x : RSA) : Int
  fun pem_write_bio_rsaprivatekey = PEM_write_bio_RSAPrivateKey(bp : BIO, x : RSA, enc : EVP_CIPHER, kstr : UChar*, klen : Int, cb : PasswordCallback, u : Void*) : Int
  fun pem_write_bio_dsaprivatekey = PEM_write_bio_DSAPrivateKey(bp : BIO, x : DSA, enc : EVP_CIPHER, kstr : UChar*, klen : Int, cb : PasswordCallback, u : Void*) : Int
  fun pem_write_bio_dsa_pubkey = PEM_write_bio_DSA_PUBKEY(bp : BIO, x : DSA) : Int

  fun asn1_time_free = ASN1_TIME_free(a : ASN1_TIME) : Void
  fun asn1_integer_set = ASN1_INTEGER_set(a : ASN1_INTEGER, v : Long) : Int
  fun asn1_dup = ASN1_dup(i2d_of_void : Void*, d2i_of_void : Void*, x : Void*) : Void*
  fun asn1_integer_new = ASN1_INTEGER_new : ASN1_INTEGER
  fun asn1_integer_free = ASN1_INTEGER_free(a : ASN1_INTEGER) : Void

  fun x509_get_issuer_name = X509_get_issuer_name(x : X509) : X509_NAME
  fun x509_get_pubkey = X509_get_pubkey(x : X509) : EVP_PKEY
  fun x509_get_serialnumber = X509_get_serialNumber(x : X509) : ASN1_INTEGER
  fun x509_set_notbefore = X509_set_notBefore(x : X509, tm : ASN1_TIME) : Int
  fun x509_set_notafter = X509_set_notAfter(x : X509, tm : ASN1_TIME) : Int
  fun x509_set1_notbefore = X509_set1_notBefore(x : X509, tm : ASN1_TIME) : Int
  fun x509_set1_notafter = X509_set1_notAfter(x : X509, tm : ASN1_TIME) : Int
  fun x509_get0_notbefore = X509_get0_notBefore(x : X509) : ASN1_TIME
  fun x509_get0_notafter = X509_get0_notAfter(x : X509) : ASN1_TIME
  fun x509_set_version = X509_set_version(x : X509, version : Long) : Int
  fun x509_set_pubkey = X509_set_pubkey(x : X509, pkey : EVP_PKEY) : Int
  fun x509_set_issuer_name = X509_set_issuer_name(x : X509, name : X509_NAME) : Int
  fun x509_set_serialnumber = X509_set_serialNumber(x : X509, serial : ASN1_INTEGER) : Int
  fun x509v3_set_ctx = X509V3_set_ctx(ctx : X509V3_CTX*, issuer : X509, subj : X509, req : X509_REQ, crl : X509_CRL, flags : Int) : Void
  fun x509v3_ext_conf_nid = X509V3_EXT_conf_nid(conf : Void*, ctx : X509V3_CTX*, ext_nid : Int, value : Char*) : X509_EXTENSION
  fun x509_sign = X509_sign(x : X509, pkey : EVP_PKEY, md : EVP_MD) : Int
  fun x509_gmtime_adj = X509_gmtime_adj(s : ASN1_TIME, adj : Long) : ASN1_TIME
  fun x509_verify = X509_verify(a : X509, r : EVP_PKEY) : Int
  fun x509_req_new = X509_REQ_new : X509_REQ
  fun x509_req_free = X509_REQ_free(a : X509_REQ) : Void
  fun x509_req_sign = X509_REQ_sign(x : X509_REQ, pkey : EVP_PKEY, md : EVP_MD) : Int
  fun x509_req_get_pubkey = X509_REQ_get_pubkey(req : X509_REQ) : EVP_PKEY
  fun x509_req_get_subject_name = X509_REQ_get_subject_name(req : X509_REQ) : X509_NAME
  fun x509_req_set_version = X509_REQ_set_version(x : X509_REQ, version : Long) : Int
  fun x509_req_set_pubkey = X509_REQ_set_pubkey(x : X509_REQ, pkey : EVP_PKEY) : Int
  fun x509_req_set_subject_name = X509_REQ_set_subject_name(req : X509_REQ, name : X509_NAME) : Int
end
