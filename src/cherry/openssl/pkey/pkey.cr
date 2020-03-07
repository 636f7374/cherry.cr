module OpenSSL
  class PKey
    enum KeyType
      All
      PrivateKey
      PublicKey
    end

    getter keyType : KeyType
    property pkey : LibCrypto::EVP_PKEY

    def initialize(@pkey : LibCrypto::EVP_PKEY, @keyType = KeyType::PublicKey)
    end

    def initialize(@keyType = KeyType::All)
      @pkey = LibCrypto.evp_pkey_new
    end

    def self.free(pkey : LibCrypto::EVP_PKEY | PKey)
      LibCrypto.evp_pkey_free pkey
    end

    def free(pkey : LibCrypto::EVP_PKEY | PKey)
      PKey.free pkey
    end

    def free
      free self
    end

    def pkey=(pkey : LibCrypto::EVP_PKEY)
      @pkey = pkey
    end

    def self.parse_public_key(public_key : String, password = nil)
      bio = MemBIO.new
      bio.write public_key
      pkey = LibCrypto.pem_read_bio_pubkey bio, nil, nil, password

      new pkey, KeyType::PublicKey
    end

    def self.parse_private_key(private_key : String, password = nil)
      bio = MemBIO.new
      bio.write private_key

      pkey = LibCrypto.pem_read_bio_privatekey bio, nil, nil, password

      new pkey, KeyType::PrivateKey
    end

    def private_key?
      KeyType::PrivateKey == keyType
    end

    def public_key?
      KeyType::PublicKey == keyType
    end

    def to_rsa
      RSA.new LibCrypto.evp_pkey_get1_rsa(self), keyType
    end

    def to_dsa
      DSA.new LibCrypto.evp_pkey_get1_dsa(self), keyType
    end

    def modulus_size
      LibCrypto.evp_pkey_size self
    end

    def to_unsafe
      @pkey
    end
  end
end
