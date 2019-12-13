module OpenSSL
  class PKey
    enum KeyType
      All
      PrivateKey
      PublicKey
    end

    property pkey : LibCrypto::EVP_PKEY
    getter keyType : KeyType

    def initialize(@pkey : LibCrypto::EVP_PKEY, @keyType = KeyType::PublicKey)
    end

    def self.new(rsa : LibCrypto::RSA, keyType = KeyType::All)
      pkey = LibCrypto.evp_pkey_new
      LibCrypto.evp_pkey_assign pkey, OpenSSL::NID::NID_rsaEncryption, rsa.as Pointer(Void)
      new pkey, keyType
    end

    def self.new(dsa : LibCrypto::DSA, keyType = KeyType::All)
      pkey = LibCrypto.evp_pkey_new
      LibCrypto.evp_pkey_assign pkey, OpenSSL::NID::NID_dsa, dsa.as Pointer(Void)
      new pkey, keyType
    end

    def self.new(keyType = KeyType::All)
      new LibCrypto.evp_pkey_new, keyType
    end

    def self.free(pkey : LibCrypto::EVP_PKEY)
      LibCrypto.evp_pkey_free pkey
    end

    def free(pkey : LibCrypto::EVP_PKEY)
      PKey.free pkey
    end

    def free
      PKey.free self
    end

    def pkey=(pkey : LibCrypto::EVP_PKEY)
      @pkey = pkey
    end

    def self.parse_public_key(public_key : String, password = nil, &block)
      _parse = parse_public_key public_key, password
      yield _parse ensure _parse.free
    end

    def self.parse_public_key(public_key : String, password = nil)
      bio = MemBIO.new
      bio.write public_key
      pkey = LibCrypto.pem_read_bio_pubkey bio, nil, nil, password
      new pkey, KeyType::PublicKey
    end

    def self.parse_private_key(private_key : String, password = nil, &block)
      _parse = parse_private_key private_key, password
      yield _parse ensure _parse.free
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
      PKey::RSA.new LibCrypto.evp_pkey_get1_rsa(self), keyType
    end

    def to_dsa
      PKey::DSA.new LibCrypto.evp_pkey_get1_dsa(self), keyType
    end

    def modulus_size
      LibCrypto.evp_pkey_size self
    end

    def to_unsafe
      @pkey
    end
  end
end
