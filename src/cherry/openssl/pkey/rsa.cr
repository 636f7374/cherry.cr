module OpenSSL
  class PKey::RSA < PKey
    def initialize(@rsa : LibCrypto::RSA, keyType = KeyType::All)
      super keyType

      LibCrypto.evp_pkey_assign @pkey, OpenSSL::NID::NID_rsaEncryption, @rsa.as Pointer(Void)
    end

    def self.new(size : Int = 4096_i32)
      generate size
    end

    def self.generate(size : Int = 4096_i32, exponent = 65537_u32)
      new LibCrypto.rsa_generate_key(size, exponent, nil, nil), KeyType::All
    end

    def free
      RSA.free self
    end

    def self.free(rsa : RSA | LibCrypto::RSA)
      LibCrypto.rsa_free rsa
    end

    def pkey_free
      RSA.pkey_free pkey
    end

    def self.free(pkey : PKey | LibCrypto::EVP_PKEY)
      PKey.free pkey
    end

    def self.pkey_free(pkey : PKey | LibCrypto::EVP_PKEY)
      PKey.free pkey
    end

    def pkey_free(pkey : PKey | LibCrypto::EVP_PKEY)
      RSA.pkey_free pkey
    end

    def self.parse_public_key(public_key : String, password = nil)
      bio = MemBIO.new
      bio.write public_key
      rsa_key = LibCrypto.pem_read_bio_rsapublickey bio, nil, nil, password

      new rsa_key, KeyType::PublicKey
    end

    def self.parse_private_key(private_key : String, password = nil)
      bio = MemBIO.new
      bio.write private_key
      rsa_key = LibCrypto.pem_read_bio_rsaprivatekey bio, nil, nil, password

      new rsa_key, KeyType::PrivateKey
    end

    def to_io(io : IO, keyType : KeyType, cipher = nil, password = nil)
      bio = MemBIO.new

      case keyType
      when .private_key?
        LibCrypto.pem_write_bio_rsaprivatekey bio, self, cipher, nil, 0_i32, nil, password
      when .public_key?
        LibCrypto.pem_write_bio_rsa_pubkey bio, self
      end

      bio.to_io io

      io
    end

    def to_io(io : IO, cipher = nil, password = nil)
      to_io io, keyType, cipher, password
    end

    def to_s(keyType : KeyType, cipher = nil, password = nil)
      io = IO::Memory.new
      to_io io, keyType, cipher, password
      String.new io.to_slice
    end

    def to_s(cipher = nil, password = nil)
      to_s keyType, cipher, password
    end

    def modulus_size
      LibCrypto.rsa_size self
    end

    def private_key
      return unless keyType.all?

      private_key!
    end

    def private_key!
      private_rsa = LibCrypto.rsaprivateKey_dup self
      raise OpenSSL::Error.new "RSAPrivateKey_dup" unless private_rsa

      new private_rsa, KeyType::PrivateKey
    end

    def public_key
      return unless keyType.all?

      public_key!
    end

    def public_key!
      public_rsa = LibCrypto.rsapublickey_dup self
      raise OpenSSL::Error.new "RSAPublicKey_dup" unless public_rsa

      new public_rsa, KeyType::PublicKey
    end

    def to_unsafe
      @rsa
    end
  end
end
