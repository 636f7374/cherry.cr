require "./pkey.cr"

module OpenSSL
  class PKey::DSA < PKey
    def initialize(@dsa : LibCrypto::DSA, keyType = KeyType::All)
      super keyType

      LibCrypto.evp_pkey_assign @pkey, OpenSSL::NID::NID_dsa, @dsa.as Pointer(Void)
    end

    def self.new(size : Int = 4096_i32)
      generate size
    end

    def self.generate(size : Int = 4096_i32) : DSA
      seed = uninitialized UInt8[20_i32]
      raise OpenSSL::Error.new if 0_i32 == LibCrypto.rand_bytes seed.to_slice, 20_i32

      dsa_key = LibCrypto.dsa_generate_parameters size, seed
        .to_slice, 20_i32, out counter, out h, nil, nil
      raise OpenSSL::Error.new unless dsa_key

      if 0_i32 == LibCrypto.dsa_generate_key dsa_key
        LibCrypto.dsa_free dsa_key ensure raise OpenSSL::Error.new
      end

      new dsa_key, KeyType::All
    end

    def free
      DSA.free self
    end

    def self.free(dsa : DSA | LibCrypto::DSA)
      LibCrypto.dsa_free dsa
    end

    def pkey_free
      DSA.pkey_free pkey
    end

    def self.pkey_free(pkey : PKey | LibCrypto::EVP_PKEY)
      Pkey.free pkey
    end

    def pkey_free(pkey : LibCrypto::EVP_PKEY)
      PKey.free pkey
    end

    def self.parse_public_key(public_key : String, password = nil)
      pkey = PKey.parse_public_key public_key, password
      pkey.to_dsa
    end

    def self.parse_private_key(private_key : String, password = nil)
      bio = MemBIO.new
      bio.write private_key

      dsa_key = LibCrypto.pem_read_bio_dsaprivatekey bio, nil, nil, password
      raise OpenSSL::Error.new "PEM_write_bio_DSAPrivateKey" if dsa_key.null?

      new dsa_key, KeyType::PrivateKey
    end

    def to_io(io : IO, keyType : KeyType, cipher = nil, password = nil)
      bio = MemBIO.new

      case keyType
      when .private_key?
        LibCrypto.pem_write_bio_dsaprivatekey bio, self, cipher, nil, 0_i32, nil, password
      when .public_key?
        LibCrypto.pem_write_bio_dsa_pubkey bio, self
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
      LibCrypto.dsa_size self
    end

    def private_key
      return unless keyType.all?

      private_key!
    end

    def private_key!
      private_key = to_s KeyType::PrivateKey
      DSA.parse_private_key private_key
    end

    def public_key
      return unless keyType.all?

      public_key!
    end

    def public_key!
      public_key = to_s KeyType::PublicKey
      DSA.parse_public_key public_key
    end

    def to_unsafe
      @dsa
    end
  end
end
