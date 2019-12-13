require "./pkey.cr"

module OpenSSL
  struct PKey::DSA
    def initialize(@dsa : LibCrypto::DSA, @keyType = KeyType::PublicKey)
      @pkey = LibCrypto.evp_pkey_new
      LibCrypto.evp_pkey_assign @pkey, OpenSSL::NID::NID_dsa, @dsa.as Pointer(Void)
    end

    def self.new(size : Int = 4096_i32, &block)
      dsa = new size
      yield dsa ensure dsa.pkey_free
    end

    def self.new(size : Int = 4096_i32)
      generate size
    end

    def self.generate(size : Int = 4096_i32)
      seed = uninitialized UInt8[20_i32]
      raise OpenSSL::Error.new if LibCrypto.rand_bytes(seed.to_slice, 20_i32) == 0_i32
      dsa_key = LibCrypto.dsa_generate_parameters size, seed
        .to_slice, 20_i32, out counter, out h, nil, nil
      raise OpenSSL::Error.new unless dsa_key
      if LibCrypto.dsa_generate_key(dsa_key) == 0_i32
        LibCrypto.dsa_free dsa_key ensure raise OpenSSL::Error.new
      end
      new dsa_key, KeyType::All
    end

    def pkey
      @pkey
    end

    def self.dsa_free(dsa : LibCrypto::DSA)
      LibCrypto.dsa_free dsa
    end

    def dsa_free(dsa : LibCrypto::DSA)
      DSA.dsa_free dsa
    end

    def free
      DSA.pkey_free pkey
    end

    def self.pkey_free(pkey : LibCrypto::EVP_PKEY)
      OpenSSL::PKey.free pkey
    end

    def pkey_free(pkey : LibCrypto::EVP_PKEY)
      DSA.pkey_free pkey
    end

    def pkey_free
      DSA.pkey_free pkey
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
      when KeyType::PrivateKey
        LibCrypto.pem_write_bio_dsaprivatekey bio, self, cipher, nil, 0_i32, nil, password
      when KeyType::PublicKey
        LibCrypto.pem_write_bio_dsa_pubkey bio, self
      end

      bio.to_io io
    end

    def to_io(io : IO, cipher = nil, password = nil)
      to_io io, keyType, cipher, password
    end

    def to_s(keyType : KeyType, cipher = nil, password = nil)
      io = IO::Memory.new

      begin
        to_io io, keyType, cipher, password
      rescue ex
        io.close ensure raise ex
      end

      io.to_s ensure io.close
    end

    def to_s(cipher = nil, password = nil)
      to_s keyType, cipher, password
    end

    def modulus_size
      LibCrypto.dsa_size self
    end

    def private_key
      return unless keyType == KeyType::All
      private_key!
    end

    def private_key!
      private_key = to_s KeyType::PrivateKey
      parse_private_key private_key
    end

    def public_key
      return unless keyType == KeyType::All
      public_key!
    end

    def public_key!
      public_key = to_s KeyType::PublicKey
      parse_public_key public_key
    end

    def to_unsafe
      @dsa
    end
  end
end
