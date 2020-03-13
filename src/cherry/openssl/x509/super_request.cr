module OpenSSL::X509
  class SuperRequest
    def initialize(@req : LibCrypto::X509_REQ)
    end

    def self.new(req : LibCrypto::X509_REQ, &block : SuperRequest ->)
      yield new req
    end

    def self.new
      generate
    end

    def self.generate
      x509_req = LibCrypto.x509_req_new
      raise OpenSSL::Error.new "X509_REQ_new" if x509_req.null?

      new x509_req
    end

    def self.parse(request : String, password = nil)
      bio = MemBIO.new
      bio.write request
      x509_req = LibCrypto.pem_read_bio_x509_req bio, nil, nil, password

      new x509_req
    end

    def subject_name
      subject = LibCrypto.x509_req_get_subject_name self
      raise OpenSSL::Error.new "X509_REQ_get_subject_name" if subject.null?

      SuperName.new subject
    end

    def public_key
      OpenSSL::PKey.new LibCrypto.x509_req_get_pubkey(self),
        OpenSSL::PKey::KeyType::PublicKey
    end

    def pkey
      @pkey
    end

    def pkey!
      @pkey.not_nil!
    end

    def self.free(req : LibCrypto::X509_REQ)
      LibCrypto.x509_req_free req
    end

    def free(req : LibCrypto::X509_REQ)
      LibCrypto.x509_req_free req
    end

    def free
      LibCrypto.x509_req_free self
    end

    def self.pkey_free(pkey : LibCrypto::EVP_PKEY)
      OpenSSL::PKey.free pkey
    end

    def pkey_free(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY)
      OpenSSL::PKey.free pkey
    end

    def pkey_free
      pkey.try { |_pkey| OpenSSL::PKey.free _pkey }
    end

    def self.name_free(name : LibCrypto::X509_NAME)
      LibCrypto.x509_name_free name
    end

    def name_free(name : LibCrypto::X509_NAME)
      LibCrypto.x509_name_free name
    end

    def sign(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY, algorithm = LibCrypto.evp_sha256)
      raise OpenSSL::Error.new "X509_REQ_sign" if 0_i32 == LibCrypto.x509_req_sign self, pkey, algorithm
    end

    def subject_name=(subject : String)
      name = SuperName.parse subject
      self.subject_name = name

      name.free
      subject
    end

    def subject_name=(name : SuperName)
      ret = LibCrypto.x509_req_set_subject_name self, name
      raise OpenSSL::Error.new "X509_set_subject_name" if ret == 0_i32

      name
    end

    def pkey=(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY)
      @pkey = pkey
    end

    def public_key=(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY)
      ret = LibCrypto.x509_req_set_pubkey self, pkey
      raise OpenSSL::Error.new "X509_REQ_set_pubkey" if ret == 0_i32

      @pkey = pkey
    end

    def version=(version = 0_i64)
      ret = LibCrypto.x509_req_set_version self, version
      raise OpenSSL::Error.new "X509_REQ_set_version" if ret == 0_i32

      version
    end

    def to_io(io : IO)
      bio = OpenSSL::MemBIO.new
      LibCrypto.pem_write_bio_x509_req bio, self
      bio.to_io io
    end

    def to_s
      io = IO::Memory.new
      to_io io
      String.new io.to_slice
    end

    def to_unsafe
      @req
    end
  end
end
