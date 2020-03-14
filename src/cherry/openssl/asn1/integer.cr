module OpenSSL::ASN1
  class Integer
    def initialize(@integer : LibCrypto::ASN1_INTEGER)
    end

    def self.new
      new LibCrypto.asn1_integer_new
    end

    def finalize
      LibCrypto.asn1_integer_free self
    end

    def to_unsafe
      @integer
    end
  end
end
