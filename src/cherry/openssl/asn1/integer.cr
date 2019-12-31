module OpenSSL::ASN1
  class Integer
    def initialize(@integer : LibCrypto::ASN1_INTEGER)
    end

    def self.new
      new LibCrypto.asn1_integer_new
    end

    def self.free(integer : LibCrypto::ASN1_INTEGER | Integer)
      LibCrypto.asn1_integer_free integer
    end

    def free(integer : LibCrypto::ASN1_INTEGER | Integer)
      Integer.free integer
    end

    def free
      Integer.free self
    end

    def to_unsafe
      @integer
    end
  end
end
