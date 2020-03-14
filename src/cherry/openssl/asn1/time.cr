module OpenSSL::ASN1
  class Time
    def initialize(@time : LibCrypto::ASN1_TIME)
    end

    def self.new(period : Int)
      new LibCrypto.x509_gmtime_adj nil, period
    end

    def self.days_from_now(days : Int)
      new days * 60_i32 * 60_i32 * 24_i32
    end

    def finalize
      LibCrypto.asn1_time_free self
    end

    def to_unsafe
      @time
    end
  end
end
