module OpenSSL::X509
  class SuperName
    def initialize(name : LibCrypto::X509_NAME)
      @name = LibCrypto.x509_name_dup name
    end

    def self.new
      new LibCrypto.x509_name_new
    end

    def self.parse(value : String)
      name = new

      value.split('/').each do |entry|
        oid, value = entry.split '='
        name.add_entry oid, value
      end

      name
    end

    def self.free(name : LibCrypto::X509_NAME | SuperName)
      LibCrypto.x509_name_free name
    end

    def free(name : LibCrypto::X509_NAME | SuperName)
      SuperName.free name
    end

    def free
      SuperName.free self
    end

    def add_entry(oid : String, value : String)
      type = LibCrypto::MBSTRING_UTF8
      ret = LibCrypto.x509_name_add_entry_by_txt self, oid, type, value, value.bytesize, -1_i32, 0_i32

      raise OpenSSL::Error.new "X509_NAME_add_entry_by_txt" if ret.null?
    end

    def to_a
      count = LibCrypto.name_entry_count self
      raise OpenSSL::Error.new "X509_NAME_entry_count" if count < 0_i32

      long_name = Bytes.new 512_i32

      Array(Tuple(String, String)).new count do |i|
        entry = LibCrypto.name_get_entry self, i
        raise OpenSSL::Error.new "X509_NAME_get_entry" if entry.null?

        obj = LibCrypto.name_entry_get_object entry
        LibCrypto.i2t_asn1_object long_name, long_name.size, obj

        nid = LibCrypto.obj_ln2nid long_name
        if nid == LibCrypto::NID_undef
          oid = String.new long_name
        else
          short_name = LibCrypto.obj_nid2sn nid
          oid = String.new short_name
        end

        asn1 = LibCrypto.name_entry_get_data entry
        str = LibCrypto.asn1_string_data asn1
        str_len = LibCrypto.asn1_string_length asn1

        {oid, String.new(str, str_len)}
      end
    end

    def to_unsafe
      @name
    end
  end
end
