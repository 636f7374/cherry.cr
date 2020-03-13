module OpenSSL::X509
  class SuperCertificate
    enum KeyUsage
      DigitalSignature
      NonRepudiation
      KeyEncipherment
      DataEncipherment
      KeyAgreement
      KeyCertSign
      CRLSign
      EncipherOnly
      DecipherOnly
    end

    enum ExtKeyUsage
      ServerAuth
      ClientAuth
      CodeSigning
      EmailProtection
      TimeStamping
      MsCodeInd
      MsCodeCom
      MsCtlSign
      MsSgc
      MsEfs
      NsSgc
    end

    def initialize(@cert : LibCrypto::X509)
    end

    def self.new(cert : LibCrypto::X509, &block : SuperCertificate ->)
      yield new cert
    end

    def self.new
      generate
    end

    def self.generate
      new LibCrypto.x509_new
    end

    def self.parse(certificate : String)
      bio = MemBIO.new
      bio.write certificate

      x509 = LibCrypto.pem_read_bio_x509 bio, nil, nil, nil

      new x509
    end

    def public_key
      OpenSSL::PKey.new LibCrypto.x509_get_pubkey(self),
        OpenSSL::PKey::KeyType::PublicKey
    end

    def pkey
      @pkey
    end

    def pkey!
      @pkey.not_nil!
    end

    def self.free(cert : LibCrypto::X509 | SuperCertificate)
      LibCrypto.x509_free cert
    end

    def free(cert : LibCrypto::X509 | SuperCertificate)
      SuperCertificate.free cert
    end

    def free
      SuperCertificate.free self
    end

    def self.pkey_free(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY)
      OpenSSL::PKey.free pkey
    end

    def pkey_free(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY)
      SuperCertificate.pkey_free pkey
    end

    def pkey_free
      pkey.try { |_pkey| SuperCertificate.pkey_free _pkey }
    end

    def self.name_free(name : LibCrypto::X509_NAME)
      LibCrypto.x509_name_free name
    end

    def name_free(name : LibCrypto::X509_NAME)
      SuperCertificate.name_free name
    end

    def self.extension_free(extension : LibCrypto::X509_EXTENSION)
      LibCrypto.x509_extension_free extension
    end

    def extension_free(extension : LibCrypto::X509_EXTENSION)
      SuperCertificate.extension_free extension
    end

    def serial
      ret = LibCrypto.x509_get_serialnumber self
      raise Error.new "X509_get_serialNumber" if ret == 0_i32

      ASN1::Integer.new ret
    end

    def not_before
      before = LibCrypto.x509_get0_notbefore self
      raise Error.new "X509_get0_notBefore" if before.null?

      ASN1::Time.new before
    end

    def not_after
      after = LibCrypto.x509_get0_notafter self
      raise Error.new "X509_get0_notAfter" if after.null?

      ASN1::Time.new after
    end

    def issuer_name
      issuer = LibCrypto.x509_get_issuer_name self
      raise Error.new "X509_get_issuer_name" if issuer.null?

      SuperName.new issuer
    end

    def subject_name
      subject = LibCrypto.x509_get_subject_name self
      raise Error.new "X509_get_subject_name" if subject.null?

      SuperName.new subject
    end

    def extension_count
      ret = LibCrypto.x509_get_ext_count self
      raise Error.new "X509_get_ext_count" if ret == 0_i32

      ret
    end

    def extensions
      count = LibCrypto.x509_get_ext_count self

      Array(Extension).new count do |item|
        ext = LibCrypto.x509_get_ext self, item

        Extension.new ext
      end
    end

    def extensions=(list : Array(LibCrypto::X509_EXTENSION))
      list.each do |item|
        unless 0_i32 == LibCrypto.x509_add_ext self, item, -1_i32
          next extension_free item
        end

        extension_free item
        raise OpenSSL::Error.new "X509_add_ext"
      end
    end

    def extension=(item = LibCrypto::X509_EXTENSION)
      self.extensions = [item]
    end

    def add_extension_item(nid, value, critical = false)
      self.extension = ExtensionFactory.create self, nid, value, critical
    end

    def verify(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY)
      ret = LibCrypto.x509_verify self, pkey
      raise Error.new "X509_verify" if ret < 0_i32

      true
    end

    def sign(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY, algorithm = LibCrypto.evp_sha256)
      raise OpenSSL::Error.new "X509_sign" if 0_i32 == LibCrypto.x509_sign self, pkey, algorithm
    end

    def to_io(io : IO)
      bio = OpenSSL::MemBIO.new
      LibCrypto.pem_write_bio_x509 bio, self
      bio.to_io io

      io
    end

    def to_s
      io = IO::Memory.new
      to_io io
      String.new io.to_slice
    end

    def subject_name=(subject : String)
      name = SuperName.parse subject
      self.subject_name = name
      name.free

      subject
    end

    def subject_name=(name : SuperName)
      ret = LibCrypto.x509_set_subject_name self, name
      raise Error.new "X509_set_subject_name" if ret == 0_i32

      name
    end

    def issuer_name=(issuer : String)
      name = SuperName.parse issuer
      self.issuer_name = name

      issuer
    end

    def issuer_name=(name : SuperName)
      ret = LibCrypto.x509_set_issuer_name self, name
      raise Error.new "X509_set_issuer_name" if ret == 0_i32

      name
    end

    def pkey=(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY)
      @pkey = pkey
    end

    def public_key=(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY)
      ret = LibCrypto.x509_set_pubkey self, pkey
      raise Error.new "X509_set_pubkey" if ret == 0_i32

      @pkey = pkey
    end

    def version=(version = 2_i64)
      ret = LibCrypto.x509_set_version self, version
      raise Error.new "X509_set_version" if ret == 0_i32

      version
    end

    def serial=(number : Int)
      asn1 = ASN1::Integer.new
      LibCrypto.asn1_integer_set asn1, number
      ret = LibCrypto.x509_set_serialnumber self, asn1
      raise Error.new "X509_set_serialNumber" if ret == 0_i32

      asn1.free
      number
    end

    def not_before=(valid_period : Int = 0_i64)
      asn1 = ASN1::Time.days_from_now valid_period

      {% if compare_versions(LibSSL::OPENSSL_VERSION, "1.0.2") >= 0_i32 %}
        ret = LibCrypto.x509_set1_notbefore self, asn1
      {% else %}
        ret = LibCrypto.x509_set_notbefore self, asn1
      {% end %}

      {% if compare_versions(LibSSL::OPENSSL_VERSION, "1.0.2") >= 0_i32 %}
        raise Error.new "X509_set1_notBefore" if ret == 0_i32
      {% else %}
        raise Error.new "X509_set_notBefore" if ret == 0_i32
      {% end %}

      asn1.free
      valid_period
    end

    def not_after=(valid_period : Int = 365_i64) : Int
      asn1 = ASN1::Time.days_from_now valid_period

      {% if compare_versions(LibSSL::OPENSSL_VERSION, "1.0.2") >= 0_i32 %}
        ret = LibCrypto.x509_set1_notafter self, asn1
      {% else %}
        ret = LibCrypto.x509_set_notafter self, asn1
      {% end %}

      {% if compare_versions(LibSSL::OPENSSL_VERSION, "1.0.2") >= 0_i32 %}
        raise Error.new "X509_set1_notAfter" if ret == 0_i32
      {% else %}
        raise Error.new "X509_set_notAfter" if ret == 0_i32
      {% end %}

      asn1.free
      valid_period
    end

    def random_serial
      Random.rand Int32::MAX
    end

    def to_unsafe
      @cert
    end
  end
end
