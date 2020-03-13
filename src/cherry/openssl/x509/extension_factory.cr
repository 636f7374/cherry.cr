module OpenSSL::X509
  class ExtensionFactory
    def initialize(@issuerCertificate : SuperCertificate, @subjectCertificate : SuperCertificate)
    end

    def self.new(certificate : SuperCertificate)
      new certificate, certificate
    end

    def issuer_certificate=(certificate : SuperCertificate)
      @issuerCertificate = certificate
    end

    def subject_certificate=(certificate : SuperCertificate)
      @subjectCertificate = certificate
    end

    def alt_name_merge(domains : Array(String))
      modified = domains.map { |domain| String.build { |io| io << "DNS:" << domain } }
      modified.join ", "
    end

    def create_subject_alt_name(domains : Array(String))
      create NID::NID_subject_alt_name, alt_name_merge(domains)
    end

    def create_subject_alt_name(domain : String)
      create_subject_alt_name [domain]
    end

    def usage_merge(list : Array(SuperCertificate::KeyUsage | SuperCertificate::ExtKeyUsage))
      modified = list.map { |value| value.to_s.camelcase lower: true }
      modified.join ", "
    end

    def create_ext_usage(list : Array(SuperCertificate::ExtKeyUsage))
      create NID::NID_ext_key_usage, usage_merge(list)
    end

    def create_ext_usage(item : SuperCertificate::ExtKeyUsage)
      create_ext_usage [item]
    end

    def create_usage(list : Array(SuperCertificate::KeyUsage))
      create NID::NID_key_usage, usage_merge(list), true
    end

    def create_usage(item : SuperCertificate::KeyUsage)
      create_usage [item]
    end

    def self.build_value(value, critical : Bool)
      String.build do |io|
        io << "critical, " if critical
        io << value
      end
    end

    def self.create(issuer : SuperCertificate, subject : SuperCertificate, nid : OpenSSL::NID, value, critical = false)
      ctx = LibCrypto::X509V3_CTX.new
      LibCrypto.x509v3_set_ctx pointerof(ctx), issuer, subject, nil, nil, 0_i32
      ret = LibCrypto.x509v3_ext_conf_nid nil, pointerof(ctx), nid, build_value value, critical
      raise Error.new "X509V3_EXT_conf_nid" if ret.null?

      ret
    end

    def self.create(certificate : SuperCertificate, nid : OpenSSL::NID, value, critical = false)
      create certificate, certificate, nid, value, critical
    end

    def create(nid : OpenSSL::NID, value, critical = false)
      ctx = LibCrypto::X509V3_CTX.new
      LibCrypto.x509v3_set_ctx pointerof(ctx), @issuerCertificate, @subjectCertificate, nil, nil, 0_i32
      ret = LibCrypto.x509v3_ext_conf_nid nil, pointerof(ctx), nid, ExtensionFactory.build_value value, critical
      raise Error.new "X509V3_EXT_conf_nid" if ret.null?

      ret
    end

    def self.free(ext : LibCrypto::X509_EXTENSION)
      LibCrypto.x509_extension_free ext
    end
  end
end
