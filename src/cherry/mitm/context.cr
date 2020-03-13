module MITM
  class Context
    alias ExtKeyUsage = OpenSSL::X509::SuperCertificate::ExtKeyUsage
    alias KeyUsage = OpenSSL::X509::SuperCertificate::KeyUsage

    getter rootCertificate : String
    getter rootPrivateKey : String
    property cache : Cache
    property country : String
    property location : String
    property notBefore : Int64
    property notAfter : Int64
    property hostName : String

    def initialize(@rootCertificate, @rootPrivateKey)
      @cache = Cache.new
      @country = "FI"
      @location = "Helsinki"
      @notBefore = -1_i64
      @notAfter = 365_i64
      @hostName = String.new
    end

    def self.new(&block : Context ->)
      yield new
    end

    def self.from_path(rootCertificate : String, rootPrivateKey : String, &block : Context ->)
      yield from_path rootCertificate, rootPrivateKey
    end

    def self.from_path(rootCertificate : String, rootPrivateKey : String)
      new File.read(rootCertificate), File.read(rootPrivateKey)
    end

    def self.create_client(verify_mode = OpenSSL::SSL::VerifyMode::NONE, &block : Context ->)
      yield create_client verify_mode
    end

    def self.create_client(verify_mode = OpenSSL::SSL::VerifyMode::NONE)
      client = OpenSSL::SSL::SuperContext::Client.new
      client.verify_mode = verify_mode
      client
    end

    def create_server(request : HTTP::Request, &block : Context ->)
      yield create_server request
    end

    def create_server(request : HTTP::Request)
      create_server request
    end

    def create_all(request : HTTP::Request, verify_mode = OpenSSL::SSL::VerifyMode::NONE, &block : Context ->)
      return unless server = create_server request
      return unless client = Context.create_client verify_mode

      yield client, server
    end

    def create_server(request : HTTP::Request)
      return unless host = request.host

      create_server host
    end

    def create_context_from_cache(value : Tuple(String, String))
      certificate, private_key = value

      _certificate = OpenSSL::X509::SuperCertificate.parse certificate
      _private_key = OpenSSL::PKey.parse_private_key private_key

      server = OpenSSL::SSL::SuperContext::Server.new
      server.ca_certificate_text = _certificate
      server.private_key_text = _private_key

      _certificate.free ensure _private_key.free

      server
    end

    def create_server(hostname : String = self.hostName)
      _cache = cache.get hostname
      return create_context_from_cache _cache if _cache

      root_certificate = OpenSSL::X509::SuperCertificate.parse rootCertificate
      root_private_key = OpenSSL::PKey.parse_private_key rootPrivateKey
      rsa = OpenSSL::PKey::RSA.new 2048_i32
      certificate = OpenSSL::X509::SuperCertificate.new

      issuer_name = root_certificate.subject_name
      x509_name = OpenSSL::X509::SuperName.new
      x509_name.add_entry "C", country
      x509_name.add_entry "ST", " "
      x509_name.add_entry "L", location
      x509_name.add_entry "O", " "
      x509_name.add_entry "OU", " "
      x509_name.add_entry "CN", hostname
      certificate.version = 2_i32
      certificate.serial = certificate.random_serial
      certificate.not_before = notBefore
      certificate.not_after = notAfter
      certificate.public_key = rsa.pkey
      certificate.subject_name = x509_name
      certificate.issuer_name = issuer_name
      extension = OpenSSL::X509::ExtensionFactory.new root_certificate

      certificate.extensions = [
        extension.create(OpenSSL::NID::NID_basic_constraints, "CA:FALSE", true),
        extension.create(OpenSSL::NID::NID_subject_key_identifier, "hash", false),
        extension.create(OpenSSL::NID::NID_authority_key_identifier,
          "keyid:always,issuer:always"
        ),
        extension.create_subject_alt_name(hostname),
        extension.create_ext_usage(ExtKeyUsage::ServerAuth),
        extension.create_usage([
          KeyUsage::NonRepudiation, KeyUsage::DigitalSignature,
          KeyUsage::KeyEncipherment, KeyUsage::DataEncipherment,
        ]),
      ]

      certificate.sign root_private_key
      issuer_name.free ensure x509_name.free
      root_certificate.free ensure root_private_key.free

      server = OpenSSL::SSL::SuperContext::Server.new
      server.ca_certificate_text = certificate
      server.private_key_text = rsa.pkey

      cache.set hostname, Tuple.new certificate.to_s, rsa.to_s OpenSSL::PKey::KeyType::PrivateKey
      certificate.free ensure rsa.pkey_free

      server
    end
  end
end
