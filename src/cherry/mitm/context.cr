module MITM
  class Context
    alias ExtKeyUsage = OpenSSL::X509::SuperCertificate::ExtKeyUsage
    alias KeyUsage = OpenSSL::X509::SuperCertificate::KeyUsage

    getter rootCertificate : OpenSSL::X509::SuperCertificate
    getter rootPrivateKey : OpenSSL::PKey

    protected def initialize(@rootCertificate, @rootPrivateKey)
    end

    def self.from_string(rootCertificate : String, rootPrivateKey : String, &block)
      yield from_string rootCertificate, rootPrivateKey
    end

    def self.from_path(rootCertificate : String, rootPrivateKey : String, &block)
      yield from_path rootCertificate, rootPrivateKey
    end

    def self.from_string(rootCertificate : String, rootPrivateKey : String)
      new OpenSSL::X509::SuperCertificate.parse(rootCertificate),
        OpenSSL::PKey.parse_private_key(rootPrivateKey)
    end

    def self.from_path(rootCertificate : String, rootPrivateKey : String)
      new OpenSSL::X509::SuperCertificate.parse(File.read rootCertificate),
        OpenSSL::PKey.parse_private_key(File.read rootPrivateKey)
    end

    def create_client(verify_mode = OpenSSL::SSL::VerifyMode::NONE, &block)
      yield create_client verify_mode
    end

    def create_client(verify_mode = OpenSSL::SSL::VerifyMode::NONE)
      client = OpenSSL::SSL::SuperContext::Client.new
      client.verify_mode = verify_mode
      client
    end

    def create_server(request : HTTP::Request, &block)
      yield create_server request
    end

    def create_server(request : HTTP::Request)
      create_certificate_key request do |certificate, private_key|
        server = OpenSSL::SSL::SuperContext::Server.new
        server.ca_certificate_text = certificate
        server.private_key_text = private_key
        server
      end
    end

    def create_all(request : HTTP::Request, verify_mode = OpenSSL::SSL::VerifyMode::NONE, &block)
      create_server request do |server|
        create_client verify_mode do |client|
          yield client, server
        end
      end
    end

    def create_certificate_key(request : HTTP::Request, &block)
      request.host.try do |host|
        create_certificate_key host do |certificate, private_key|
          yield certificate, private_key
        end
      end
    end

    def create_certificate_key(hostname : String, &block)
      OpenSSL::PKey::RSA.new 2048_i32 do |rsa|
        OpenSSL::X509::SuperCertificate.new do |certificate|
          issuer_name = rootCertificate.subject_name
          x509_name = OpenSSL::X509::SuperName.new
          x509_name.add_entry "C", "FI"
          x509_name.add_entry "ST", " "
          x509_name.add_entry "L", "Helsinki"
          x509_name.add_entry "O", " "
          x509_name.add_entry "OU", " "
          x509_name.add_entry "CN", hostname
          certificate.version = 2_i32
          certificate.serial = certificate.random_serial
          certificate.not_before = -1_i64
          certificate.not_after = 365_i64
          certificate.public_key = rsa.pkey
          certificate.subject_name = x509_name
          certificate.issuer_name = issuer_name
          extension = OpenSSL::X509::ExtensionFactory.new rootCertificate
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
          certificate.sign rootPrivateKey.pkey

          begin
            yield certificate, rsa.pkey
          ensure
            issuer_name.free ensure x509_name.free
          end
        end
      end
    end
  end
end
