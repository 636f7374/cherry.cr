module MITM
  class Client
    def self.upgrade(io : IO, hostname : String? = nil, verify_mode : OpenSSL::SSL::VerifyMode = OpenSSL::SSL::VerifyMode::NONE)
      return io unless client_context = Context.create_client

      upgrade = OpenSSL::SSL::Socket::Client.new io: io, context: client_context,
        sync_close: true, hostname: hostname rescue nil

      upgrade || io
    end
  end
end
