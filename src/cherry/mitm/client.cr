module MITM
  class Client
    def self.upgrade(io : IO, hostname : String? = nil, verify_mode : OpenSSL::SSL::VerifyMode = OpenSSL::SSL::VerifyMode::NONE)
      return io unless client_context = Context.create_client

      upgrade = OpenSSL::SSL::SuperSocket::Client.new io: io, context: client_context,
        sync_context_free: false, hostname: hostname rescue nil

      client_context.free unless upgrade

      upgrade || io
    end
  end
end
