module MITM
  class Client
    def self.upgrade(io : TCPSocket, context : MITM::Context, hostname : String? = nil)
      return io unless client_context = context.create_client

      upgrade = OpenSSL::SSL::SuperSocket::Client.upgrade io: io,
        context: client_context, sync_context_free: false, hostname: hostname

      upgrade.sync = true if upgrade
      client_context.free unless upgrade

      upgrade || io
    end
  end
end
