module MITM
  class Server
    def self.upgrade(socket, request, context : MITM::Context)
      return socket unless server_context = context.create_server request

      upgrade = OpenSSL::SSL::SuperSocket::Server.new io: socket,
        context: server_context, sync_context_free: false rescue nil

      server_context.free unless upgrade
      upgrade.sync = true if upgrade

      upgrade || socket
    end
  end
end
