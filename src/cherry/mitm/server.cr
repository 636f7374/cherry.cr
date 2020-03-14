module MITM
  class Server
    def self.upgrade(socket, request, context : MITM::Context)
      return socket unless server_context = context.create_server request

      upgrade = OpenSSL::SSL::Socket::Server.new io: socket,
        context: server_context, sync_close: true rescue nil

      upgrade.sync = true if upgrade

      upgrade || socket
    end
  end
end
