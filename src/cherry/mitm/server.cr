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

    def self.extract(socket : TCPSocket, sync_close : Bool = true)
      part = Extract.part socket
      stream = Extract.new socket, part

      Tuple.new part.dup, IO::Stapled.new stream, socket, sync_close
    end

    def self.extract(socket : TCPSocket, sync_close : Bool = true, &block)
      Extract.part socket do |part|
        Extract.new socket, part do |stream|
          yield part.dup, IO::Stapled.new stream, socket, sync_close
        end
      end
    end
  end
end
