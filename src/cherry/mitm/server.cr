module MITM
  class Server
    def self.open(socket, request, context : MITM::Context, &block)
      context.create_server request do |server_context|
        open socket: socket, context: server_context do |_socket|
          return yield _socket
        end

        server_context.free
      end
    end

    def self.open!(socket, request, context : MITM::Context, &block)
      context.create_server request do |server_context|
        begin
          open socket: socket, context: server_context do |_socket|
            return yield _socket
          end
        rescue ex
          server_context.free
          raise ex
        end

        server_context.free
      end
    end

    def self.open(socket, context : OpenSSL::SSL::SuperContext::Server, &block)
      OpenSSL::SSL::SuperSocket::Server.open io: socket, context: context do |_socket|
        return yield _socket
      end

      yield nil
    end

    def self.open!(socket, context : OpenSSL::SSL::SuperContext::Server, &block)
      OpenSSL::SSL::SuperSocket::Server.open! io: socket, context: context do |_socket|
        yield _socket
      end
    end

    def self.extract(socket : TCPSocket, sync_close : Bool = true)
      Extract.part socket do |part|
        Extract.new socket, part do |stream|
          yield part.dup, IO::Stapled.new stream, socket, sync_close
        end
      end
    end
  end
end
