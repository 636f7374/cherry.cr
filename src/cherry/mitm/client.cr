module MITM
  class Client
    def self.open(io : TCPSocket, context : MITM::Context, hostname : String? = nil, &block)
      context.create_client do |client_context|
        open io: io, context: client_context, hostname: hostname do |_socket|
          return yield _socket
        end

        client_context.free
      end
    end

    def self.open!(io : TCPSocket, context : MITM::Context, hostname : String? = nil, &block)
      context.create_client do |client_context|
        begin
          open io: io, context: client_context, hostname: hostname do |_socket|
            return yield _socket
          end
        rescue ex
          client_context.free
          raise ex
        end

        client_context.free
      end
    end

    def self.open(io : TCPSocket, context : OpenSSL::SSL::SuperContext::Client, hostname : String? = nil, &block)
      OpenSSL::SSL::SuperSocket::Client.open io: io, context: context, hostname: hostname do |_socket|
        return yield _socket
      end

      yield nil
    end

    def self.open!(io : TCPSocket, context : OpenSSL::SSL::SuperContext::Client, hostname : String? = nil, &block)
      OpenSSL::SSL::SuperSocket::Client.open! io: io, context: context, hostname: hostname do |_socket|
        yield _socket
      end
    end
  end
end
