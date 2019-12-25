class OpenSSL::SSL::SuperServer
  include ::Socket::Server

  # Returns the wrapped server socket.
  getter wrapped : ::Socket::Server

  getter certificate : String
  getter privateKey : String

  # If `#sync_close?` is `true`, closing this server will
  # close the wrapped server.
  property? sync_close : Bool

  # Returns `true` if this SSL server has been closed.
  getter? closed : Bool = false

  # Creates a new SSL server wrapping *wrapped*.
  def initialize(@wrapped : ::Socket::Server, @certificate : String, @privateKey : String, @sync_close : Bool = true)
  end

  # Implements `::Socket::Server#accept`.
  #
  # This method calls `@wrapped.accept` and wraps the resulting IO in a SSL socket (`OpenSSL::SSL::Socket::Server`) with `context` configuration.
  def accept : OpenSSL::SSL::SuperSocket::Server
    context = OpenSSL::SSL::SuperContext::Server.new
    context.ca_certificate_text = certificate
    context.private_key_text = privateKey

    begin
      OpenSSL::SSL::SuperSocket::Server.new @wrapped.accept, context, sync_context_free: true
    rescue ex
      context.free
      raise ex
    end
  end

  # Implements `::Socket::Server#accept?`.
  #
  # This method calls `@wrapped.accept?` and wraps the resulting IO in a SSL socket (`OpenSSL::SSL::Socket::Server`) with `context` configuration.
  def accept? : OpenSSL::SSL::SuperSocket::Server?
    if socket = @wrapped.accept?
      context = OpenSSL::SSL::SuperContext::Server.new
      context.ca_certificate_text = certificate
      context.private_key_text = privateKey

      begin
        OpenSSL::SSL::SuperSocket::Server.new socket, context, sync_context_free: true
      rescue ex
        socket.close
        raise ex
      end
    end
  end

  def client_read_timeout
    wrapped.client_read_timeout
  end

  def client_write_timeout
    wrapped.client_write_timeout
  end

  def closed?
    @closed
  end

  # Closes this SSL server.
  #
  # Propagates to `wrapped` if `sync_close` is `true`.
  def close
    return if closed?
    @closed = true

    @wrapped.close if @sync_close
  end

  # Returns local address of `wrapped`.
  def local_address : ::Socket::Address
    @wrapped.local_address
  end
end
