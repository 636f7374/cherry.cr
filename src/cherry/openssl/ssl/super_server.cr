class OpenSSL::SSL::SuperServer
  include ::Socket::Server

  # Returns the wrapped server socket.
  getter wrapped : ::Socket::Server

  # Returns the SSL context.
  getter context : OpenSSL::SSL::SuperContext::Server

  # If `#sync_close?` is `true`, closing this server will
  # close the wrapped server.
  property? sync_close : Bool

  # Returns `true` if this SSL server has been closed.
  getter? closed : Bool = false

  # Creates a new SSL server wrapping *wrapped*.
  #
  # *context* configures the SSL options, see `OpenSSL::SSL::SuperContext::Server` for details
  def initialize(@wrapped : ::Socket::Server, @context : OpenSSL::SSL::SuperContext::Server = OpenSSL::SSL::SuperContext::Server.new, @sync_close : Bool = true)
  end

  # Creates a new SSL server wrapping *wrapped*  and yields it to the block.
  #
  # *context* configures the SSL options, see `OpenSSL::SSL::SuperContext::Server` for details
  #
  # The server is closed after the block returns.
  def self.open(wrapped : ::Socket::Server, context : OpenSSL::SSL::SuperContext::Server = OpenSSL::SSL::SuperContext::Server.new, sync_close : Bool = true)
    server = new wrapped, context, sync_close

    begin
      yield server
    ensure
      server.close
    end
  end

  # Implements `::Socket::Server#accept`.
  #
  # This method calls `@wrapped.accept` and wraps the resulting IO in a SSL socket (`OpenSSL::SSL::Socket::Server`) with `context` configuration.
  def accept : OpenSSL::SSL::SuperSocket::Server
    begin
      OpenSSL::SSL::SuperSocket::Server.new @wrapped.accept, @context, sync_context_free: false
    rescue ex
      socket.close ensure raise ex
    end
  end

  # Implements `::Socket::Server#accept?`.
  #
  # This method calls `@wrapped.accept?` and wraps the resulting IO in a SSL socket (`OpenSSL::SSL::Socket::Server`) with `context` configuration.
  def accept? : OpenSSL::SSL::SuperSocket::Server?
    if socket = @wrapped.accept?
      begin
        OpenSSL::SSL::SuperSocket::Server.new socket, @context, sync_context_free: false
      rescue ex
        socket.close ensure raise ex
      end
    end
  end

  def client_read_timeout
    wrapped.client_read_timeout
  end

  def client_write_timeout
    wrapped.client_write_timeout
  end

  # Closes this SSL server.
  #
  # Propagates to `wrapped` if `sync_close` is `true`.
  def close
    return if @closed
    @closed = true

    @wrapped.close if @sync_close
  end

  # Returns local address of `wrapped`.
  def local_address : ::Socket::Address
    @wrapped.local_address
  end
end
