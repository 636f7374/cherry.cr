class HTTP::Server
  def bind_tcp(host : String, port : Int32, write_timeout : Int32? = nil, read_timeout : Int32? = nil, reuse_port : Bool = false) : Socket::IPAddress
    tcp_server = TCPServer.new host, port, reuse_port: reuse_port
    read_timeout.try { |_read_timeout| tcp_server.client_read_timeout = _read_timeout }
    write_timeout.try { |_write_timeout| tcp_server.client_write_timeout = _write_timeout }

    begin
      bind tcp_server
    rescue exc
      tcp_server.close
      raise exc
    end

    tcp_server.local_address
  end

  def bind_unix(path : String, write_timeout : Int32? = nil, read_timeout : Int32? = nil) : Socket::UNIXAddress
    server = UNIXServer.new path
    read_timeout.try { |_read_timeout| server.client_read_timeout = _read_timeout }
    write_timeout.try { |_write_timeout| server.client_write_timeout = _write_timeout }

    begin
      bind server
    rescue exc
      server.close
      raise exc
    end

    server.local_address
  end

  {% unless flag?(:without_openssl) %}
    def bind_tls(host : String, port : Int32, context : OpenSSL::SSL::SuperContext::Server,
                 write_timeout : Int32? = nil, read_timeout : Int32? = nil, reuse_port : Bool = false) : Socket::IPAddress
      tcp_server = TCPServer.new host, port, reuse_port: reuse_port
      read_timeout.try { |_read_timeout| tcp_server.client_read_timeout = _read_timeout }
      write_timeout.try { |_write_timeout| tcp_server.client_write_timeout = _write_timeout }
      server = OpenSSL::SSL::SuperServer.new tcp_server, context

      begin
        bind server
      rescue exc
        server.close
        raise exc
      end

      tcp_server.local_address
    end

    def bind_tls(host : String, context : OpenSSL::SSL::SuperContext::Server) : Socket::IPAddress
      bind_tls host, 0_i32, context
    end

    def bind_tls(address : Socket::IPAddress, context : OpenSSL::SSL::SuperContext::Server) : Socket::IPAddress
      bind_tls address.address, address.port, context
    end

    def bind_tls(host : String, port : Int32, context : OpenSSL::SSL::Context::Server,
                 write_timeout : Int32? = nil, read_timeout : Int32? = nil, reuse_port : Bool = false) : Socket::IPAddress
      tcp_server = TCPServer.new host, port, reuse_port: reuse_port
      read_timeout.try { |_read_timeout| tcp_server.client_read_timeout = _read_timeout }
      write_timeout.try { |_write_timeout| tcp_server.client_write_timeout = _write_timeout }
      server = OpenSSL::SSL::Server.new tcp_server, context

      begin
        bind server
      rescue exc
        server.close
        raise exc
      end

      tcp_server.local_address
    end
  {% end %}

  def bind(uri : URI) : Socket::Address
    case uri.scheme
    when "tcp"
      bind_tcp Socket::IPAddress.parse(uri)
    when "unix"
      bind_unix Socket::UNIXAddress.parse(uri)
    when "tls", "ssl"
      address = Socket::IPAddress.parse(uri)
      {% unless flag?(:without_openssl) %}
        context = OpenSSL::SSL::SuperContext::Server.from_hash HTTP::Params.parse(uri.query || "")

        bind_tls address, context
      {% else %}
        raise ArgumentError.new "Unsupported socket type: #{uri.scheme} (program was compiled without openssl support)"
      {% end %}
    else
      raise ArgumentError.new "Unsupported socket type: #{uri.scheme}"
    end
  end

  private def accept(server : Socket::Server)
    begin
      accept! server
    rescue ex
      handle_exception ex
    end
  end

  private def accept!(server : Socket::Server)
    while socket = server.accept?
      socket.try do |client|
        _client = client
        spawn same_thread: true do
          handle_client server, _client
        end
      end
    end
  end

  private def set_socket_timeout(server : Socket::Server, socket : IO?)
    if socket.responds_to? :read_timeout=
      socket.read_timeout = server.client_read_timeout
    end

    if socket.responds_to? :write_timeout=
      socket.write_timeout = server.client_write_timeout
    end
  end

  def listen
    raise "Can't re-start closed server" if closed?
    raise "Can't start server with no sockets to listen to, use HTTP::Server#bind first" if @sockets.empty?
    raise "Can't start running server" if listening?

    @listening = true
    done = Channel(Nil).new

    @sockets.each do |socket|
      spawn same_thread: true do
        until closed?
          accept socket
        end
      ensure
        done.send nil
      end
    end

    @sockets.size.times { done.receive }
  end

  private def handle_client(server, client : IO)
    set_socket_timeout server, client

    if client.is_a? IO::Buffered
      client.sync = false
    end

    if client.responds_to? :skip_free=
      client.skip_free = true
    end

    exception = nil

    begin
      @processor.process client, client
    rescue ex
      exception = ex
    end

    if client.is_a? OpenSSL::SSL::SuperSocket::Server
      client.free
    end

    handle_exception exception if exception
  end
end
