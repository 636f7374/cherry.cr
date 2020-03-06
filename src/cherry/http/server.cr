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

  private def accept(server : Socket::Server)
    begin
      accept! server
    rescue ex
      handle_exception ex
    end
  end

  private def accept!(server : Socket::Server)
    socket = server.accept?

    spawn do
      next unless client = socket

      handle_client server, client
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
      spawn do
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
    client.sync = false if client.is_a? IO::Buffered

    begin
      @processor.process client, client
    rescue ex
      exception = ex
    end

    handle_exception exception if exception
  end
end
