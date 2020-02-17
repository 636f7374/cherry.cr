class HTTP::Client
  {% if flag? :without_openssl %}
    getter! tls : Nil
  {% else %}
    getter! tls : OpenSSL::SSL::SuperContext::Client | OpenSSL::SSL::Context::Client
  {% end %}

  # Whether automatic compression/decompression is enabled.
  property? compress : Bool

  {% if flag? :without_openssl %}
    @socket : TCPSocket?
  {% else %}
    @socket : TCPSocket | OpenSSL::SSL::SuperSocket | OpenSSL::SSL::Socket | Nil
  {% end %}

  {% unless flag? :without_openssl %}
    def initialize(@host : String, port = nil, tls : Bool | OpenSSL::SSL::SuperContext::Client = false)
      check_host_only @host

      @tls = case tls
             when true
               OpenSSL::SSL::SuperContext::Client.new
             when OpenSSL::SSL::SuperContext::Client
               tls
             when false
               nil
             end

      @port = (port || (@tls ? 443_i32 : 80_i32)).to_i
      @compress = true
    end
  {% end %}

  {% unless flag? :without_openssl %}
    protected def self.tls_flag(uri, context : OpenSSL::SSL::SuperContext::Client?)
      scheme = uri.scheme
      case {scheme, context}
      when {nil, _}
        raise ArgumentError.new "Missing scheme: #{uri}"
      when {"http", nil}
        false
      when {"http", OpenSSL::SSL::SuperContext::Client}
        raise ArgumentError.new "TLS context given for HTTP URI"
      when {"https", nil}
        true
      when {"https", OpenSSL::SSL::SuperContext::Client}
        context
      else
        raise ArgumentError.new "Unsupported scheme: #{scheme}"
      end
    end
  {% end %}

  def dns_resolver=(value : Durian::Resolver)
    @dns_resolver = value
  end

  def dns_resolver
    @dns_resolver
  end

  def io_socket
    @socket
  end

  def tls_context
    tls rescue nil
  end

  def close
    @socket.try &.close rescue nil
    tcp_socket.try &.close rescue nil
  end

  def cleanup
    close

    case _socket = @socket
    when OpenSSL::SSL::SuperSocket::Client
      _socket.all_free
    else
      _context = tls_context
      _context.free if _context.is_a? OpenSSL::SSL::SuperContext::Client
    end

    @socket = nil
    @tls = nil
  end

  def create_socket(hostname : String)
    return TCPSocket.new hostname, @port, @dns_timeout, @connect_timeout unless resolver = dns_resolver

    TCPSocket.connect hostname, @port, resolver, @connect_timeout
  end

  def tcp_socket=(value : TCPSocket)
    @tcp_socket = value
  end

  def tcp_socket
    @tcp_socket
  end

  private def socket
    _socket = @socket
    return _socket if _socket

    begin
      hostname = @host.starts_with?('[') && @host.ends_with?(']') ? @host[1_i32..-2_i32] : @host

      socket = create_socket hostname
      socket.read_timeout = @read_timeout if @read_timeout
      socket.sync = false
      @socket = socket
      self.tcp_socket = socket

      {% unless flag? :without_openssl %}
        case _tls = tls_context
        when OpenSSL::SSL::SuperContext::Client
          socket = OpenSSL::SSL::SuperSocket::Client.new socket, context: _tls, hostname: @host, sync_context_free: false
        when OpenSSL::SSL::Context::Client
          socket = OpenSSL::SSL::Socket::Client.new socket, context: _tls, sync_close: true, hostname: @host
        end
      {% end %}

      @socket = socket
    rescue ex
      cleanup

      raise ex
    end
  end
end
