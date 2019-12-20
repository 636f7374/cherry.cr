class HTTP::Client
  {% if flag?(:without_openssl) %}
    getter! tls : Nil
  {% else %}
    getter! tls : OpenSSL::SSL::SuperContext::Client | OpenSSL::SSL::Context::Client
  {% end %}

  # Whether automatic compression/decompression is enabled.
  property? compress : Bool

  {% if flag?(:without_openssl) %}
    @socket : TCPSocket?
  {% else %}
    @socket : TCPSocket | OpenSSL::SSL::SuperSocket | OpenSSL::SSL::Socket | Nil
  {% end %}

  {% unless flag?(:without_openssl) %}
    def initialize(@host : String, port = nil, tls : Bool | OpenSSL::SSL::SuperContext::Client = false)
      check_host_only(@host)

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

  {% unless flag?(:without_openssl) %}
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

  def close
    return unless _socket = @socket

    _socket.close ensure original_socket.try &.close
    all_free ensure super_context_free

    @socket = nil
  end

  def super_context_freed?
    return unless _tls = @tls

    _tls.freed? if _tls.is_a? OpenSSL::SSL::SuperContext::Client
  end

  def super_context_free
    return unless _tls = @tls

    _tls.free if _tls.is_a? OpenSSL::SSL::SuperContext::Client
  end

  def all_free
    return unless _socket = @socket

    _socket.all_free if _socket.is_a? OpenSSL::SSL::SuperSocket::Client
  end

  private def original_socket=(value : TCPSocket)
    @original_socket = value
  end

  private def original_socket : TCPSocket?
    @original_socket
  end

  def io_socket
    return if super_context_freed?

    socket
  end

  def tls_context
    tls rescue nil
  end

  private def socket
    _socket = @socket
    return _socket if _socket

    hostname = @host.starts_with?('[') && @host.ends_with?(']') ? @host[1_i32..-2_i32] : @host

    begin
      socket = TCPSocket.new hostname, @port, @dns_timeout, @connect_timeout
      socket.read_timeout = @read_timeout if @read_timeout
      socket.sync = false
      self.original_socket = socket

      {% unless flag?(:without_openssl) %}
        case _tls = tls_context
        when OpenSSL::SSL::SuperContext::Client
          socket = OpenSSL::SSL::SuperSocket::Client.new socket, context: _tls, hostname: @host, sync_context_free: false
          socket.skip_free = true if socket.responds_to? :skip_free=
        when OpenSSL::SSL::Context::Client
          socket = OpenSSL::SSL::Socket::Client.new socket, context: _tls, sync_close: true, hostname: @host
        end
      {% end %}

      @socket = socket
    rescue ex
      @socket.try &.close ensure original_socket.try &.close
      all_free ensure super_context_free ensure raise ex
    end
  end
end
