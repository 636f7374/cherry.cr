abstract class OpenSSL::SSL::SuperSocket < OpenSSL::SSL::Socket
  getter? io : IO

  class Client < SuperSocket
    def initialize(io, context : SuperContext::Client = SuperContext::Client.new, sync_context_free : Bool = true, hostname : String? = nil)
      super io, context, sync_context_free

      begin
        set_hostname hostname: hostname
        ret = LibSSL.ssl_connect @ssl
        raise OpenSSL::SSL::Error.new @ssl, ret, "SSL_connect" unless ret == 1_i32
      rescue ex
        sync_context_free ? all_free : free
        raise ex
      end
    end

    private def set_hostname(hostname : String? = nil)
      if hostname
        # Macro from OpenSSL: SSL_ctrl(s,SSL_CTRL_SET_TLSEXT_HOSTNAME,TLSEXT_NAMETYPE_host_name,(char *)name)
        LibSSL.ssl_ctrl(
          @ssl,
          LibSSL::SSLCtrl::SET_TLSEXT_HOSTNAME,
          LibSSL::TLSExt::NAMETYPE_host_name,
          hostname.to_unsafe.as(Pointer(Void))
        )

        {% if compare_versions(LibSSL::OPENSSL_VERSION, "1.0.2") >= 0_i32 %}
          param = LibSSL.ssl_get0_param @ssl

          if ::Socket.ip? hostname
            unless LibCrypto.x509_verify_param_set1_ip_asc(param, hostname) == 1_i32
              raise OpenSSL::Error.new "X509_VERIFY_PARAM_set1_ip_asc"
            end
          else
            unless LibCrypto.x509_verify_param_set1_host(param, hostname, 0_i32) == 1_i32
              raise OpenSSL::Error.new "X509_VERIFY_PARAM_set1_host"
            end
          end
        {% else %}
          _context = @context

          if _context.is_a? OpenSSL::SSL::SuperContext::Client
            _context.set_cert_verify_callback hostname
          end
        {% end %}
      end
    end
  end

  class Server < SuperSocket
    def initialize(io, context : SuperContext::Server = SuperContext::Server.new, sync_context_free : Bool = true)
      super io, context, sync_context_free

      begin
        ret = LibSSL.ssl_accept @ssl
        raise OpenSSL::SSL::Error.new @ssl, ret, "SSL_accept" unless ret == 1_i32
      rescue ex
        sync_context_free ? all_free : free
        raise ex
      end
    end
  end

  protected def initialize(@io, @context : SuperContext, @sync_context_free : Bool = true)
    @sync_close = true
    @freed = false
    @closed = false

    begin
      raise OpenSSL::Error.new "SSL_new" if context.freed?
    rescue ex
      raise ex
    end

    @ssl = LibSSL.ssl_new context

    begin
      raise OpenSSL::Error.new "SSL_new" unless @ssl
    rescue ex
      sync_context_free ? all_free : free
      raise ex
    end

    # Since OpenSSL::SSL::Socket is buffered it makes no
    # sense to wrap a IO::Buffered with buffering activated.
    if io.is_a? IO::Buffered
      io.sync = true
      io.read_buffering = false
    end

    @bio = BIO.new io
    LibSSL.ssl_set_bio @ssl, @bio, @bio
  end

  def skip_free=(value : Bool)
    @skip_free = value
  end

  def skip_free?
    @skip_free
  end

  def context_free
    @context.free
  end

  def context_free!
    @context.free!
  end

  def freed?
    @freed
  end

  def closed?
    @closed
  end

  def free
    return if freed?
    free!
  end

  def free!
    @freed = true
    LibSSL.ssl_free @ssl
  end

  def all_free
    context_free
    free
  end

  def all_free!
    context_free!
    free!
  end

  def unbuffered_read(slice : Bytes)
    return 0_i32 if freed? || closed?
    check_open

    count = slice.size
    return 0_i32 if count == 0_i32

    LibSSL.ssl_read(@ssl, slice.to_unsafe, count).tap do |bytes|
      if bytes <= 0_i32 && !LibSSL.ssl_get_error(@ssl, bytes).zero_return?
        begin
          raise OpenSSL::SSL::Error.new @ssl, bytes, "SSL_read"
        rescue ex
          unless skip_free?
            @sync_context_free ? all_free : free
          end

          raise ex
        end
      end
    end
  end

  def unbuffered_write(slice : Bytes)
    return if freed? || closed?
    check_open
    return if slice.empty?

    count = slice.size
    bytes = LibSSL.ssl_write @ssl, slice.to_unsafe, count

    unless bytes > 0_i32
      begin
        raise OpenSSL::SSL::Error.new @ssl, bytes, "SSL_write"
      rescue ex
        unless skip_free?
          @sync_context_free ? all_free : free
        end

        raise ex
      end
    end

    nil
  end

  def unbuffered_flush
    return if freed? || closed?
    @bio.io.flush
  end

  def unbuffered_close
    return if freed? || closed?
    @closed = true
    @io.close
  end

  def unbuffered_rewind
    raise IO::Error.new "Can't rewind OpenSSL::SSL::SuperSocket"
  end

  def finalize
  end
end
