class OpenSSL::SSL::Server
  def client_read_timeout
    wrapped.client_read_timeout
  end

  def client_write_timeout
    wrapped.client_write_timeout
  end
end
