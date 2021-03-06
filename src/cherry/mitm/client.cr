class MITM::Client
  def self.upgrade(io : IO, hostname : String? = nil, options : Array(LibSSL::Options)? = nil,
                   verify_mode : OpenSSL::SSL::VerifyMode = OpenSSL::SSL::VerifyMode::NONE) : Tuple(OpenSSL::SSL::Context::Client?, IO)
    return Tuple.new nil, io unless client_context = Context.create_client
    options.try &.each { |option| client_context.add_options option } rescue nil

    upgrade = OpenSSL::SSL::Socket::Client.new io: io, context: client_context, sync_close: true, hostname: hostname rescue nil

    Tuple.new client_context, (upgrade || io)
  end
end
