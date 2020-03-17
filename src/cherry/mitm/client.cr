module MITM
  class Client
    def self.upgrade(io : IO, hostname : String? = nil, options : Array(LibSSL::Options)? = nil,
                     verify_mode : OpenSSL::SSL::VerifyMode = OpenSSL::SSL::VerifyMode::NONE)
      return io unless client_context = Context.create_client
      options.each { |option| client_context.add_options option } rescue nil if options

      upgrade = OpenSSL::SSL::Socket::Client.new io: io, context: client_context,
        sync_close: true, hostname: hostname rescue nil

      upgrade || io
    end
  end
end
