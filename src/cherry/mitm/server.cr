class MITM::Server
  def self.upgrade(socket, request, context : MITM::Context, options : Array(LibSSL::Options)? = nil)
    return socket unless server_context = context.create_server request
    options.try &.each { |option| server_context.add_options option } rescue nil

    upgrade = OpenSSL::SSL::Socket::Server.new io: socket, context: server_context, sync_close: true rescue nil
    upgrade.sync = true if upgrade

    upgrade || socket
  end
end
