require "base64"
require "orange"
require "cherry"

# This is a simple design, please do not use it directly.

def handle_client(context, client : Orange::Socket)
  return client.close unless request = client.request_payload

  STDOUT.puts [client]

  case {client.tunnel_mode, client.traffic_type}
  when {true, Orange::Traffic::HTTPS}
    client = MITM::Server.upgrade client, request, context

    buffer = uninitialized UInt8[4096_i32]
    length = client.read buffer.to_slice
    puts String.new buffer.to_slice[0_i32, length]
  end

  # But you have to manage the memory manually, please free the memory allocation manually when you don't need it.
  # If you free the same memory multiple times, your program will crash.
  # When using `Fiber`, please use it with `Channel` (It will protect you from free the same memory multiple times).

  client.close
  tls_free client
end

def tls_free(socket : IO)
  case socket
  when Orange::Client
    socket = socket.wrapped
  end

  socket.all_free if socket.responds_to? :all_free
end

# Durian
servers = [] of Tuple(Socket::IPAddress, Durian::Protocol)
servers << Tuple.new Socket::IPAddress.new("8.8.8.8", 53_i32), Durian::Protocol::UDP
servers << Tuple.new Socket::IPAddress.new("1.1.1.1", 53_i32), Durian::Protocol::UDP
resolver = Durian::Resolver.new servers
resolver.ip_cache = Durian::Resolver::Cache::IPAddress.new

# Orange
tcp_server = TCPServer.new "0.0.0.0", 1234_i32
orange = Orange::Server.new tcp_server, resolver
orange.authentication = Orange::Authentication::None
orange.client_timeout = Orange::TimeOut.new
orange.remote_timeout = Orange::TimeOut.new

certificate = Base64.decode_string "Something..."
private_key = Base64.decode_string "Something..."
context = MITM::Context.new certificate, private_key

# Authentication (Optional)
# orange.authentication = Orange::Authentication::Basic
# orange.on_auth = ->(user_name : String, password : String) do
#  STDOUT.puts [user_name, password]
#  Orange::Verify::Pass
# end

loop do
  socket = orange.accept?

  spawn do
    next unless client = socket
    next unless client = orange.process client

    handle_client context, client
  end
end
