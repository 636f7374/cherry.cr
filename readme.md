<div align = "center"><img src="images/icon.png" width="256" height="256" /></div>

<div align = "center">
  <h1>Cherry.cr - Man-in-the-middle Toolkit</h1>
</div>

<p align="center">
  <a href="https://crystal-lang.org">
    <img src="https://img.shields.io/badge/built%20with-crystal-000000.svg" /></a>
  <a href="https://travis-ci.org/636f7374/cherry.cr">
    <img src="https://api.travis-ci.org/636f7374/cherry.cr.svg" /></a>
  <a href="https://github.com/636f7374/cherry.cr/releases">
    <img src="https://img.shields.io/github/release/636f7374/cherry.cr.svg" /></a>
  <a href="https://github.com/636f7374/cherry.cr/blob/master/license">
  	<img src="https://img.shields.io/github/license/636f7374/cherry.cr.svg"></a>
</p>

## Description

* Because Crystal language is missing most OpenSSL bindings ([libCrypto](https://github.com/crystal-lang/crystal/blob/master/src/openssl/lib_crypto.cr), libSSL).
  * [It doesn't even support loading certificate / private key files from memory](https://github.com/crystal-lang/crystal/issues/7897).
* Of course, Crystal official is [always busy](#related), it will not help you solve these problems.
  * In despair, I came across [openssl.cr](https://github.com/datanoise/openssl.cr), which is a shabby OpenSSL binding.
  * This OpenSSL repository was last updated 5 years ago, Fortunately, most of its features are not completely broken.
  * So I started to test slowly and repair the broken things, And refer to [Ruby prototype](https://ruby-doc.org/stdlib-2.4.0/libdoc/openssl/rdoc/OpenSSL/X509/Certificate.html) for redesign.
  * It took one month to fix most of the problems, and finally it was available after three months.
* I think if I was using [Rust](https://github.com/sfackler/rust-openssl) then I would n’t have encountered these problems.
  * But this allows me to learn a lot, I hope it can help more people.
* That's it, Thanks for using, If you encounter any problems, please let me know.
* After a period of testing, thread safety is now supported.

## Features

* OpenSSL
  * Lib (libCrypto, libSSL)
    * There are many bindings in it, many related to loading / reading certificates.
    * libCrypto: (I.e. `bio_*`, `evp_*`, `rsa_*`, `dsa_*`, `pem_*`, `asn1_*`, `x509_*`).
    * libSSL: (I.e. `ssl_ctx_use_certificate`, `ssl_ctx_use_privatekey`).
  * Asn1 (Integer, Time)
    * Integer: Certificate serial number, very useful.
    * Time: Certificate validity period, very useful.
  * Bio (MemBIO)
    * MemBIO: OpenSSL memory buffer, Essential when making Certificate / (Private / Public) keys.
  * Nid
    * Certificate subject id flag, Essential when making Certificate.
    * NID: (I.e. `subject_alt_name`, `ext_usage`, `usage`).
  * Pkey (PKey, DSA, RSA)
    * Essential when (create / read) Public / Private Key.
    * I encountered a memory leak problem here, it has been fixed.
  * SSL (Context)
    * Context: Support loading certificate / private key files from memory.
  * X509 (ExtensionFactory, Request, SuperCertificate, SuperName).
    * ExtensionFactory: Certificate Subject Add / Remove, very important.
    * Request: I don't seem to use it, but I also made.
    * SuperCertificate: Generate certificate requires it.
    * SuperName: `issuer_name`, `subject_name`, Generate certificate requires it.

* MITM
  * Mitm Slightly complicated but worth it, low memory usage.
  * Client: Wrapper for `OpenSSL::SSL::Socket::Client`.
  * Server: Wrapper for `OpenSSL::SSL::Socket::Server`.
  * Context: Convenient and fast certificate generation, for Man-in-the-middle.

## Tips

* This repository contains OpenSSL and Network components.
  * Crystal HTTP::Client components are highly integrated with OpenSSL.

## Next

* [ ] More specification tests.
* [ ] Troubleshooting Deep Memory Errors / Memory Leaks (More stress tests?)
* [ ] ...


## Usage

* Simple Mitm Server (Need to be used with [Carton.cr](https://github.com/636f7374/carton.cr))

```crystal
require "base64"
require "carton"
require "cherry"

# This is a simple design, please do not use it directly.

def handle_client(context, client : Carton::Socket)
  return client.close unless request = client.request_payload

  STDOUT.puts [client]

  case {client.tunnel_mode, client.traffic_type}
  when {true, Carton::Traffic::HTTPS}
    client = MITM::Server.upgrade client, request, context

    buffer = uninitialized UInt8[4096_i32]
    length = client.read buffer.to_slice
    puts String.new buffer.to_slice[0_i32, length]
  end

  client.close
end

# Durian
servers = [] of Tuple(Socket::IPAddress, Durian::Protocol)
servers << Tuple.new Socket::IPAddress.new("8.8.8.8", 53_i32), Durian::Protocol::UDP
servers << Tuple.new Socket::IPAddress.new("1.1.1.1", 53_i32), Durian::Protocol::UDP
resolver = Durian::Resolver.new servers
resolver.ip_cache = Durian::Resolver::Cache::IPAddress.new

# Carton
tcp_server = TCPServer.new "0.0.0.0", 1234_i32
carton = Carton::Server.new tcp_server, resolver

carton.authentication = Carton::Authentication::None
carton.client_timeout = Carton::TimeOut.new
carton.remote_timeout = Carton::TimeOut.new

certificate = Base64.decode_string "Something..."
private_key = Base64.decode_string "Something..."
context = MITM::Context.new certificate, private_key

# Authentication (Optional)
# carton.authentication = Carton::Authentication::Basic
# carton.on_auth = ->(user_name : String, password : String) do
#  STDOUT.puts [user_name, password]
#  Carton::Verify::Pass
# end

loop do
  socket = carton.accept?

  spawn do
    next unless client = socket
    next unless client = carton.process client

    handle_client context, client
  end
end
```

* Simple HTTP Client

  * ...

### Used as Shard

Add this to your application's shard.yml:
```yaml
dependencies:
  cherry:
    github: 636f7374/cherry.cr
```

### Installation

```bash
$ git clone https://github.com/636f7374/cherry.cr.git
```

## Development

```bash
$ make test
```

## References

* [Official | Ruby OpenSSL::X509::Certificate](https://ruby-doc.org/stdlib-2.4.0/libdoc/openssl/rdoc/OpenSSL/X509/Certificate.html)
* [Official | OpenSSL Documentation](https://www.openssl.org/docs/)
* [Official | OpenSSL x509v3_config](https://www.openssl.org/docs/manmaster/man5/x509v3_config.html)
* [Official | PEM_read_bio_PrivateKey](https://www.openssl.org/docs/man1.1.0/man3/PEM_write_bio_RSA_PUBKEY.html)
* [Official | X509V3_get_d2i](https://www.openssl.org/docs/man1.1.0/man3/X509_add1_ext_i2d.html)
* [Official | Secure programming with the OpenSSL API](https://developer.ibm.com/tutorials/l-openssl/)
* [Github | Golang Nid.go](https://github.com/spacemonkeygo/openssl/blob/master/nid.go)
* [Github | Rust OpenSSL Password callbacks](https://github.com/sfackler/rust-openssl/pull/410)
* [Github | OpenSSL SSL_Rsa.c](https://github.com/openssl/openssl/blob/master/ssl/ssl_rsa.c)
* [Blogs | The Most Common OpenSSL Commands](https://www.sslshopper.com/article-most-common-openssl-commands.html)
* [Blogs | OpenSSL – Convert RSA Key to private key](https://rafpe.ninja/2016/08/17/openssl-convert-rsa-key-to-private-key/)
* [Blogs | problem with d2i_X509?](http://openssl.6102.n7.nabble.com/problem-with-d2i-X509-td1537.html)
* [Blogs | Parsing X.509 Certificates with OpenSSL and C](https://zakird.com/2013/10/13/certificate-parsing-with-openssl)
* [Blogs | Using the OpenSSL library with macOS Sierra](https://medium.com/@timmykko/using-openssl-library-with-macos-sierra-7807cfd47892)
* [StackOverflow | Read certificate files from memory instead of a file using OpenSSL](https://stackoverflow.com/questions/3810058/read-certificate-files-from-memory-instead-of-a-file-using-openssl)
* [StackOverflow | Programmatically Create X509 Certificate using OpenSSL](https://stackoverflow.com/questions/256405/programmatically-create-x509-certificate-using-openssl)
* [StackOverflow | OpenSSL Command to check if a server is presenting a certificate](https://stackoverflow.com/questions/24457408/openssl-command-to-check-if-a-server-is-presenting-a-certificate)
* [StackOverflow | C++ OpenSSL export private key](https://stackoverflow.com/questions/5367991/c-openssl-export-private-key)
* [StackOverflow | Why is openssl key length different from specified bytes](https://security.stackexchange.com/questions/102508/why-is-openssl-key-length-different-from-specified-bytes)
* [StackOverflow | Reading PEM-formatted RSA keyfile with the OpenSSL C API](https://stackoverflow.com/questions/16675147/reading-pem-formatted-rsa-keyfile-with-the-openssl-c-api)
* [StackOverflow | OpenSSL certificate lacks key identifiers](https://stackoverflow.com/questions/2883164/openssl-certificate-lacks-key-identifiers)
* [StackOverflow | OpenSSL CA keyUsage extension](https://superuser.com/questions/738612/openssl-ca-keyusage-extension)
* ...

## Related

* [#7897 | Need to enhance the OpenSSL::SSL::Context loads Certificate / PrivateKey from Memory](https://github.com/crystal-lang/crystal/issues/7897)
* [#7896 | Need to enhance the OpenSSL::X509 more features](https://github.com/crystal-lang/crystal/issues/7896)
* [#8108 | openssl ssl_accept sometimes does not return, causes server to hang permanently](https://github.com/crystal-lang/crystal/issues/8108)
* [#7291 | Get SNI for OpenSSL](https://github.com/crystal-lang/crystal/pull/7291)
* ...

## Credit

* [\_Icon::Wanicon/Fruits](https://www.flaticon.com/packs/fruits-and-vegetables-48)
* [\_Icon::Freepik/GraphicDesign](https://www.flaticon.com/packs/graphic-design-125)

## Contributors

|Name|Creator|Maintainer|Contributor|
|:---:|:---:|:---:|:---:|
|**[636f7374](https://github.com/636f7374)**|√|√||
|**[datanoise](https://github.com/datanoise)**|||√|

## License

* MIT License
