class OpenSSL::MemBIO < IO
  def initialize(@bio : LibCrypto::BIO)
  end

  def self.new
    new LibCrypto.bio_new LibCrypto.bio_s_mem
  end

  def read(data : Bytes)
    LibCrypto.bio_read self, data, data.size
  end

  def write(data : String) : Nil
    write data.to_slice
  end

  def write(data : Bytes) : Nil
    LibCrypto.bio_write self, data, data.size
  end

  def reset
    ret = LibCrypto.bio_ctrl self, LibCrypto::BIO_CTRL_RESET, 0_i64, nil
    raise OpenSSL::Error.new "BIO_ctrl" if ret == 0_i32

    ret
  end

  def to_io(io : IO)
    IO.copy self, io
  end

  def to_s
    io = IO::Memory.new
    to_io io
    String.new io.to_slice
  end

  def finalize
    LibCrypto.bio_free_all self
  end

  def to_unsafe
    @bio
  end
end
