module MITM
  class Extract < IO
    property extract : IO::Memory
    property socket : TCPSocket
    property sync_close : Bool
    property? closed : Bool

    def initialize(@socket, @extract, @sync_close : Bool = true)
      @closed = false
    end

    def self.new(socket, extract, sync_close : Bool = true, &block)
      yield new socket, extract, sync_close
    end

    def self.part(socket : TCPSocket, &block)
      yield part socket
    end

    def self.part(socket : TCPSocket)
      part! socket rescue IO::Memory.new
    end

    def self.part!(socket : TCPSocket, &block)
      yield part! socket
    end

    def self.part!(socket : TCPSocket)
      buffer = uninitialized UInt8[24576_i32]
      length = socket.read buffer.to_slice
      IO::Memory.new String
        .new buffer.to_slice[0_i32, length]
    end

    def extract_eof?
      extract.pos == extract.size
    end

    def write(slice : Bytes) : Nil
    end

    def read(slice : Bytes)
      if extract.closed?
        return socket.read slice
      end

      length = extract.read slice
      extract.close if extract_eof?
      length
    end

    def closed?
      @closed
    end

    def close
      return if closed?
      @closed = true

      extract.close
      if sync_close
        socket.close
      end
    end
  end
end
