class MITM::Cache
  property storage : Hash(String, Tuple(String, String))
  property capacity : Int32
  property mutex : Mutex

  def initialize(@capacity : Int32 = 1024_i32)
    @storage = Hash(String, Tuple(String, String)).new
    @mutex = Mutex.new :unchecked
  end

  def full?
    @mutex.synchronize { capacity <= self.storage.size }
  end

  def clear
    @mutex.synchronize { self.storage.clear }
  end

  private def set!(name : String, value : Tuple(String, String))
    clear if full?

    @mutex.synchronize { self.storage[name] = value }
  end

  def get(name : String)
    @mutex.synchronize { storage[name]? }
  end

  def set(name : String, value : Tuple(String, String))
    @mutex.synchronize do
      return if storage[name]?

      set! name, value
    end
  end
end
