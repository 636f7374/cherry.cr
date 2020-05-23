class MITM::Cache
  property storage : Hash(String, Tuple(String, String))
  property capacity : Int32
  property mutex : Mutex

  def initialize(@capacity : Int32 = 1024_i32)
    @storage = Hash(String, Tuple(String, String)).new
    @mutex = Mutex.new :unchecked
  end

  def full?
    capacity <= storage.size
  end

  def reset
    self.storage.clear
  end

  private def set!(name : String, value : Tuple(String, String))
    reset if full?

    self.storage[name] = value
  end

  def get(name : String)
    storage[name]?
  end

  def set(name : String, value : Tuple(String, String))
    return if storage[name]?

    @mutex.synchronize do
      set! name, value
    end
  end
end
