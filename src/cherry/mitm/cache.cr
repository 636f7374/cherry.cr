module MITM
  class Cache
    property collects : Immutable::Map(String, Tuple(String, String))
    property capacity : Int32

    def initialize(@capacity : Int32 = 1024_i32)
      @collects = Immutable::Map(String, Tuple(String, String)).new
    end

    def full?
      capacity <= collects.size
    end

    def reset
      @collects = Immutable::Map(String, Tuple(String, String)).new
    end

    def set!(name : String, value : Tuple(String, String))
      reset if full?

      _collects = collects.set name, value
      self.collects = _collects
    end

    def get(name : String)
      collects[name]?
    end

    def set(name : String, value : Tuple(String, String))
      return if collects[name]?

      set! name, value
    end
  end
end
