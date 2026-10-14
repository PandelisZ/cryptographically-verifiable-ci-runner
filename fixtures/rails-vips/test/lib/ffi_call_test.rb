require "test_helper"
require "ffi"

# (c) A C function called through FFI: vci cannot see what C code reads.
module Libc
  extend FFI::Library
  ffi_lib FFI::Library::LIBC
  attach_function :getpid, [], :int
end

class FfiCallTest < ActiveSupport::TestCase
  test "calls C" do
    assert_equal Process.pid, Libc.getpid
  end
end
