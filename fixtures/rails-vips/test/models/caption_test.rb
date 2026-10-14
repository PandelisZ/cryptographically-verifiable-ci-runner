require "test_helper"

# (a) A model test that never touches storage: Rails boots Active Storage,
# which loads ruby-vips (and libvips through FFI), but nothing calls it.
class CaptionTest < ActiveSupport::TestCase
  test "caption" do
    assert_equal "Beach!", photos(:beach).caption
    assert_not Photo.new.valid?
  end
end
