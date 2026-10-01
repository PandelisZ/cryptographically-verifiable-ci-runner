require "test_helper"

class BTest < ActiveSupport::TestCase
  test "fixture widget" do
    w = widgets(:small)
    assert_equal "sprocket (2)", w.label
    assert_equal 1, Widget.count
  end

  test "gadgets" do
    assert_equal "BOLT", Gadget.create!(name: "bolt").shout
    assert_equal 1, Gadget.count
  end
end
