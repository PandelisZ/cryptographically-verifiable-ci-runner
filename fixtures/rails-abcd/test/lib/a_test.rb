require "test_helper"

class ATest < ActiveSupport::TestCase
  test "adds" do
    assert_equal 3, Calc.add(1, 2)
  end
end
