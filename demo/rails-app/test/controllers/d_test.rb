require "test_helper"

class DTest < ActionDispatch::IntegrationTest
  test "encodes the id" do
    get code_path(42)
    assert_response :success
    assert_equal Hashids.new("abcd").encode(42), response.body
  end
end
