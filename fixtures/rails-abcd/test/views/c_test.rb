require "test_helper"

class CTest < ActiveSupport::TestCase
  test "renders the report named in which.txt" do
    name = file_fixture("which.txt").read.strip
    title = file_fixture("#{name}.txt").read.strip
    out = ApplicationController.render(template: "reports/show", formats: [:text], locals: { title: title })
    assert_equal "Report: Alpha title\n", out
  end
end
