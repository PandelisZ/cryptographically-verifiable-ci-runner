require "test_helper"

# (b) Attaching a fixture image and analysing it through Active Storage:
# libvips reads the image's copy in the process's temp dir; the fixture file
# itself is read by Ruby, so it is an input.
class ImageTest < ActiveSupport::TestCase
  test "analyses an attached image" do
    photo = photos(:beach)
    photo.image.attach(io: file_fixture("pixel.png").open, filename: "pixel.png", content_type: "image/png")
    blob = photo.image.blob
    blob.analyze
    assert_equal 3, blob.metadata[:width]
    assert_equal 2, blob.metadata[:height]
  end
end
