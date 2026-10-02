require "rails_helper"

RSpec.describe "codes" do
  it "encodes the id" do
    get code_path(42)
    expect(response).to have_http_status(:success)
    expect(response.body).to eq(Hashids.new("abcd").encode(42))
  end
end
