RSpec.shared_examples "a labelled record" do
  it "needs a name" do
    expect(described_class.new(name: "")).not_to be_valid
  end
end
