require "rails_helper"

RSpec.describe Widget do
  fixtures :widgets

  it_behaves_like "a labelled record"

  it "loads the fixture" do
    expect(widgets(:small).label).to eq("sprocket (2)")
    expect(Widget.count).to eq(1)
  end

  it "builds gadgets from the factory" do
    expect(create(:gadget)).to be_shouted_as("BOLT")
    expect(Gadget.count).to eq(1)
  end
end
