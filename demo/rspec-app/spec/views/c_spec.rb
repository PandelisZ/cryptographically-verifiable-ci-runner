require "rails_helper"

RSpec.describe "reports/show" do
  it "renders the report named in which.txt" do
    name = file_fixture("which.txt").read.strip
    title = file_fixture("#{name}.txt").read.strip
    render template: "reports/show", formats: [:text], locals: { title: title }
    expect(rendered).to eq("Report: Alpha title\n")
  end
end
