RSpec::Matchers.define :be_shouted_as do |expected|
  match { |record| record.shout == expected }
end
