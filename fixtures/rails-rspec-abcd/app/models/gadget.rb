class Gadget < ApplicationRecord
  def shout
    name.upcase
  end
end
