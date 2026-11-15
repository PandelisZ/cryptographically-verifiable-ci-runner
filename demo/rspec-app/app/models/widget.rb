class Widget < ApplicationRecord
  validates :name, presence: true

  def label
    "#{name} (#{size})"
  end
end

# Touched by the local agent.
