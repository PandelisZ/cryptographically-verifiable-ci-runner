class Photo < ApplicationRecord
  has_one_attached :image
  validates :title, presence: true

  def caption
    "#{title}!"
  end
end
