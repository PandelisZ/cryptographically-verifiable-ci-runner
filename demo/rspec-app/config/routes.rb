Rails.application.routes.draw do
  get "codes/:id" => "codes#show", as: :code
end
