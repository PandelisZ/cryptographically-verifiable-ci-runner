class CodesController < ApplicationController
  def show
    render plain: Hashids.new("abcd").encode(params[:id].to_i)
  end
end
