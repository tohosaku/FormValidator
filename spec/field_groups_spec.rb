$KCODE = "u"

require "rspec"
require "formvalidator"

describe FormValidator do
  before :each do
    @fv = FormValidator.new
    @profile = {
      :result_symbol => true,
      :field_groups => {
        :tel => [:tel1, :tel2, :tel3]
      },
      :required => [ :tel, :mail_address ],
      :constraints => {
        :tel => /^d+/,
        :mail_address => :email
      },
      :msgs => {
        :constraints =>
        {
          :tel => "input your telephone no"
        }
      }
    }
  end

  it "invalid tel no" do
    params = { "tel1" => "aaa", "tel2" => "bbb", "tel3" => "ccc", "mail_address" => "aaa" }
    @fv.validate(params, @profile)
    expect(@fv.invalid).to eq( { :tel => [:tel], :mail_address => [:email] } )
  end
end

