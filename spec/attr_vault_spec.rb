require 'spec_helper'
require 'json'

describe AttrVault do
  context "with a single encrypted column" do
    let(:key_data) {
      [{
        id: '80a8571b-dc8a-44da-9b89-caee87e41ce2',
        value: 'aFJDXs+798G7wgS/nap21LXIpm/Rrr39jIVo2m/cdj8=',
        created_at: Time.now }].to_json
    }
    let(:item)   {
      # the let form can't be evaluated inside the class definition
      # because Ruby scoping rules were written by H.P. Lovecraft, so
      # we create a local here to work around that
      k = key_data
      Class.new(Sequel::Model(:items)) do
        include AttrVault
        vault_keyring k
        vault_attr :secret
      end
    }

    context "with a new object" do
      it "does not affect other attributes" do
        not_secret = 'jimi hendrix was rather talented'
        s = item.create(not_secret: not_secret)
        s.reload
        expect(s.not_secret).to eq(not_secret)
        expect(s.this.where(not_secret: not_secret).count).to eq 1
      end

      it "encrypts non-empty values" do
        secret = 'lady gaga? also rather talented'
        s = item.create(secret: secret)
        s.reload
        expect(s.secret).to eq(secret)
        s.columns.each do |col|
          expect(s.this.where(Sequel.cast(Sequel.cast(col, :text), :bytea) => secret).count).to eq 0
        end
      end
    end
  end
end
