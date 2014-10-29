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

      it "stores empty values as empty" do
        secret = ''
        s = item.create(secret: secret)
        s.reload
        expect(s.secret).to eq('')
        expect(s.secret_encrypted).to eq('')
      end

      it "stores nil values as nil" do
        s = item.create(secret: nil)
        s.reload
        expect(s.secret).to be_nil
        expect(s.secret_encrypted).to be_nil
      end
    end

    context "with an existing object" do
      it "does not affect other attributes" do
        not_secret = 'soylent is not especially tasty'
        s = item.create
        s.update(not_secret: not_secret)
        s.reload
        expect(s.not_secret).to eq(not_secret)
        expect(s.this.where(not_secret: not_secret).count).to eq 1
      end

      it "encrypts non-empty values" do
        secret = 'soylent green is made of people'
        s = item.create
        s.update(secret: secret)
        s.reload
        expect(s.secret).to eq(secret)
        s.columns.each do |col|
          expect(s.this.where(Sequel.cast(Sequel.cast(col, :text), :bytea) => secret).count).to eq 0
        end
      end

      it "stores empty values as empty" do
        s = item.create(secret: "darth vader is luke's father")
        s.update(secret: '')
        s.reload
        expect(s.secret).to eq('')
        expect(s.secret_encrypted).to eq('')
      end

      it "leaves nil values as nil" do
        s = item.create(secret: "dr. crowe was dead all along")
        s.update(secret: nil)
        s.reload
        expect(s.secret).to be_nil
        expect(s.secret_encrypted).to be_nil
      end
    end
  end

  context "with multiple encrypted columns" do
    let(:key_data) {
      [{
        id: '80a8571b-dc8a-44da-9b89-caee87e41ce2',
        value: 'aFJDXs+798G7wgS/nap21LXIpm/Rrr39jIVo2m/cdj8=',
        created_at: Time.now }].to_json
    }
    let(:item)   {
      k = key_data
      Class.new(Sequel::Model(:items)) do
        include AttrVault
        vault_keyring k
        vault_attr :secret
        vault_attr :other
      end
    }

    it "does not clobber other attributes" do
      secret1 = "superman is really mild-mannered reporter clark kent"
      secret2 = "batman is really millionaire playboy bruce wayne"
      s = item.create(secret: secret1)
      s.reload
      expect(s.secret).to eq secret1
      s.update(other: secret2)
      s.reload
      expect(s.secret).to eq secret1
      expect(s.other).to eq secret2
    end
  end

  context "with renamed database fields" do
    let(:key_data) {
      [{
        id: '80a8571b-dc8a-44da-9b89-caee87e41ce2',
        value: 'aFJDXs+798G7wgS/nap21LXIpm/Rrr39jIVo2m/cdj8=',
        created_at: Time.now }].to_json
    }

    it "supports renaming the encrypted and hmac fields" do
      k = key_data
      item = Class.new(Sequel::Model(:items)) do
        include AttrVault
        vault_keyring k
        vault_attr :classified_info,
          encrypted_field: :secret_encrypted,
          hmac_field: :secret_hmac
      end

      secret = "we've secretly replaced the fine coffee they usually serve with Folgers Crystals"
      s = item.create(classified_info: secret)
      s.reload
      expect(s.classified_info).to eq secret
      expect(s.secret_encrypted).not_to eq secret
      expect(s.secret_hmac).not_to be_nil
    end

    it "supports renaming the key id field" do
      k = key_data
      item = Class.new(Sequel::Model(:items)) do
        include AttrVault
        vault_keyring k, key_field: :alt_key_id
        vault_attr :secret
      end

      secret = "up up down down left right left right b a"
      s = item.create(secret: secret)
      s.reload
      expect(s.secret).to eq secret
      expect(s.secret_encrypted).not_to eq secret
      expect(s.secret_hmac).not_to be_nil
      expect(s.alt_key_id).not_to be_nil
      expect(s.key_id).to be_nil
    end
  end
end
