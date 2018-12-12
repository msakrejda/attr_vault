require "spec_helper"
require "json"
require "securerandom"

module AttrVault
  describe Keyring do

    describe ".load" do
      let(:key_data) {
        [
         { id: SecureRandom.uuid, value: SecureRandom.base64(32), created_at: Time.now, new_id: 1 },
         { id: SecureRandom.uuid, value: SecureRandom.base64(32), created_at: Time.now, new_id: 2 }
        ]
      }

      it "loads a valid keyring string" do
        keyring = Keyring.load(key_data.to_json)
        expect(keyring).to be_a Keyring
        expect(keyring.keys.count).to eq 2
        (0..1).each do |i|
          expect(keyring.keys[i].id).to eq key_data[i][:id]
          expect(keyring.keys[i].value).to eq key_data[i][:value]
          expect(keyring.keys[i].created_at).to be_within(60).of(key_data[i][:created_at])
          expect(keyring.keys[i].new_id).to eq key_data[i][:new_id]
        end
      end

      it "rejects unexpected JSON" do
        expect { Keyring.load('hello') }.to raise_error(InvalidKeyring)
      end

      it "rejects unknown formats" do
        keys = key_data.map do |k|
          "<key id='#{k[:id]}' value='#{k[:value]}' created_at='#{k[:created_at]}'/>"
        end
        expect { Keyring.load("<keys>#{keys}</keys>") }.to raise_error(InvalidKeyring)
      end

      it "rejects keys with missing ids" do
        key_data[0].delete :id
        expect { Keyring.load(key_data) }.to raise_error(InvalidKeyring)
      end

      it "rejects keys with missing values" do
        key_data[0].delete :value
        expect { Keyring.load(key_data) }.to raise_error(InvalidKeyring)
      end
    end
  end

  describe "#keys" do
    let(:keyring) { Keyring.new }
    let(:k1)      { Key.new(SecureRandom.uuid, SecureRandom.base64(32), Time.now) }
    let(:k2)      { Key.new(SecureRandom.uuid, SecureRandom.base64(32), Time.now) }

    before do
      keyring.add_key(k1)
      keyring.add_key(k2)
    end

    it "lists all keys" do
      expect(keyring.keys).to include(k1)
      expect(keyring.keys).to include(k2)
    end
  end

  describe "#fetch" do
    let(:keyring) { Keyring.new }
    let(:k1)      { Key.new(SecureRandom.uuid, SecureRandom.base64(32), Time.now) }
    let(:k2)      { Key.new(SecureRandom.uuid, SecureRandom.base64(32), Time.now) }

    before do
      keyring.add_key(k1)
      keyring.add_key(k2)
    end

    it "finds the right key by its id" do
      expect(keyring.fetch(k1.id)).to be k1
      expect(keyring.fetch(k2.id)).to be k2
    end

    it "raises for an unknown id" do
      expect { keyring.fetch('867344d2-ac73-493b-9a9e-5fa688ba25ef') }
        .to raise_error(UnknownKey)
    end
  end

  describe "#has_key?" do
    let(:keyring) { Keyring.new }
    let(:k1)      { Key.new(SecureRandom.uuid, SecureRandom.base64(32), Time.now) }
    let(:k2)      { Key.new(SecureRandom.uuid, SecureRandom.base64(32), Time.now) }

    before do
      keyring.add_key(k1)
      keyring.add_key(k2)
    end

    it "is true if the keyring has a key with the given id" do
      expect(keyring.has_key?(k1.id)).to be true
      expect(keyring.has_key?(k2.id)).to be true
    end

    it "is false if no such key is present" do
      expect(keyring.has_key?('867344d2-ac73-493b-9a9e-5fa688ba25ef')).to be false
    end
  end

  describe "#add_key" do
    let(:keyring) { Keyring.new }
    let(:k1)      { Key.new(SecureRandom.uuid, SecureRandom.base64(32), Time.now) }

    it "adds keys" do
      expect(keyring.keys).to be_empty
      expect { keyring.add_key(k1) }.to change { keyring.keys.count }.by 1
      expect(keyring.keys[0]).to be k1
    end
  end

  describe "#drop_key" do
    let(:keyring) { Keyring.new }
    let(:k1)      { Key.new(SecureRandom.uuid, SecureRandom.base64(32), Time.now) }
    let(:k2)      { Key.new(SecureRandom.uuid, SecureRandom.base64(32), Time.now) }

    before do
      keyring.add_key(k1)
      keyring.add_key(k2)
    end

    it "drops keys by identity" do
      expect(keyring.keys.count).to eq 2
      expect { keyring.drop_key(k1) }.to change { keyring.keys.count }.by -1
      expect(keyring.keys.count).to eq 1
      expect(keyring.keys[0]).to be k2
    end

    it "drops keys by identifier" do
      expect(keyring.keys.count).to eq 2
      expect { keyring.drop_key(k1.id) }.to change { keyring.keys.count }.by -1
      expect(keyring.keys.count).to eq 1
      expect(keyring.keys[0]).to be k2
    end
  end

  describe "#to_json" do
    let(:keyring) { Keyring.new }
    let(:k1)      { Key.new(SecureRandom.uuid, SecureRandom.base64(32), Time.now) }
    let(:k2)      { Key.new(SecureRandom.uuid, SecureRandom.base64(32), Time.now) }

    before do
      keyring.add_key(k1)
      keyring.add_key(k2)
    end

    it "serializes the keyring to an expected format" do
      keyring_data = keyring.to_json
      reparsed = JSON.parse(keyring_data)
      expect(reparsed[0]["id"]).to eq k1.id
      expect(reparsed[0]["value"]).to eq k1.value
      expect(reparsed[0]["created_at"]).to eq k1.created_at.to_s

      expect(reparsed[1]["id"]).to eq k2.id
      expect(reparsed[1]["value"]).to eq k2.value
      expect(reparsed[1]["created_at"]).to eq k2.created_at.to_s
    end
  end

  describe "#current_key" do
    let(:keyring) { Keyring.new }
    let(:k1)      { Key.new(SecureRandom.uuid, SecureRandom.base64(32), Time.now - 3) }
    let(:k2)      { Key.new(SecureRandom.uuid, SecureRandom.base64(32), Time.now) }

    before do
      keyring.add_key(k1)
      keyring.add_key(k2)
    end

    it "returns the newest key" do
      expect(keyring.current_key).to eq k2
    end

    it "raise if no keys are registered" do
      other_keyring = Keyring.new
      expect { other_keyring.current_key }.to raise_error(KeyringEmpty)
    end
  end
end
