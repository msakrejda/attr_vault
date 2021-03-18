require "spec_helper"
require "json"
require "securerandom"

module AttrVault
  describe Keyring do

    describe ".load" do
      let(:key_data) {
        {
          '1' => SecureRandom.base64(32),
          '2' => SecureRandom.base64(32),
        }
      }

      it "loads a valid keyring string" do
        keyring = Keyring.load(key_data.to_json)
        expect(keyring).to be_a Keyring
        expect(keyring.keys.count).to eq 2
        key_data.keys.each do |key_id|
          key = keyring.keys.find { |k| k.id == Integer(key_id) }
          expect(key.value).to eq key_data[key_id]
        end
      end

      it "rejects unexpected JSON" do
        expect { Keyring.load('hello') }.to raise_error(InvalidKeyring)
      end

      it "rejects unknown formats" do
        keys = key_data.map do |k,v|
          "<key id='#{k}' value='#{v}'/>"
        end.join(',')
        expect { Keyring.load("<keys>#{keys}</keys>") }.to raise_error(InvalidKeyring)
      end

      it "rejects keys with missing values" do
        key_data['1'] = nil
        expect { Keyring.load(key_data) }.to raise_error(InvalidKeyring)
      end

      it "rejects keys with empty values" do
        key_data['1'] = ''
        expect { Keyring.load(key_data) }.to raise_error(InvalidKeyring)
      end
    end
  end

  describe "#keys" do
    let(:keyring) { Keyring.new }
    let(:k1)      { Key.new(1, ::SecureRandom.base64(32)) }
    let(:k2)      { Key.new(2, ::SecureRandom.base64(32)) }

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
    let(:k1)      { Key.new(1, ::SecureRandom.base64(32)) }
    let(:k2)      { Key.new(2, ::SecureRandom.base64(32)) }

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
    let(:k1)      { Key.new(1, ::SecureRandom.base64(32)) }
    let(:k2)      { Key.new(2, ::SecureRandom.base64(32)) }

    before do
      keyring.add_key(k1)
      keyring.add_key(k2)
    end

    it "is true if the keyring has a key with the given id" do
      expect(keyring.has_key?(k1.id)).to be true
      expect(keyring.has_key?(k2.id)).to be true
    end

    it "is false if no such key is present" do
      expect(keyring.has_key?(5)).to be false
    end
  end

  describe "#add_key" do
    let(:keyring) { Keyring.new }
    let(:k1)      { Key.new(1, ::SecureRandom.base64(32)) }

    it "adds keys" do
      expect(keyring.keys).to be_empty
      expect { keyring.add_key(k1) }.to change { keyring.keys.count }.by 1
      expect(keyring.keys[0]).to be k1
    end
  end

  describe "#drop_key" do
    let(:keyring) { Keyring.new }
    let(:k1)      { Key.new(1, ::SecureRandom.base64(32)) }
    let(:k2)      { Key.new(2, ::SecureRandom.base64(32)) }

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
    let(:k1)      { Key.new(1, ::SecureRandom.base64(32)) }
    let(:k2)      { Key.new(2, ::SecureRandom.base64(32)) }

    before do
      keyring.add_key(k1)
      keyring.add_key(k2)
    end

    it "serializes the keyring to an expected format" do
      keyring_data = keyring.to_json
      reparsed = JSON.parse(keyring_data)
      expect(reparsed[k1.id.to_s]).to eq k1.value
      expect(reparsed[k2.id.to_s]).to eq k2.value
    end
  end

  describe "#current_key" do
    let(:keyring) { Keyring.new }
    let(:k1)      { Key.new(1, ::SecureRandom.base64(32)) }
    let(:k2)      { Key.new(2, ::SecureRandom.base64(32)) }

    before do
      keyring.add_key(k1)
      keyring.add_key(k2)
    end

    it "returns the key with the largest id" do
      expect(keyring.current_key).to eq k2
    end

    it "returns the key with second largest id when use_nth_newest_key set to 2" do
      ring = Keyring.new(2)
      ring.add_key(k1)
      expect(ring.current_key).to eq k1
      ring.add_key(k2)
      expect(ring.current_key).to eq k1
      ring.add_key(Key.new(3, ::SecureRandom.base64(32)))
      expect(ring.current_key).to eq k2
    end

    it "raise if no keys are registered" do
      other_keyring = Keyring.new
      expect { other_keyring.current_key }.to raise_error(KeyringEmpty)
    end
  end
end
