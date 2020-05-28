require 'spec_helper'

describe AttrVault::Secret do
  it "can resolve a URL safe base64 encoded 32 byte string" do
    resolves_input(Base64.urlsafe_encode64("A"*16 + "B"*16))
  end

  it "can resolve a base64 encoded 32 byte string" do
    resolves_input(Base64.encode64("A"*16 + "B"*16))
  end

  it "can resolve a 32 byte string without encoding" do
    resolves_input("A"*16 + "B"*16)
  end

  it "fails loudly when an invalid secret is provided" do
    secret = Base64.urlsafe_encode64("bad")
    [true, false].each do |aead|
      expect do
        AttrVault::Secret.new(secret, aead: aead)
      end.to raise_error(AttrVault::InvalidSecret)
    end
  end

  def resolves_input(input)
    secret = AttrVault::Secret.new(input, aead: false)

    expect(
      secret.signing_key
    ).to eq("A"*16)

    expect(
      secret.encryption_key
    ).to eq("B"*16)

    secret = AttrVault::Secret.new(input, aead: true)
    
    expect {
      secret.signing_key
     }.to raise_error(AttrVault::Error)

    expect(
      secret.encryption_key
    ).to eq("A"*16 + "B"*16)
  end
end
