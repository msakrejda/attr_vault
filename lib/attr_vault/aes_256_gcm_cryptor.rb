# frozen_string_literal: true

require "base64"
require "openssl"

module AttrVault
  module AES256GCMCryptor
    def self.encrypt(value, key)
      return value if value.nil? || value.empty?
      secret = AttrVault::Secret.new(key, aead: true)
      cipher = OpenSSL::Cipher.new("AES-256-GCM")
      cipher.encrypt
      cipher.key = secret.encryption_key
      iv = cipher.random_iv
      cipher.auth_data = ""

      blob = StringIO.open { |io|
        io.binmode
        io.write(iv)
        io.write(cipher.update(value))
        io.write(cipher.final)
        io.write(cipher.auth_tag(16))

        io.string
      }

      Sequel.blob(blob)
    end

    def self.decrypt(encrypted, key)
      return encrypted if encrypted.nil? || encrypted.empty?

      secret = AttrVault::Secret.new(key, aead: true)

      decipher = OpenSSL::Cipher.new("AES-256-GCM")
      decipher.decrypt
      decipher.key = secret.encryption_key
      iv = encrypted[0..11]
      decipher.iv = iv

      # Check auth tag length with care: if truncated, it will open an
      # attack to forge the message.
      auth_tag = encrypted[-16..-1]
      fail auth_tag.bytesize.to_s unless auth_tag.bytesize == 16
      decipher.auth_tag = auth_tag

      decipher.auth_data = ""

      StringIO.open do |io|
        io.binmode
        io.write(decipher.update(encrypted[12..-17]))

        begin
          io.write(decipher.final)
        rescue OpenSSL::Cipher::CipherError
          raise InvalidCiphertext.new("Could not decrypt field")
        end

        io.string
      end
    end
  end
end
