require 'base64'

module AttrVault
  module Cryptor

    PARANOID = true

    def self.encrypt(value, key)
      return value if value.nil? || value.empty?

      secret = AttrVault::Secret.new(key)
      encrypted_message, iv = Encryption.encrypt(key: secret.encryption_key,
                                                 message: value)
      encrypted_payload = iv + encrypted_message
      mac = Encryption.hmac_digest(secret.signing_key, encrypted_payload)

      if PARANOID
        mac_again = Encryption.hmac_digest(secret.signing_key, encrypted_payload)
        unless verify_signature(mac, mac_again)
          raise InvalidCiphertext, "Could not reliably calculate HMAC; " +
            "got #{Base64.encode64(mac)} and #{Base64.encode64(mac_again)} " +
            "for the same values"
        end
      end

      Sequel.blob(mac + encrypted_payload)
    end

    def self.decrypt(encrypted, key)
      return encrypted if encrypted.nil? || encrypted.empty?

      secret = AttrVault::Secret.new(key)
      hmac, encrypted_payload = encrypted[0...32], encrypted[32..-1]
      expected_hmac = Encryption.hmac_digest(secret.signing_key, encrypted_payload)

      unless verify_signature(expected_hmac, hmac)
        raise InvalidCiphertext,
          "Expected hmac #{Base64.encode64(expected_hmac)} for this value; " +
          "got #{Base64.encode64(hmac)}"
      end

      iv, encrypted_message = encrypted_payload[0...16], encrypted_payload[16..-1]
      block_size = Encryption::AES_BLOCK_SIZE
      unless (encrypted_message.size % block_size).zero?
        raise InvalidCiphertext,
          "Expected message size to be multiple of #{block_size}; got #{encrypted_message.size}"
      end

      begin
        Encryption.decrypt(key: secret.encryption_key,
                           ciphertext: encrypted_message,
                           iv: iv)
      rescue OpenSSL::Cipher::CipherError
        raise InvalidCiphertext, "Could not decrypt field"
      end
    end

    private

    def self.verify_signature(expected, actual)
      expected_bytes = expected.bytes.to_a
      actual_bytes = actual.bytes.to_a
      actual_bytes.inject(0) do |accum, byte|
        accum |= byte ^ expected_bytes.shift
      end.zero?
    end
  end
end
