require 'openssl'

module AttrVault
  # borrowed wholesale from Fernet

  # Internal: Encapsulates encryption and signing primitives
  module Encryption
    AES_BLOCK_SIZE  = 16.freeze

    # Internal: Encrypts the provided message using a AES-128-CBC cipher with a
    #   random IV and the provided encryption key
    #
    # Arguments:
    #
    # * message - the message to encrypt
    # * key     - the encryption key
    # * iv      - override for the random IV, only used for testing
    #
    # Examples
    #
    #   ciphertext, iv = AttrVault::Encryption.encrypt(
    #     message: 'this is a secret', key: encryption_key
    #   )
    #
    # Returns a two-element array containing the ciphertext and the random IV
    def self.encrypt(key:, message:, iv: nil)
      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.encrypt
      iv ||= cipher.random_iv
      cipher.iv  = iv
      cipher.key = key
      [cipher.update(message) + cipher.final, iv]
    end

    # Internal: Decrypts the provided ciphertext using a AES-128-CBC cipher with a
    #   the provided IV and encryption key
    #
    # Arguments:
    #
    # * ciphertext - encrypted message
    # * key        - encryption key used to encrypt the message
    # * iv         - initialization vector used in the ciphertext's cipher
    #
    # Examples
    #
    #   ciphertext, iv = AttrVault::Encryption.encrypt(
    #     message: 'this is a secret', key: encryption_key
    #   )
    #
    # Returns a two-element array containing the ciphertext and the random IV
    def self.decrypt(key:, ciphertext:, iv:)
      decipher = OpenSSL::Cipher.new('AES-128-CBC')
      decipher.decrypt
      decipher.iv  = iv
      decipher.key = key
      decipher.update(ciphertext) + decipher.final
    end

    # Internal: Creates an HMAC signature (sha256 hashing) of the given bytes
    #   with the provided signing key
    #
    # key   - the signing key
    # bytes - blob of bytes to sign
    #
    # Returns the HMAC signature as a string
    def self.hmac_digest(key, bytes)
      OpenSSL::HMAC.digest('sha256', key, bytes)
    end
  end
end
