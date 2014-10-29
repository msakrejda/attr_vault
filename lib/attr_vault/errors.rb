module AttrVault
  # Base class for AttrVault errors
  class Error < StandardError; end
  class InvalidKey < AttrVault::Error; end
  class InvalidKeyring < AttrVault::Error; end
  class KeyringEmpty < AttrVault::Error; end
  class UnknownKey < AttrVault::Error
    def initialize(key_id)
      @key_id = key_id
    end
    def message
      formatted_id = if @key_id.nil?
                       '<nil>'
                     else
                       @key_id
                     end
      "No key with id #{formatted_id} found in keyring"
    end
  end
  class InvalidCiphertext < AttrVault::Error; end
end
