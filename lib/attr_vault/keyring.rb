module AttrVault
  class Key
    attr_reader :id, :value, :created_at

    def initialize(id, value, created_at)
      if id.nil?
        raise InvalidKey, "key id required"
      end
      if value.nil?
        raise InvalidKey, "key value required"
      end
      if created_at.nil?
        raise InvalidKey, "key created_at required"
      end

      @id = id
      @value = value
      @created_at = created_at
    end

    def digest(data)
      AttrVault::Encryption::hmac_digest(value, data)
    end

    def to_json(*args)
      { id: id, value: value, created_at: created_at }.to_json
    end
  end

  class Keyring
    attr_reader :keys

    def self.load(keyring_data)
      keyring = Keyring.new
      begin
        candidate_keys = JSON.parse(keyring_data)
        unless candidate_keys.respond_to? :each
          raise InvalidKeyring, "does not respond to each"
        end
        candidate_keys.each_with_index do |k|
          created_at = unless k["created_at"].nil?
                         Time.parse(k["created_at"])
                       end
          keyring.add_key(Key.new(k["id"], k["value"], created_at || Time.now))
        end
      rescue StandardError => e
        raise InvalidKeyring, e.message
      end
      keyring
    end

    def initialize
      @keys = []
    end

    def add_key(k)
      @keys << k
    end

    def drop_key(id_or_key)
      id = if id_or_key.is_a? Key
             id_or_key.id
           else
             id_or_key
           end
      @keys.reject! { |k| k.id == id.downcase }
    end

    def fetch(id)
      @keys.find { |k| k.id == id.downcase } or raise UnknownKey, id
    end

    def has_key?(id)
      !@keys.find { |k| k.id == id.downcase }.nil?
    end

    def current_key
      k = @keys.sort_by(&:created_at).last
      if k.nil?
        raise KeyringEmpty, "No keys in keyring"
      end
      k
    end

    def digests(data)
      keys.map { |k| k.digest(data) }
    end

    def to_json
      @keys.to_json
    end
  end
end
