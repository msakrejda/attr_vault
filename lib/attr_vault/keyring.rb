module AttrVault
  class Key
    attr_reader :id, :value, :created_at

    def initialize(id, value, created_at=nil)
      if id.nil?
        raise InvalidKey, "key id required"
      end
      if value.nil?
        raise InvalidKey, "key value required"
      end
      begin
        id = Integer(id)
      rescue
        if created_at.nil?
          raise InvalidKey, "key created_at required"
        end
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
        candidate_keys = JSON.parse(keyring_data, symbolize_names: true)

        case candidate_keys
        when Array
          candidate_keys.each do |k|
            created_at = Time.parse(k[:created_at]) if k.has_key?(:created_at)
            keyring.add_key(Key.new(k[:id], k[:value], created_at || Time.now))
          end
        when Hash
          candidate_keys.each do |key_id, key|
            keyring.add_key(Key.new(key_id.to_s, key))
          end
        else
          raise InvalidKeyring, "Invalid JSON structure"
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
      @keys.reject! { |k| k.id == id }
    end

    def fetch(id)
      @keys.find { |k| k.id == id } or raise UnknownKey, id
    end

    def has_key?(id)
      !@keys.find { |k| k.id == id }.nil?
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
      if @keys.all? { |k| k.created_at.nil? }
        @keys.each_with_object({}) do |k,obj|
          obj[k.id] = k.value
        end.to_json
      else
        # Assume we are dealing with a legacy keyring
        @keys.to_json
      end
    end
  end
end
