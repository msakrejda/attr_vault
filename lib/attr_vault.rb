require 'attr_vault/errors'
require 'attr_vault/keyring'
require 'attr_vault/secret'
require 'attr_vault/encryption'
require 'attr_vault/cryptor'

module AttrVault
  def self.included(base)
    base.extend(ClassMethods)
    base.include(InstanceMethods)
  end

  module InstanceMethods
    def before_save
      keyring = self.class.vault_keys
      current_key = keyring.current_key
      key_id = self[self.class.vault_key_field]
      record_key = self.class.vault_keys.fetch(key_id) unless key_id.nil?

      @vault_dirty_attrs ||= {}
      if !record_key.nil? && current_key != record_key
        # If the record key is not nil and not current, flag *all*
        # attrs as dirty, since we want to rewrite them all in order
        # to use the latest key. Note that when the record key is nil,
        # we're dealing with a new record, so there are no existing
        # vault attributes to rewrite. We only write these out when
        # they're set explicitly in a new record, in which case they
        # will be in the dirty attrs already and are handled below.
        self.class.vault_attrs.each do |attr|
          @vault_dirty_attrs[attr.name] ||= self.send(attr.name)
        end
      end
      # If any attr has migrate_from_field and the plaintext field
      # has a value set, flag the attr as dirty using the plaintext
      # source value, then nil out the plaintext field. Skip any
      # attributes that are already dirty.
      self.class.vault_attrs.reject { |attr| attr.migrate_from_field.nil? }.each do |attr|
        unless self[attr.migrate_from_field].nil?
          @vault_dirty_attrs[attr.name] ||= self[attr.migrate_from_field]
          self[attr.migrate_from_field] = nil
        end
      end
      self.class.vault_attrs.each do |attr|
        next unless @vault_dirty_attrs.has_key? attr.name

        value = @vault_dirty_attrs[attr.name]
        encrypted = Cryptor.encrypt(value, current_key.value)

        self[attr.encrypted_field] = encrypted
        unless attr.digest_field.nil?
          if value.nil?
            self[attr.digest_field] = nil
          else
            self[attr.digest_field] =
              Sequel.blob(Encryption.hmac_digest(current_key.value, value))
          end
        end
      end
      self[self.class.vault_key_field] = current_key.id
      @vault_dirty_attrs = {}
      super
    end
  end

  module ClassMethods
    def vault_keyring(keyring_data, key_field: :key_id)
      @key_field = key_field.to_sym
      @keyring = Keyring.load(keyring_data)
    end

    def vault_digests(data)
      @keyring.digests(data).map { |d| Sequel.blob(d) }
    end

    def vault_attr(name, opts={})
      attr = VaultAttr.new(name, opts)
      self.vault_attrs << attr

      define_method(name) do
        @vault_dirty_attrs ||= {}
        if @vault_dirty_attrs.has_key? name
          return @vault_dirty_attrs[name]
        end
        # if there is a plaintext source field, use that and ignore
        # the encrypted field
        if !attr.migrate_from_field.nil? && !self[attr.migrate_from_field].nil?
          return self[attr.migrate_from_field]
        end

        keyring = self.class.vault_keys
        key_id = self[self.class.vault_key_field]
        if key_id.nil?
          # if there is no recorded key, this is not an encrypted
          # record so we return nil
          return nil
        end
        record_key = self.class.vault_keys.fetch(key_id)

        encrypted_value = self[attr.encrypted_field]
        # TODO: cache decrypted value
        Cryptor.decrypt(encrypted_value, record_key.value)
      end

      define_method("#{name}=") do |value|
        @vault_dirty_attrs ||= {}
        @vault_dirty_attrs[name] = value
        # ensure that Sequel knows that this is in fact dirty and must
        # be updated--otherwise, the object is never saved,
        # #before_save is never called, and we never store the update
        self.modified! attr.encrypted_field
        unless attr.digest_field.nil?
          self.modified! attr.digest_field
        end
      end
    end

    def vault_attrs
      @vault_attrs ||= []
    end

    def vault_key_field
      @key_field
    end

    def vault_keys
      @keyring
    end
  end

  class VaultAttr
    attr_reader :name, :encrypted_field, :migrate_from_field,
                :migrate_from_kind, :digest_field

    def initialize(name,
                   encrypted_field: "#{name}_encrypted",
                   migrate_from_field: nil,
                   migrate_from_kind: :plaintext,
                   digest_field: nil)
      @name = name
      @encrypted_field = encrypted_field.to_sym
      @migrate_from_field = migrate_from_field.to_sym unless migrate_from_field.nil?
      unless migrate_from_kind == :plaintext
        raise ArgumentError, "Unknown migration kind: #{migrate_from_kind}"
      end
      @migrate_from_kind = migrate_from_kind
      @digest_field = digest_field.to_sym unless digest_field.nil?
    end
  end
end
