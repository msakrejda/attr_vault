[![Build Status](https://travis-ci.org/uhoh-itsmaciek/attr_vault.svg)](https://travis-ci.org/uhoh-itsmaciek/attr_vault)

# AttrVault

Simple encryption-at-rest plugin for
[Sequel](https://github.com/jeremyevans/sequel.git).


N.B.: AttrVault is *not* for encrypting passwords--for that, you
should use something like
[bcrypt](https://github.com/codahale/bcrypt-ruby). It's meant for
encrypting sensitive data you will need to access in
plaintext. Passwords do not fall in that category.


### Philosophy

Sensitive data should be encrypted at rest. Data breaches are common,
and while preventing the breach in the first place is preferable,
defense in depth is a wise strategy.

AttrVault encrypts your data in-application, so your encryption keys
are never sent to the database. It includes an HMAC, so you can be
confident the data was not tampered with.

AttrVault is also designed with key rotation in mind. It relies on a
keyring of keys, always using the newest one for encryption, and
supporting decryption with any available key. It tracks which data was
encrypted with which key, making it easy to age out keys when needed
(e.g., on an employee departure).


### Keyring

Keys are managed through a keyring--a short JSON document describing
your encryption keys. The keyring must be a JSON object mapping
numeric ids of the keys to the key values. A keyring must have at
least one key. For example:

```json
{
  "1": "PV8+EHgJlHfsVVVstJHgEo+3OCSn4iJDzqJs55U650Q=",
  "2": "0HyJ15am4haRsCyiFCxDdlKwl3G5yPNKTUbadpaIfPI="
}
```

The `id` is used to track which key encrypted which piece of data; a
key with a larger id is assumed to be newer. The `value` is the actual
bytes of the encryption key, used for encryption and verification: see
below.


### Encryption and verification

The encryption mechanism in AttrVault is borrowed from another
encryption library, [Fernet](https://github.com/fernet). The encrypted
payload format is slightly different: AttrVault drops the TTL (almost
never useful for data at rest) and the Base64 encoding (since most
modern databases can deal with binary data natively).

The key should be 32 bytes of random data, base64-encoded. A simple
way to generate that is:

```console
$ dd if=/dev/urandom bs=32 count=1 2>/dev/null | openssl base64
```

Include the result of this in the `value` section of the key
description in the keyring. Half this key is used for encryption, and
half for the HMAC.


### Usage

N.B.: AttrVault depends on the `Sequel::Model#before_save` hook. If
you use this in your model, be sure to call `super`!

First generate a key as above.

#### General schema changes

AttrVault needs some small changes to your database schema. It
requires a key identifier column for each model that uses encrypted
fields, and a binary data column for each field.

Here is a sample Sequel migration for adding encrypted fields to
Postgres, where binary data is stored in `bytea` columns:

```ruby
Sequel.migration do
  change do
    alter_table(:diary_entries) do
      add_column :key_id, :integer
      add_column :secret_stuff, :bytea
    end
  end
end
```


#### Encrypted fields

AttrVault needs some configuration in models as well. A
`vault_keyring` attribute specifies a keyring in JSON (see the
expected format above). Then, for each field to be encrypted, include
a `vault_attr` attribute with its desired attribute name. You can
optionally specify the name of the encrypted column as well (by
default, it will be the field name suffixed with `_encrypted`):

```ruby
class DiaryEntry < Sequel::Model
  vault_keyring ENV['ATTR_VAULT_KEYRING']
  vault_attr :body, encrypted_field: :secret_stuff
end
```

AttrVault will generate getters and setters for any `vault_attr`s
specified.


#### Lookups

One tricky aspect of encryption is looking up records by known secret.
E.g.,

```ruby
DiaryEntry.where(body: '@SwiftOnSecurity is dreamy')
```

is trivial with plaintext fields, but impossible with the model
defined as above.

AttrVault includes a way to mitigate this. Another small schema change:

```ruby
Sequel.migration do
  change do
    alter_table(:diary_entries) do
      add_column :secret_digest, :bytea
    end
  end
end
```

Another small model definition change:

```ruby
class DiaryEntry < Sequel::Model
  vault_keyring ENV['ATTR_VAULT_KEYRING']
  vault_attr :body, encrypted_field: :secret_stuff,
    digest_field: :secret_digest
end
```

To be continued...

(storing digests is implemented, easy lookup by digest is not)

#### Migrating unencrypted data

If you have plaintext data that you'd like to start encrypting, doing
so in one shot can require a maintenance window if your data volume is
large enough. To avoid this, AttrVault supports online migration via
an "encrypt-on-write" mechanism: models will be read as normal, but
their fields will be encrypted whenever the models are saved. To
enable this behavior, just specify where the unencrypted data is
coming from:

```ruby
class DiaryEntry < Sequel::Model
  vault_keyring ENV['ATTR_VAULT_KEYRING']
  vault_attr :body, encrypted_field: :secret_stuff,
    migrate_from_field: :please_no_snooping
end
```

It's safe to use the same name as the name of the encrypted attribute.


#### Key rotation

Because AttrVault uses a keyring, with access to multiple keys at
once, key rotation is fairly straightforward: if you add a key to the
keyring with a higher id than any other key, that key will
automatically be used for encryption. Any keys that are no longer in
use can be removed from the keyring.

To check if an existing key with id 123 is still in use, run:

```ruby
DiaryEntry.where(key_id: 123).empty?
```

If this is true, the key with that id can be safely removed.

For a large dataset, you may want to index the `key_id` column.


### Contributing

Patches are warmly welcome.

To run tests locally, you'll need a `DATABASE_URL` environment
variable pointing to a database AttrVault may use for testing. E.g.,

```console
$ createdb attr_vault_test
$ DATABASE_URL=postgres:///attr_vault_test bundle exec rspec
```

Please follow the project's general coding style and open issues for
any significant behavior or API changes.

A pull request is understood to mean you are offering your code to the
project under the MIT License.


### License

Copyright (c) 2014-2015 AttrVault Contributors

MIT License. See LICENSE for full text.
