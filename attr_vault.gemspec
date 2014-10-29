require File.expand_path('../lib/attr_vault/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Maciek Sakrejda"]
  gem.email         = ["m.sakrejda@gmail.com"]
  gem.description   = %q{Encryption at rest made easy}
  gem.summary       = %q{Sequel plugin for encryption at rest}
  gem.homepage      = "https://github.com/deafbybeheading/attr_vault"

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.name          = "attr_vault"
  gem.require_paths = ["lib"]
  gem.version       = AttrVault::VERSION
  gem.license       = "MIT"

  gem.add_runtime_dependency 'fernet', '~> 2.1'

  gem.add_development_dependency "rspec", '~> 3.0'
  gem.add_development_dependency "pg"
  gem.add_development_dependency "sequel", '~> 4.13.0'
end