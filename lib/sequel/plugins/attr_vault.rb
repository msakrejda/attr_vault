require 'sequel'

module Sequel
  module Plugins
    module AttrVault
      def self.apply(model, opts={})
        model.extend ::AttrVault::ClassMethods
        model.include ::AttrVault::InstanceMethods
      end
    end
  end
end
