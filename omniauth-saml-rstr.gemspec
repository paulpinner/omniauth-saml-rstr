require File.expand_path('../lib/omniauth-saml-rstr/version', __FILE__)

Gem::Specification.new do |gem|
  gem.name          = "omniauth-saml-rstr"
  gem.version       = OmniAuth::SAML_RSTR::VERSION
  gem.summary       = %q{A RequestSecurityTokenResponse for ADFS strategy based on https://github.com/PracticallyGreen/omniauth-saml.}
  gem.description   = %q{A RequestSecurityTokenResponse for ADFS strategy based on https://github.com/PracticallyGreen/omniauth-saml.}

  gem.authors       = ["Josh Skeen"]
  gem.email         = "josh@highgroove.com"
  gem.homepage      = "https://github.com/mutexkid/omniauth-saml-rstr"

  gem.add_runtime_dependency 'omniauth', '~> 1.0'
  gem.add_runtime_dependency 'xmlcanonicalizer', '0.1.1'
  gem.add_runtime_dependency 'uuid', '~> 2.3'

  gem.add_development_dependency 'guard', '1.0.1'
  gem.add_development_dependency 'guard-rspec', '0.6.0'
  gem.add_development_dependency 'rspec', '2.8'
  gem.add_development_dependency 'simplecov', '0.6.1'
  gem.add_development_dependency 'rack-test', '0.6.1'
  gem.add_development_dependency 'nokogiri', '1.5.5'

  gem.files         = ['README.md'] + Dir['lib/**/*.rb']
  gem.test_files    = Dir['spec/**/*.rb']
  gem.require_paths = ["lib"]
end
