# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth-simple-api-ift/version'

Gem::Specification.new do |spec|
  spec.name          = "omniauth-simple-api-ift"
  spec.version       = Omniauth::SimpleApiIft::VERSION
  spec.authors       = ["Timm Liu"]
  spec.email         = ["tliu@blueskybroadcast.com"]
  spec.summary       = %q{SimpleApiIft Omniauth Gem}
  spec.description   = %q{SimpleApiIft Ominauth gem using oauth2 specs}
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency 'builder'
  spec.add_dependency 'nokogiri'
  spec.add_dependency 'omniauth', '~> 1.0'
  spec.add_dependency 'omniauth-oauth2', '~> 1.0'
  spec.add_dependency 'typhoeus'

  spec.add_development_dependency "bundler", "~> 1.6"
  spec.add_development_dependency "rake"
end
