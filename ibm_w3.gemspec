# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ibm_w3/version'

Gem::Specification.new do |spec|
  spec.name          = "ibm_w3"
  spec.version       = IBMW3::VERSION
  spec.authors       = ["Mateus Pinheiro", "Vinicius Stigliani"]
  spec.email         = ["mateus.pinheiro@gmail.com", "viniciusstigliani@gmail.com"]

  spec.summary       = "Connect to IBM's internal W3 and Authenticate"
  spec.description   = "Provides an LDAP adapter to login to IBM's internal LDAP server"
  spec.homepage      = "https://github.com/mateusnroll/ibm_w3"
  spec.license       = "MIT"

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata['allowed_push_host'] = "TODO: Set to 'http://mygemserver.com'"
  else
    raise "RubyGems 2.0 or newer is required to protect against " \
      "public gem pushes."
  end

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.14"
  spec.add_development_dependency "rake", "~> 10.0"

  spec.add_dependency 'ruby-ldap', '~> 0.9.19'
end
