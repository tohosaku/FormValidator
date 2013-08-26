# -*- encoding: utf-8 -*-
require File.expand_path('../lib/formvalidator/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Travis Whitton"]
  gem.email         = ["tinymountain@gmail.com"]
  gem.description   = %q{FormValidator is a Ruby port of Perl's Data::FormValidator library.}
  gem.summary       = %q{FormValidator is a Ruby port of Perl's Data::FormValidator library.}
  gem.homepage      = "http://grub.ath.cx/formvalidator/"

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.name          = "formvalidator"
  gem.require_paths = ["lib"]
  gem.version       = FormValidator::VERSION
  gem.has_rdoc      = true
  gem.rdoc_options  = ["--main", "README.rdoc"]
  gem.extra_rdoc_files = ["README.rdoc"]
  gem.test_files    = %w{tests/regress.rb}
  gem.add_development_dependency "rspec"
end
