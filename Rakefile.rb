# encoding: UTF-8

require 'rubygems'
require 'rdoc/task'
require 'rake/testtask'
require 'rubygems/package_task'

spec = Gem::Specification.new do |s|
  s.name       = "nflog"
  s.version    = "1.0.1"
  s.author     = "Guillaume Delugré"
  s.email      = "guillaume AT security-labs DOT org"
  s.homepage   = "http://github.com/gdelugre/ruby-nflog"
  s.platform   = Gem::Platform::RUBY
  s.licenses   = [ "GPL" ]
  
  s.summary    = "nflog is a simple wrapper around libnetfilter_log using FFI."
  s.description = <<DESC
nflog is a wrapper around libnetfilter_log that allows you to capture packets using the NFLOG target of netfilter.
DESC

  s.files             = FileList[
    'README.md', 'COPYING', "{lib}/**/*", "{samples}/**/*"
  ]

  s.require_path      = "lib"
  s.has_rdoc          = true
  s.requirements      = "Support for NFLOG in your Linux kernel, libnetfilter_log installed and Ruby FFI"

  s.add_dependency('ffi', '>= 0')
  s.add_dependency('nfnetlink', '>=0')
end

task :default => [:package]

Gem::PackageTask.new(spec) do |pkg|
  pkg.need_tar = true
end

