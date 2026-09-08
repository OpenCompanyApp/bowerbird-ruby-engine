# This is an allowlist, not a gembox: adding a dependency changes the guest's
# compatibility and capability contract and requires a security review.
MRuby::Build.new('host') do |conf|
  conf.toolchain :gcc
  conf.gem core: 'mruby-compiler'
  conf.gem core: 'mruby-bin-mrbc'
end

MRuby::Build.new('guest') do |conf|
  conf.toolchain :gcc
  conf.cc.defines += %w[MRB_NO_STDIO MRB_USE_DEBUG_HOOK MRB_INT64 MRB_STACK_MAX=65536]
  conf.cc.flags << '-fPIC'
  %w[mruby-compiler mruby-bigint mruby-array-ext mruby-hash-ext
     mruby-string-ext mruby-enum-ext mruby-numeric-ext
     mruby-range-ext mruby-proc-ext mruby-error].each do |name|
    conf.gem core: name
  end
end
