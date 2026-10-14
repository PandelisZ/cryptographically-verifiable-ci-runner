# Spike: Rails dependency collection (`vci_collector.rb`), Minitest and RSpec

Date: 2026-10-01. macOS arm64 (Darwin 25.6). Ruby 3.4.9 (`3.4.9p82`, through mise), Bundler 4.0.9, RubyGems 3.6.9,
Rails 8.1.3.1, Minitest 6.0.6, Zeitwerk 2.8.3, `sqlite3` 2.9.6 (SQLite 3.53.2), `tzinfo-data` 1.2026.5. Fixture:
`fixtures/rails-abcd`. Collector: `ruby/vci-collector/vci_collector.rb`; its tests:
`ruby/vci-collector/test/collector_test.rb`. A cross-platform check used the `ruby:3.4.9` image (`linux/amd64`, Debian)
in OrbStack with a static `x86_64-unknown-linux-musl` `vci`.

## How it collects

The Rust adapter runs one process per test file:

```
RUBYOPT=-r<abs>/ruby/vci-collector/vci_collector.rb VCI_RAILS_MODE=collect VCI_OUT=<dir> VCI_TEST_ID=<file> \
  VCI_ROOT=<project> VCI_REPO=<repo> VCI_DB_DIR=<fresh dir> TMPDIR=<fresh dir> RAILS_ENV=test RACK_ENV=test \
  PARALLEL_WORKERS=1 DISABLE_SPRING=1 DISABLE_BOOTSNAP=1 BUNDLE_GEMFILE=<project>/Gemfile \
  ruby bin/rails test test/models/b_test.rb --seed 0
```

`RUBYOPT=-r` is processed after RubyGems' prelude and before the script, so the collector is loaded before
`bin/rails`, `config/boot.rb` (`bundler/setup`), Rails and the test file. It requires nothing that is a gem while the
tests run (a default gem such as `json` or `set` required that early would be activated in its default version and
clash with the bundle's); it writes its JSONL by hand and requires `digest/sha2`, `rubygems/package` and `zlib` only at
exit. Output is written by the first `at_exit` handler registered, which runs last (after Minitest's, which
registers its own when `minitest/autorun` loads and an inner one while it runs), and only in the process vci started
(a forked child inherits the collector).

## Findings

**F1. Ruby has no audit hook: wrap the entry points, and verify each one.** Hooks (all checked by the collector tests
or the fixture runs):

| Entry point | Mechanism |
|---|---|
| `File.open`/`new`, `Kernel#open`, `File.read`/`binread`/`readlines`/`foreach`, `IO.read`/..., `IO.sysopen`, `IO.copy_stream`, `IO#reopen`, `Zlib::GzipReader.open` | `File#initialize` prepended (`File.open`, `File.new` and `Kernel#open(path)` all dispatch to it); `IO`'s singleton class prepended (`File.read` finds it through `File`'s singleton class); `IO#reopen`, Zlib (`rb_file_open_str` in C) wrapped separately |
| `Pathname#read`, `#exist?`, `#children`, `#glob`, `#realpath`, ... | nothing extra: `pathname.so` calls `File`, `FileTest` and `Dir` through method dispatch (verified: `Pathname#read` and `#exist?` are recorded) |
| `File.exist?`/`file?`/`directory?`/`size`/`stat`/`lstat`/`mtime`/`readlink`/... and `FileTest.*` | both singleton classes prepended (FileTest's functions are separate method entries); `Kernel#test(?e, p)` (C) wrapped |
| `Dir.glob`, `Dir[]`, `Dir.children`/`entries`/`each_child`/`foreach`, `Dir.new`/`open`, `Dir.exist?`/`empty?` | prepended (`Dir.open` separately: Ruby 3.4's builds the `Dir` in C without `Dir#initialize`); a glob records the listing of every directory its pattern reads (braces expanded, `**` walked like `Dir.glob`: no symlinked or dot directories) and every literal path it checks |
| `File::Stat.new`, `File.realpath`/`realdirpath` (every component inside the repository) | prepended |
| writes: `File.delete`/`unlink`/`rename`/`symlink`/`link`/`chmod`/`utime`/`truncate`, `Dir.mkdir`/`rmdir`, opens for writing, `IO.write` | prepended; once the process created or truncated a file (or renamed its own file onto it) it is its own output: reads after that are not inputs, reads before it are |
| `require`, `load` | **aliased** in `Kernel` (see F2), not prepended |
| every Ruby file compiled from disk | `TracePoint(:script_compiled)` (`require`, `require_relative`, `load`, `autoload`, Zeitwerk); `RubyVM::InstructionSequence.compile_file` (no event) wrapped |
| failed lookups | `TracePoint(:raise)` on `LoadError` (`LoadError#path`) |
| `ENV` | its singleton class prepended: key reads, and every method that walks it |
| processes | `Kernel#system`/`spawn`/`exec`/`` ` ``/`open("\|cmd")` (and `Kernel.`'s copies), `Process.spawn`/`exec`/`daemon`, `Process._fork` (every fork, Ruby 3.1+), `IO.popen`, `PTY.spawn` |
| network | `TCPSocket`, `TCPServer`, `UDPSocket`, `UNIXSocket`, `UNIXServer`, `Socket` constructors, `Socket.tcp`/`getaddrinfo`/..., `Addrinfo.getaddrinfo`/... |
| native code | `Fiddle::Handle` and `Fiddle::Function` (so `Fiddle.dlopen(nil)` too), FFI `ffi_lib`/`attach_function`/`DynamicLibrary.open`/`Function`, libxml2 options and APIs that read files, a `.so`/`.bundle` inside the repository in `$LOADED_FEATURES` |
| file descriptors | `IO.for_fd`/`IO.new(fd)`/`File.new(fd)`: accepted when `fstat` gives the dev/inode of a file a hook saw opened |
| SQLite | `SQLite3::Database#initialize`: a file outside `VCI_DB_DIR`/`TMPDIR` taints; an authorizer taints `ATTACH`; extension loading taints |

What is not seen (documented in the README): C code opening paths itself (libxml2 entity resolution, image
libraries, `Etc.getpwuid` reading the user database), `getenv` in C, `/etc/localtime`, threads still running after the
collector wrote its output.

**F2. `Kernel.prepend` breaks under Bundler.** The first version prepended a module to `Kernel` for `require`. Ruby
3.4's `bundled_gems.rb` (`Gem::BUNDLED_GEMS.replace_require`, run by `bundler/setup`) does
`Kernel.singleton_class.send(:alias_method, :no_warning_require, :require)`, which copied the prepended method into
`#<Class:Kernel>`, where its `super` has nothing to call:

```
There was an error while trying to load the gem 'railties'. (Bundler::GemRequireError)
Gem Load Error is: super: no superclass method 'require' for class #<Class:Kernel>
```

`Kernel` is now patched the way RubyGems, `bundled_gems.rb` and Zeitwerk patch it: `alias_method` + redefinition,
calling the alias by name. Later patchers (Zeitwerk's `Kernel#require`) alias ours in turn, so every `require` still
passes through it; `autoload` calls `Kernel#require` by method dispatch, so autoloads (and Zeitwerk's) do too.

**F2b. Under Bundler, a plain `require` goes through `Kernel.require`, not `Kernel#require`.** `replace_require`
redefines `Kernel#require` as `kernel_class.send(:no_warning_require, name)` with `kernel_class` = `::Kernel`: that
calls `Kernel`'s singleton method, the alias of `Kernel.require` (the module function's own copy, C). With only
`Kernel#require` patched, every `require` in the application and its tests after `bundler/setup` skipped the
collector: no shadowing probes, and `PTY`, Fiddle, FFI and database clients required lazily were never hooked (found
by adversarial review). Both copies are now patched, and hooks are also installed whenever a watched constant is
defined (`Module#const_added`, called for constants defined in C too) and after every compiled file; a library
loaded but never hooked refuses the file. `collector_test.rb` runs a script under a real `bundler/setup`.

**F3. Lookups: the hit is `$LOADED_FEATURES.last`.** Ruby appends a feature after loading it (nested requires come
first), and searches `$LOAD_PATH` entry by entry, trying `.rb` then the platform's `DLEXT` in each
(`rb_find_file_ext`). For a `require "x"` that loaded something, every repository `$LOAD_PATH` entry before the one
holding the hit gets `x.rb`, `x.so`, `x.bundle` as probes (both native suffixes, so an attestation made on macOS also
notices a Linux `.so`). The Rails test command appends `test/` to `$LOAD_PATH` before loading the test file, so a
failed `require` reaches it: `Bundler.require(*Rails.groups)` tries `require "railties"` (no such file in that gem) and
rescues the `LoadError`, which records `test/railties.rb` as absent: creating it would be loaded. The same for
`concurrent-ruby`'s optional `concurrent/concurrent_ruby_ext` and TZInfo's `tzinfo/data`. b's record has 52 probes.

**F4. Zeitwerk lists directories, lazily.** At boot it lists the top level of every autoload root (`Dir.children`:
`app/models`, `app/controllers`, `lib` with `config.autoload_lib`) and defines autoloads; a subdirectory (a namespace)
is listed when the namespace is first used. Rails lists `app/` to find the roots. These listings are inputs, so a new
file in `app/models` runs every test that boots Rails. The e2e test adds `app/models/calc.rb` defining `Calc`, which
takes over the `Calc` of `lib/calc.rb` (an earlier root wins); a's attestation fails on `entry:app/models`.

**F5. ENV is read by RubyGems, Bundler and Rails at boot, and enumerated twice.** Without attribution b's record had
`PATH`, `HOME`, `GEM_HOME`, `GEM_PATH`, `RUBYOPT`, `BUNDLER_ORIG_*`, ... (from `rubygems/defaults.rb`,
`rubygems/path_support.rb`, `bundler/shared_helpers.rb`), and three enumerations:

```
{"kind":"env","key":"*","where":"to_hash at .../bundler-4.0.9/lib/bundler/environment_preserver.rb"}
{"kind":"env","key":"*","where":"replace at .../bundler-4.0.9/lib/bundler/environment_preserver.rb"}
{"kind":"env","key":"*","where":"to_h at .../bundler-4.0.9/lib/bundler/settings.rb"}
```

`EnvironmentPreserver.from_env` copies `ENV.to_hash` to restore it for child processes and `replace_with_backup` adds
`BUNDLER_ORIG_*` copies; `Settings` keeps `ENV.to_h` to look up `BUNDLE_*` settings. Those two call sites (and only
those methods) are allowed; `Bundler.with_original_env` called by a test enumerates through `bundler.rb` and refuses
the file. Reads by RubyGems' and Bundler's own files (`<rubylibdir>/rubygems*`, `bundled_gems.rb`, the Bundler
gem's `lib/`) of their own variables (`HOME`, `PATH`, `GEM_*`, `BUNDLE_*`, `BUNDLER_*`, `RUBYOPT`, `XDG_*`, ...) are
dropped, as are their existence checks outside the repository (`~/.gem`, `~/.gem/specs`, `HOME`, `~/.bundle/config`);
their content reads are kept (a gemspec outside the bundle loaded as code refuses). What remains for b, all read by
Rails, Rack, Minitest, Thor or optparse: `RAILS_ENV`, `DATABASE_URL`, `PRIMARY_DATABASE_URL`, `RAILS_MASTER_KEY`,
`SECRET_KEY_BASE`, `SECRET_KEY_BASE_DUMMY`, `SCHEMA`, `VERBOSE`, `RACK_*`, `MT_CPU`, `MINITEST_SERVER`,
`MT_NO_SKIP_MSG`, `NO_FORK`, `THOR_SHELL`, `POSIXLY_CORRECT`, `PRISM_FFI_BACKEND`, `RUBY` (rake), `RAILS_TEST_*`,
`BUNDLE_GEMFILE` (`config/boot.rb`). In strict mode they are unset on both sides.

**F6. Rails shells out to prepare the test database.** `rails/test_help` calls
`ActiveRecord::Migration.maintain_test_schema!`; when the schema's SHA-1 differs from `ar_internal_metadata`'s,
`load_schema!` runs `system("bin/rails db:test:prepare")` (activerecord 8.1.3.1, `migration.rb` line 782): a child
process, and the database keeps whatever earlier runs left in it. The collector therefore (in every mode):

- prepends `Rails::Application::Configuration#database_configuration` and points every SQLite database of the test
  environment at a fresh file in `VCI_DB_DIR` (one file per configured file, so a replica stays the same database);
- registers `ActiveSupport.on_load(:after_initialize)` (after `initialize!`, before `rails/test_help`) and loads the
  schema into each one with `ActiveRecord::Tasks::DatabaseTasks.load_schema` (`structure.sql` for SQLite through
  `execute_batch2`, since Rails would run the `sqlite3` tool), which records the schema SHA-1, so
  `maintain_test_schema!` finds nothing to do. A plain first run of the fixture took 1.25 s (the `db:test:prepare`
  child) and later ones 0.49 s; with the collector 0.72 s (collect) and 0.50 s (plain).

A database server is purged (`DatabaseTasks.purge`) and loaded the same way with `policy.rails_allow_db`; a test of
the waiver uses SQLite registered under another adapter name (`ActiveRecord::ConnectionAdapters.register("vcifake",
...)`), whose `database_version` gives the "server" version.

**F7. Rails keeps a random secret in `tmp/`.** Rails 8.1's `Configuration#secret_key_base` falls back to
`generate_local_secret` in development and test, which writes a random `tmp/local_secret.txt` once and reads it
afterwards. Every later run of an integration test would record that random file as an input, which no CI checkout
has. The collector replaces `generate_local_secret` with an in-memory random value per process: what a fresh checkout
does.

**F8. Logger reopens its file descriptor.** `logger` 1.7.0 (`log_device.rb`) does `File.new(dev.fileno, mode:, path:)`
and, at load, `File.new(f.fileno, autoclose: false, path: "")`. A first version tainted every `File.new(fd)`; the
collector now records the dev/inode of every file it saw opened and accepts an fd whose `fstat` matches one, or that
is not a regular file. An fd of a file opened unseen still refuses (tested with a file opened inside the collector's
quiet block).

**F9. Without `tzinfo-data`, TZInfo scans the system zone database.** At boot (`Time.zone_default`) TZInfo's
`ZoneinfoDataSource` stats `/usr/share/zoneinfo/iso3166.tab`, `zone.tab` and every zone file and directory (hundreds
of records), and probes `/usr/share/misc/iso3166.tab`. These are not recorded; the toolchain records the data source
instead: `tz=zoneinfo 2026c` (`+VERSION` on macOS, the `# version` line of `tzdata.zi` on Linux) or `tz=tzinfo-data`
when the gem is in the bundle (then nothing outside the gem is read). Different system versions run everything, so
the fixture uses `tzinfo-data`.

**F10. Rails looks for `config.ru` above the application.** `Rails::Application.find_root` walks up from
`config/application.rb`'s directory testing `config.ru`; without one it probed every ancestor up to `/` (paths
outside the repository, which refuse). The fixture has `config.ru`, as `rails new` creates.

**F11. Parallel testing forks unless `PARALLEL_WORKERS=1`.** A test class with `parallelize(workers: 2, threshold:
0)` run with `PARALLEL_WORKERS=2` and the collector:

```
{"kind":"taint","reason":"network:UNIXServer.new"}
{"kind":"taint","reason":"process:fork"}
```

(DRb's server for the workers, then the forks). With vci's `PARALLEL_WORKERS=1` (`parallelize` takes the variable over
its argument) the same file is attested: no fork happened, or the taint would be there.

**F12. Installed gems can be checked against their archives.** The RubyGems cache held the `.gem` of every gem of
the fixture's bundle (Ruby 3.4.9 from mise; 285 archives). For every gem a test used, the collector compares the
archive's sha256 with `Gemfile.lock`'s `CHECKSUMS` and every used file with the archive's `data.tar.gz` entry.
Installing hashids into a separate `GEM_PATH` and appending a comment to its `lib/hashids.rb`:

```
{"kind":"taint","reason":"ruby:gem-modified:hashids-1.0.6:lib/hashids.rb (differs from hashids-1.0.6.gem)"}
```

(The whole collector, this check included, adds about 0.2 s to each of the fixture's processes: F6.)

**F13. RubyGems reads every gemspec.** RubyGems' bookkeeping reads `specifications/*.gemspec` of every installed gem
(not only the bundle's). Only code loaded from an installed gem outside the bundle refuses; other reads under the gem
directories are not inputs.

**F14. macOS to Linux.** Attestations of the fixture made on macOS arm64 and checked by the Linux `vci` in the
`ruby:3.4.9` container (non-root, `bundle config set --local path vendor/bundle` like `setup-ruby`'s
`bundler-cache`, `TZ=UTC`) failed in turn on:

1. `ruby libraries`: `openssl=OpenSSL 3.6.4` (Homebrew) vs `OpenSSL 3.5.6` (Debian). OpenSSL is no longer compared;
2. `entry:vendor`: Rails tests whether `vendor` exists; the fixture lacked the `vendor/.keep` that `rails new`
   creates, so `vendor/bundle` made it exist only in CI. With `vendor/.keep` only its type is recorded;
3. `env:TMPDIR`: something reads `TMPDIR`, which vci sets to a fresh directory per process; it is no longer hashed.

Then all four files were skipped; editing the view template in the container ran c only, and `TZ=Europe/London` ran
everything. The SQLite library (3.53.2), libyaml (0.2.5), encodings, Ruby, Rails, Bundler, Minitest and the bundle
matched without changes.

**F15. Minitest results.** A reporter added through `Minitest.register_plugin` counts results; `state` is `passed`
only with exit status 0, at least one test, no failure, error or skip, and at least one assertion in every test
(Rails prints "Test is missing assertions" but passes such a test). `--seed 0` reaches Minitest through the Rails
runner (`Run options: --seed 0`).

## Output (as emitted)

`test/models/b_test.rb` of the fixture (root shortened to `R`, gem paths to `G`; 52 probes and most externals and
env keys omitted):

```
{"v":1,"kind":"meta","testId":"test/models/b_test.rb","adapter":"rails","ruby":"3.4.9p82","engine":"ruby 3.4.9","rails":"8.1.3.1","bundler":"4.0.9","runner":"minitest 6.0.6","root":"R","platform":"arm64-darwin25","collector":"vci_collector@0.1.0","db":"sqlite3","tz":"tzinfo-data"}
{"kind":"module","path":"R/config/application.rb"}
{"kind":"read","path":"R/Gemfile.lock"}
{"kind":"probe","path":"R/test/railties.rb"}
{"kind":"readdir","path":"R/app/models"}
{"kind":"read","path":"R/config/database.yml"}
{"kind":"module","path":"R/db/schema.rb"}
{"kind":"readdir","path":"R/test/fixtures"}
{"kind":"read","path":"R/test/fixtures/widgets.yml"}
{"kind":"module","path":"R/app/models/gadget.rb"}
{"kind":"write","path":"R/log/test.log"}
{"kind":"external","name":"sqlite3","version":"2.9.6","platform":"arm64-darwin"}
{"kind":"external","name":"tzinfo-data","version":"1.2026.5","platform":"ruby"}
{"kind":"env","key":"DATABASE_URL","where":"G/activerecord-8.1.3.1/lib/active_record/database_configurations.rb"}
{"kind":"env","key":"TZ","where":"ruby"}
{"kind":"result","state":"passed","tests":2,"failed":0,"skipped":0,"assertions":4,"noAssertions":0,"durationMs":86,"exitStatus":0}
```

## RSpec

Date: 2026-10-02. Same machine and Ruby; rspec-core 3.13.6, rspec-expectations 3.13.5, rspec-mocks 3.13.8,
rspec-support 3.13.7, rspec-rails 8.0.4, factory_bot 6.6.0 / factory_bot_rails 6.5.1, simplecov 0.22.0. Fixture:
`fixtures/rails-rspec-abcd`; end-to-end tests: `crates/vci-cli/tests/e2e_rspec.rs`; collector tests:
`test_rspec_*` and `test_stubbed_file_methods_do_not_hide_real_reads` in `collector_test.rb`.

RSpec runs under the Rails adapter with the same collector, loaded the same way (`RUBYOPT=-r`), and
`VCI_RAILS_RUNNER=rspec`:

```
ruby -e 'require "bundler/setup"; require "rspec/core"; $0 = "rspec"; RSpec::Core::Runner.invoke' \
  -- --options .rspec spec/models/b_spec.rb
```

**R1. `$0` matters.** `Configuration#files_or_directories_to_run=` adds `default_path` only when `command`
(`$0`'s last component) is `rspec`. Under `ruby -e`, `$0` is `-e`, so a run with no file argument (the listing,
`vci ci` on `no_skip_refs`) found no file until the script set `$0 = "rspec"`. `bundler/setup` comes first, as in
`bundle exec`: `rspec/core` must be the bundle's.

**R2. Option files.** `ConfigurationOptions#file_options` reads `[global_options, project_options, local_options]`
(`$XDG_CONFIG_HOME/rspec/options` if it exists, else `~/.rspec`; `./.rspec`; `./.rspec-local`), **or only the file
`--options` names** when the command line has one (`custom_options_file` comes from the command line only, not from
`SPEC_OPTS`); `SPEC_OPTS` is parsed on top (`env_options`). A missing custom file reads as empty. vci therefore passes
`--options .rspec`: `.rspec` is read (and made a global input), the files outside the repository and `.rspec-local`
never are, in `vci run` and `vci ci` alike, so nothing has to be configured on the runner. Measured with the fixture:
`~/.rspec` holding `--tag focus` makes a plain run of a print `Run options: include {focus: true}` and `0 examples`;
`$XDG_CONFIG_HOME/rspec/options` holding `--require does_not_exist` makes it fail; `.rspec-local` holding `--tag slow`
filters it; under vci all three change nothing (the same inputs, the same storage key). A run without `--options` is
refused (`rspec:option-files`), and a read of `~/.rspec` would be a read outside the repository anyway.

**R3. Listing.** `ConfigurationOptions.new(["--options", ".rspec"]).configure(RSpec.configuration)` then
`files_to_run` gives what `rspec` would run: `default_path`, `pattern` and `exclude_pattern` from `.rspec` and
`SPEC_OPTS`, `--require`d files loaded (the fixture's `spec_helper`), a pattern starting with the default path used
as-is (`spec/**/*_spec.rb,test/**/*_test.rb` lists test files: in a project with both runners that is refused until
`runner` decides). Shared examples and support files do not match the pattern.

**R4. Results.** `RSpec::Core::Reporter` is prepended: `start`, `example_passed`, `example_failed` (also a fixed
`pending`), `example_pending` (`pending`, `skip`, `xit`, `xdescribe`), `notify_non_example_exception` (load errors
from `Configuration#load_file_handling_errors`, `before`/`after(:suite)` through `SuiteHookContext#set_exception`,
`after(:context)` from `hooks.rb`). The declared examples are `World#all_examples`, counted in a prepended
`World#announce_filters`, because it **clears `example_groups` when every example was filtered out**. A focused run
(`fit` with `filter_run_when_matching :focus`) reported `1 of 2 examples did not run (inclusion filter {focus:
true})`; `--only-failures` `(inclusion filter {last_run_status: "failed"}; only_failures)`; an excluded tag
`(exclusion filter {slow: true})`. `--bisect` forks (`process:fork`) and is an `options[:runner]`
(`Invocations::Bisect`), as are `--drb` (it also opens sockets), `--init`, `--version` and `--help`.

**R5. Seed.** `Ordering::ConfigurationManager#initialize` sets `@seed = rand(0xFFFF)`; `--seed`/`--order rand:N`
force it (`force`), `config.seed =` sets it unless forced, `config.order = :random` uses it. The collector sets the
default to 0 after `initialize` (and on a configuration created before its hook): `Randomized with seed 0` in every
run; the fixture's `Kernel.srand config.seed` gets 0.

**R6. The example status file.** `config.example_status_persistence_file_path=` is prepended to point at
`$TMPDIR/vci-rspec-example-statuses.txt` (vci's fresh dir). RSpec reads it lazily (`last_run_statuses`: for
`--only-failures` and `metadata[:last_run_status]`) and writes it at the end (`ExampleStatusPersister`), creating its
directory with rspec-support's `DirectoryMaker.mkdir_p`, which checks **every ancestor** of the temp dir: `/`,
`/private`, `/private/var/...` were recorded as stats outside the repository and refused every file. In RSpec
processes, type checks of directories above vci's temp dirs (outside the repository) are not inputs. A
`spec/examples.txt` left by a plain run is never read: the fixture's attested files stay skipped when it is edited, and
an example reading `last_run_status` sees `"unknown"`.

**R7. rspec-rails lists the whole spec tree at boot.** rspec-rails 8's `rspec_rails.code_statistics` initializer (Rails
>= 8.0) runs `Dir[Rails.root.join("spec", "**", "*_spec.rb")]` to register `bin/rails stats` directories. Recorded,
that made the listing of `spec/` and every subdirectory an input of every spec that boots Rails: a new spec file
anywhere ran all of them. The result only reaches `Rails::CodeStatistics` (`directories`, `test_types`), so the glob
is not recorded (matched by its caller, `rspec-rails-*/lib/rspec-rails.rb`) and reading those directories outside
`code_statistics.rb` refuses the file (`rails:code-statistics:`). Its `File.directory?` checks of the `spec/<type>`
directories it found are still recorded.

**R8. `maintain_test_schema!`.** The generated `rails_helper` calls it directly. With the schema loaded by the
collector after initialisation (F6) it finds nothing to do: no `bin/rails db:test:prepare` child. A migration newer
than the schema (`db/migrate/20261001120000_add_colour.rb`) makes `check_pending_migrations` raise
`ActiveRecord::PendingMigrationError` and `rails_helper` abort: refused as a load error, `db/` unchanged (a timestamp in
the future is rejected as `InvalidMigrationTimestampError`, also a load error).

**R9. Loading.** b records `spec/spec_helper.rb` (through `.rspec`'s `--require`, with its load path probes in `spec/`
and `lib/`, which RSpec adds to `$LOAD_PATH`), `spec/rails_helper.rb`, the listings `spec/support`,
`spec/support/matchers`, `spec/support/shared_examples` (from `Rails.root.glob("spec/support/**/*.rb")`, a
`Pathname#glob` that reaches `Dir.glob(..., base:)`), both support files, `spec/factories` (FactoryBot's
`find_definitions`: `File.exist?("spec/factories.rb")`, `File.directory?`, `Dir["spec/factories/**/*.rb"]`; and
`FactoryBotRails::Reloader`'s `FileUpdateChecker` glob) and `spec/factories/gadgets.rb`, `spec/fixtures/widgets.yml`,
`db/schema.rb`. factory_bot_rails loads the definitions in `after_initialize`, so c and d record them too. c records
`spec/fixtures/files/which.txt` and `alpha.txt` (not `beta.txt`) and the template. a records `.rspec`,
`spec/spec_helper.rb`, `spec/lib/a_spec.rb` and `lib/calc.rb` (`require_relative`): 65 inputs against b's 7515.

**R10. Toolchain.** a never loads Rails: the collector reported `rails ""` against the probe's `8.1.3.1` and every
such file was refused (`toolchain seen by the collector ... differs`). In RSpec processes the Rails version falls back
to the bundle's `railties` spec. The test framework string is built from the bundle's specs (`Gem.loaded_specs`, set up
by Bundler for the whole bundle), not from what a file loaded: `minitest 6.0.6; rspec-core 3.13.6, rspec-expectations
3.13.5, rspec-mocks 3.13.8, rspec-rails 8.0.4, rspec-support 3.13.7`, the same in the probe and every process. For the
Minitest fixture (no RSpec in its bundle) it is unchanged: `minitest 6.0.6`.

**R11. Stubs.** rspec-mocks' `allow(File).to receive(:read)` finds vci's prepended module defining `read` and
prepends its own module in front (`MethodDouble#usable_rspec_prepended_module`); the original it calls for
`and_call_original` is `File.method(:read)` taken before, i.e. vci's hook. `ENV`'s `[]` likewise. `Kernel.require`
stubbed does not affect plain `require`, which Bundler routes through `Kernel.no_warning_require` (F2b). The weak spot
was the collector itself: it checked the file system with `File.directory?`, `File.exist?`, `Dir.children` and
`File.expand_path`, so a test stubbing `File.directory?` to `false` made a real `Dir.glob` record no listing (shown
by running the new collector test against a copy using those methods: `Expected [] to include "data/g"`). The
collector now calls the C methods it captured at load (`VciCollector::Real`). This also covers Minitest's `File.stub`.

**R12. SimpleCov** (`require "simplecov"; SimpleCov.start` in `spec_helper`, tried in a copy of the fixture): every
file was refused for `input outside the repository: /Users/pz/.simplecov` (`load_global_config.rb` checks
`~/.simplecov`), then for `.simplecov` in every directory above the project (`defaults.rb` searches upward until it
finds one; `Pathname#exist?` asks `FileTest`, not `File`). In RSpec processes those files look absent (a `.simplecov`
in the repository is read and recorded), and `SimpleCov.coverage_path` is the process's `$TMPDIR/vci-coverage`, so the
`.resultset.json` it merges and `.last_run.json` never come from (or go to) `coverage/`: two consecutive `vci run`s of
the four files attested all four both times, and `vci ci` printed `Coverage report generated for RSpec to
.../vci-coverage`. SimpleCov is not part of the fixture; `test_rspec_simplecov_is_kept_out_of_the_repository` covers it
when the gem is installed.

**R13. Plain Ruby.** A project with only `rspec-core` and `rspec-expectations`, locked with `bundle lock --local`, was
refused for `wrote inside the repository: Gemfile.lock`: that lockfile (platform `arm64-darwin-25`, `CHECKSUMS` without
digests) is rewritten by every `require "bundler/setup"` (its mtime changed on a plain `ruby -e`). A complete lockfile
(the fixture's checksums, platforms `arm64-darwin`, `ruby`, `x86_64-linux-gnu`) is left alone, and the project is
attested and invalidated like the Rails one.

**R14. macOS to Linux.** The fixture's four spec files attested on macOS arm64 (`platform = "any"`, `TZ=UTC`) were
checked as in F14: the static `x86_64-unknown-linux-musl` `vci` in the `ruby:3.4.9` image (`linux/amd64`, non-root,
Bundler 4.0.9, gems in `vendor/bundle`). `vci plan` skipped all four with nothing changed; editing the view template ran
c only; `TZ=Europe/London` ran everything; with `config/routes.rb` edited, `vci ci` ran b, c and d (one RSpec process
each, `3 examples, 0 failures` in total, exit 0) and skipped a, with a `~/.rspec` holding an invalid option in the
container user's home, and wrote neither `spec/examples.txt` nor `db/`. Nothing needed changing for RSpec (the RSpec
gems are pure Ruby, matched by version like the rest of the bundle).

**R15. Not verified.** A GitHub Actions runner, Capybara system specs that drive a browser, rspec-retry and
parallel_tests as gems (their refusal is tested by defining their constants; a home-grown retry is tested as such,
R18), and Spring with `spring-commands-rspec`.

**R16. Exit code after the run.** The collector read the exit status from `$!` after calling `VciCollector.unhooked`,
whose `defined?` checks reset `$!` to nil: a spec with `at_exit { exit 1 }` exited 1 but recorded `"state":"passed",
"exitStatus":0` and was attested (and then skipped); so was a file below SimpleCov's `minimum_coverage` (exit 2) and
one requiring `minitest/autorun` (its handler rejects `--options` and exits 1). The status is now read first thing in
the collector's `at_exit` handler (the last to run, so every later-registered handler has set it), a clean framework
report with a non-zero status adds `vci:process-exit:<n>`, and `RailsAdapter::run_one` independently taints a
`passed` result whose process did not exit 0 (with only that Rust check and the old collector, the e2e test
`rspec_exit_code_set_after_the_run_refuses` passes too). Checked with real SimpleCov 0.22.0 in a copy of the fixture:
80% line coverage against `minimum_coverage 100` was refused with `vci:process-exit:2`, 100% was attested.

**R17. `ENV["TMPDIR"]` and `resolv.conf`.** The paths the collector ignores (vci's temp dirs) were computed from the
live `ENV["TMPDIR"]` at exit, so a spec that set it to `/` hid every read outside the repository. It is now read once
when the collector loads. A stock `rails new` app with rspec-rails and Capybara refused every spec for `input outside
the repository: /etc/resolv.conf`: rspec-rails requires `capybara/rspec`, Capybara requires `net/http`, which requires
`resolv`, whose `DefaultResolver = self.new` (in `class Resolv`'s body) parses `/etc/resolv.conf`. That read (and
existence check), made with a `<class:Resolv>` frame of a `resolv.rb` outside the repository on the stack, is not
recorded; a test calling `Resolv::DNS::Config.default_config_hash` itself still records it. After the change the stock
app's model spec and a `rack_test` feature spec (`visit "/up"`) were attested and skipped. Prism's `*_file` methods
(`parse_file`, `parse_file_success?`, `lex_file`, ...) read in C and are now hooked like
`InstructionSequence.compile_file`.

**R18. Cleared failures.** rspec-retry's refusal relied on its constant. A retry in an `around` hook that clears
`@exception` and calls `ex.run` again, a prepended `Example#finish` that drops `@exception`, and a prepended
`Reporter#example_failed` calling `example_passed` were all attested. The collector now hooks
`Example#display_exception=` (through which `set_exception` and `set_aggregate_failures_exception` store a failure; a
pending example's goes to `pending_exception` instead) and refuses a file in which an example with a recorded failure
is reported as passed (`rspec:failure-cleared`), and compares the reporter's counts with the examples'
`execution_result.status` (`rspec:status-mismatch`).

## Not done

- **RSpec expectation counts**: RSpec does not count expectations, and vci does not either; an example without one
  passes (Minitest's no-assertion rule has no RSpec counterpart).
- **RSpec on a GitHub runner**: checked in the Linux container only (R14).
- **Precise Zeitwerk modelling**: a new file in an autoload root runs every test that boots Rails, whether or not a
  constant it defines is ever referenced.
- **A type-only record for files**: `File.exist?(routes.rb)` records the file's content, so a routes change runs
  every test that boots Rails.
- **A git gem's checkout** is identified by its locked revision; its working tree is not checked for edits (registry
  gems are checked against their archives).
- Not run on a GitHub Actions runner: `ruby/setup-ruby`'s Ruby build, Ubuntu's libyaml and a service-container
  database were not tried; the Linux check used the `ruby:3.4.9` Docker image.
