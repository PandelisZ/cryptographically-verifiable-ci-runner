# Spike: Rails dependency collection (`vci_collector.rb`)

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

## Not done

- **RSpec**: needs a reporter for RSpec's results and its expectation counts, and handling the options RSpec reads
  from `~/.rspec` and `$XDG_CONFIG_HOME/rspec/options` (outside the repository, so every file would be refused). The
  adapter errors on RSpec-only projects rather than running nothing.
- **Precise Zeitwerk modelling**: a new file in an autoload root runs every test that boots Rails, whether or not a
  constant it defines is ever referenced.
- **A type-only record for files**: `File.exist?(routes.rb)` records the file's content, so a routes change runs
  every test that boots Rails.
- **A git gem's checkout** is identified by its locked revision; its working tree is not checked for edits (registry
  gems are checked against their archives).
- Not run on a GitHub Actions runner: `ruby/setup-ruby`'s Ruby build, Ubuntu's libyaml and a service-container
  database were not tried; the Linux check used the `ruby:3.4.9` Docker image.
