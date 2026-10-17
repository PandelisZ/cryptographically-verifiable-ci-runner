# Spike: Rails dependency collection (`vci_collector.rb`), Minitest and RSpec

Date: 2026-10-01. macOS arm64 (Darwin 25.6). Ruby 3.4.9 (`3.4.9p82`, through mise), Bundler 4.0.9, RubyGems 3.6.9,
Rails 8.1.3.1, Minitest 6.0.6, Zeitwerk 2.8.3, `sqlite3` 2.9.6 (SQLite 3.53.2), `tzinfo-data` 1.2026.5. Fixture:
`fixtures/rails-abcd`. Collector: `ruby/vci-collector/vci_collector.rb`; its tests:
`ruby/vci-collector/test/collector_test.rb`. A cross-platform check used the `ruby:3.4.9` image (`linux/amd64`, Debian)
in OrbStack with a static `x86_64-unknown-linux-musl` `vci`.

## How it collects

The Rust adapter runs one process per test file (several files: since vci 2.0 one process that boots once and forks
one process per file, see "Batch mode" below):

```
RUBYOPT=-r<abs>/ruby/vci-collector/vci_collector.rb VCI_RAILS_MODE=collect VCI_OUT=<dir> VCI_TEST_ID=<file> \
  VCI_ROOT=<project> VCI_REPO=<repo> TMPDIR=<fresh dir> RAILS_ENV=test RACK_ENV=test \
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
| native code | `Fiddle::Handle` and `Fiddle::Function` (so `Fiddle.dlopen(nil)` too); FFI: `DynamicLibrary.open` records the library it opened (all modes), calls of what `attach_function`/`attach_variable` attached (FFI's methods on the module and its singleton class replaced in place by a checking wrapper, F18), `Function#call`, `Function#attach`, `VariadicInvoker#invoke`, and ruby-vips' `Vips::Operation.call` (F16); libxml2 options and APIs that read files, a `.so`/`.bundle` inside the repository in `$LOADED_FEATURES` |
| file descriptors | `IO.for_fd`/`IO.new(fd)`/`File.new(fd)`: accepted when `fstat` gives the dev/inode of a file a hook saw opened |
| SQLite | `SQLite3::Database#initialize`: a file other than the test environment's configured databases (or one in `TMPDIR`) taints at exit; an authorizer taints `ATTACH`; extension loading taints |

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

**Superseded in vci 1.4.0 (collector 0.5.0).** By the user's decision the test database is now the test engine's
business: the collector no longer redirects, prepares, purges or loads any database, and `policy.rails_allow_db` is
gone. The configured databases are used as they are; `load_schema!`'s `bin/rails db:test:prepare` child is accepted
(it is started with `VCI_RAILS_MODE=engine`, where the collector does nothing) when the `system` call comes from
`ActiveRecord::Migration.load_schema!` in the bundle's activerecord gem; the test environment's SQLite files and their
`-wal`/`-shm`/`-journal` siblings are never recorded (a listing of their directory leaves them out); Active Record's
server connections are accepted; `ruby_db` is the adapter names only. Files of a project run one at a time, and
`vci ci` runs the remainder in one process per runner. The database's contents are no longer an input: an attestation
promises what CI promises, a pass on a database the engine set up (see "vci does not manage the database" in
`docs/REFERENCE.md`).

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

**F16. FFI: loading is not reading; ruby-vips is hooked (collector 0.4.0).** A Rails 8.1 application with
`image_processing` in the bundle refused every test on a machine with libvips: Active Storage's engine requires
`ruby-vips` at boot, which runs `ffi_lib` and attaches about 130 functions, and the collector tainted `ffi_lib`,
`attach_function` and `FFI::Function` themselves. It also tainted `ffi_lib` *before* calling it, so an optional
library whose load failed (a rescued `LoadError`) still refused the file. The rule now:

1. **A load is recorded, not refused.** `FFI::DynamicLibrary.open` (which `ffi_lib` calls for every candidate name)
   records the library that opened as the external `native:<file name>`, version `sha256:<hex>` of the file it
   resolved to (computed when the records are written, so no gem is required while the tests run). The probe records
   the same while the application boots and reports `natives`; `vci plan` resolves a test's `native:` externals
   against them like gems. A failed open records nothing. FFI's search for the file (`LD_LIBRARY_PATH`, `File.exist?`
   over its library directories) runs quietly: what it found is recorded instead.
2. **A call is refused, unless the library has hooks.** `attach_function` is wrapped after it succeeds: the methods
   FFI defined (on the module and its singleton class) get a wrapper that taints the file when called
   (`native:FFI call <Module>.<function> (C code of <library>: ...)`). The same for `attach_variable`'s accessors,
   `Function#attach` used by hand, and `Function#call`/`VariadicInvoker#invoke` on anything not attached through a
   wrapped method (the `FFI::Function` `attach_function` returned is called through the same policy: ruby-vips keeps
   `g_free`'s as `GLib::G_FREE` and FFI's `AutoPointer` calls it during GC).
3. **ruby-vips' policy.** Functions attached by the modules `Vips`, `GLib` and `GObject`, from files inside the
   installed `ruby-vips` gem, over libvips/GLib/GObject, follow `Native::Vips`: the ~130 functions ruby-vips 2.3.0
   attaches are classified (memory only; `vips_foreign_find_load` and file sources record a read, file targets a
   write; descriptor sources and targets are refused; an unknown function is refused). `vips_cache_operation_build`
   is the one that runs an operation: the operation's nickname comes from the `vips_operation_new` call that made
   the pointer (type names such as `VipsForeignLoadPngFile`, which `vips_foreign_find_load` answers, are resolved to
   nicknames), and a file loader or saver is only built inside `Vips::Operation.call` for that operation, once.
   `Vips::Operation.call` itself classifies the operation and its arguments before it runs: single-file loaders and
   savers of `jpeg`, `png`, `webp`, `gif`, `tiff`, `heif`, `jp2k`, `jxl`, `rad`, `ppm`, `csv`, `matrix` and
   `thumbnail` record the file; their buffer, source, target and mime variants, `thumbnail_image` and every other
   operation are allowed; other loaders and savers, `text`, `system`, ICC profiles that are files and file options
   (also inside option strings such as `"x.jpg[profile=x.icc]"`) are refused.
4. **Active Storage.** The analyzer copies the blob to a temp file and calls `Vips::Image.new_from_file` on it: the
   copy is the process's own (vci's temp dir), the original is the fixture the test read through Ruby. So a model test
   that never touches storage and a test that attaches and analyses an image are both attested, the image being an
   input of the second (`fixtures/rails-vips`, `rails_active_storage_with_libvips`). Previewers run external
   programs and stay refused.

Accepted, and documented in the reference: libvips' own dependencies (GLib, libjpeg, libpng, its modules) are
identified only by libvips' file hash; `VIPS_*` and `G_*` are hashed whenever present, since libvips and GLib read
them in C. What vci records for a library is its file, so another platform's libvips (or none) runs the file there.

**F17. Minitest files that never load Rails.** A Minitest file under `test/lib` that requires only `minitest` and a
plain Ruby file never defines `Rails::VERSION`. The collector fell back to the bundle's `railties` version only for
RSpec files, so such a Minitest file reported `rails ""` and was refused ("toolchain seen by the collector ... rails ,
... differs from the project's (... rails 8.1.3.1 ...)"). Both runners now report `Rails::VERSION` when Rails is loaded
and the bundle's `railties` otherwise, which is what the probe (which boots Rails) reports; without `railties` both
sides report `""`.

**F18. Names, links and C readers the hooks missed (collector 0.4.1).** An adversarial pass on `fixtures/rails-vips`
found false skips, each now a regression test (`collector_test.rb`, `rails_files_named_oddly_read_in_c_or_through_links`,
`collector_dir_symlinks_out_of_it_are_kept` in `jsonl.rs`):

1. **`~` and `|`.** `File.read("~note.txt")`, `File.open("|pipe.txt")` and `Vips::Image.new_from_file("~pic.png")`
   open those names literally, relative to the working directory, but the collector expanded paths with
   `File.expand_path` (which raises for `~note.txt`: no such user) and skipped `|...` as a command, recording nothing.
   Names are now resolved as the file system entry points use them (`~` literally; `|` is a command only for
   `Kernel#open` and `IO.read`/`binread`/`readlines`/`foreach`/`write`/`binwrite` called on `IO` itself, all of which
   taint, `IO.write("|cmd")` newly so). A name the collector cannot resolve after the operation succeeded taints
   (`vci:unresolvable-path:`).
2. **libvips resolves operation names without regard to case.** `vips_operation_new` finds an operation with
   `vips_type_find("VipsOperation", name)`, which compares nicknames and class names with `strcasecmp`, so
   `Operation.call("PNGLOAD", ...)`, `"PngLoad"`, `"VIPSFOREIGNLOADPNGFILE"` loaded a file the case-sensitive
   classification took for a memory operation, and `"SYSTEM"` ran a shell. The collector now asks libvips the same
   way (`Vips.type_find`, then `Vips.nickname_find`) and classifies the real nickname; a name libvips does not resolve
   is refused.
3. **OpenSSL reads in C.** `X509::Store#add_file` is recorded; a store given `set_default_paths` (as
   `SSLContext::DEFAULT_CERT_STORE` is when `openssl/ssl` loads) or `add_path` is marked, and verifying with it
   (`Store#verify`, `StoreContext.new`, a TLS handshake) refuses the file: what it reads (the system CA bundle,
   `SSL_CERT_FILE`, a hashed directory read on demand) is not seen. `SSLContext`'s `ca_file` is recorded, `ca_path`
   refused; `Config.new(file)` and `Random.load_random_file` are recorded; loading a provider or engine is refused.
   `OPENSSL_*` variables are hashed whenever present.
4. **Symlinks out of exempt directories.** Reads in vci's temp dirs, Ruby's own library directories and the zone
   database are not inputs, and the CLI drops reads of the collector's own directory; each was decided by how the
   path was spelt. A directory symlink there into the repository (made, read through and removed by the test) hid
   the repository files read through it. Paths outside the repository are now resolved when they are used (the link
   may be gone at exit): one that leads into the repository is recorded as that file, and an exemption holds only for
   where a path really leads (elsewhere it is a read outside the repository, refused). `drop_collector_paths` drops a
   path only when its real path is in the collector directory.
5. **Who the process runs as.** `Process.uid`/`euid`/`gid`/`egid`/`groups`, `Process::UID`/`GID`/`Sys` and
   `Etc.getpwuid`/`getlogin`/`getpwnam`/... were not observed, so a test asserting the user name was attested as
   `pz` and skipped in a root CI container (`policy.allow_superuser_mismatch`) or under another uid. Reading them
   refuses the file (`ruby:process-identity:`), except from RubyGems, Bundler and Ruby's standard library.
6. **`super_method` past the FFI check.** The check on an attached function was a module prepended to the module and
   its singleton class, so `m.method(:fopen).super_method.call(...)` called C unchecked (with a library the probe
   also opens, such as libvips, the read was a false skip). The wrapper now replaces FFI's method in place and holds
   the original only inside itself.

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

## Batch mode: one boot, one process per file (vci 2.1)

Date: 2026-10-16. Same machine, Ruby 3.4.9, Rails 8.1.3.1, Minitest 6.0.6, rspec-core 3.13.6; vex-api
(`/Users/pz/w/vex-git`, master `2b59eb17cc`, MySQL 8 in Docker on 127.0.0.1:3306).

One process per file boots the application once per file. On vex-api that averaged 41 s a file (the boot with the
collector, Oaken reseeding the database in each process's first test, then the file's tests), so `vci run` of the
`application` group (925 files) would take about ten and a half hours, and CI never attested Rails. `vci run` (and `vci
ci --key`) of several files now starts one process per runner, `bin/rails test <files> --seed 0` or `rspec --options
.rspec <files>`, with the collector in **batch mode** (`VCI_RAILS_BATCH` names a file listing the test ids). One file,
or `VCI_RAILS_PER_FILE=1` in vci's environment, still runs one process per file from the start.

**B1. One boot, then a fork per file.** The collector lets the process run until the test runner's loader asks for the
first file of the batch (Rails' `Runner.load_tests` requires each file; RSpec's `load_spec_files` loads each; the
collector recognises the request by the loader's frame, past `require` wrappers such as Zeitwerk's and Ruby's
`bundled_gems`). That process, the *driver*, loads no test file. It groups the files by what their first statement
requires (`require "test_helper"`, `require_relative "../test_helper"`, `require File.expand_path("x", __dir__)`;
comments, blank lines and magic comments may come first) and, per group, forks a process that requires it: the
**boot**, exactly what a run of any file of the group does first, from the same place in the runner. The boot's
process then forks one process per file of the group, one at a time (they share the test database, as one-file runs
do), and waits for it. From the fork on, a file's process is a one-file run of that file: the loader's requests for the
other files of the batch are skipped (only the loader's: a test file may still require another one, which then loads
as in its own run), its own file loads, its tests run, and at exit the collector writes its output as a one-file run
does (the collector's test id becomes its file, and its process the one allowed to write). Everything the boot
observed before the fork is in its tables, as it is in a one-file run's. A file whose first statement is not such a
require has a group of its own with nothing preloaded: its process boots by itself (correct, only slower).

Nothing one file's process does reaches another's: classes and the tests they inherit, monkey patches and constants
defined at a file's top level, RSpec shared examples, memoized helpers, lazily loaded code and what loading it read,
threads (Minitest's `parallelize_me!`), native libraries opened through FFI, results and exit statuses. So each
file's inputs, verdict and exit status are those of its own run; there is nothing to attribute. The first design of
batch mode (one process for every file, observations attributed to files by segments, with Rails' fixture and
template caches replayed) was reviewed against that standard and failed it in eight ways, each reproduced with the
e2e fixture: a failing inherited test counted for the parent's file, a file requiring another test file without it as
an input, top-level patches and shared examples making a file pass that fails on its own, Minitest's thread pool
mixing two files' reads and results, a read outside the repository refusing only the first file that lazily loaded
it, a memoized helper and a cache in vci's temp dir serving later files without an input, an absent-path probe
dropped because another file wrote that path, and a non-zero exit after every file passed on its own. All eight are
gone by construction; `rails_batch_mode_gives_what_one_process_per_file_gives` (below) runs each of them.

What the processes of a batch share is what processes of one-file runs share, plus two things vci handles:

- **The database connections of the boot.** A forked process that used them and closed them at exit left the next
  file's process a dead socket (on vex-api: `Mysql2::Error::ConnectionError: Lost connection to MySQL server during
  query` in the second file's first test). Before each fork the boot's process closes its Active Record connections
  (`connection_handler.clear_all_connections!`), as Rails' `parallelize` does before forking its workers; each file's
  process connects anew. (A connection-level setting the boot made by hand would be lost; Rails re-applies
  `database.yml`'s.)
- **vci's temp dir** (`TMPDIR`), which a one-file run gets fresh. After each file's process the boot's process removes
  what it added there, so a cache one file left there (`Dir.tmpdir/x`) is not there for the next. A file the boot had
  put there and a file's process changed or removed cannot be put back: the rest of the group goes back to one
  process per file (B3).

The repository's own scratch directories (`tmp/`, `log/`, `storage/`) and the database are shared as between
one-file runs: a file reading what an earlier file's process wrote there records it as an input, as it would after an
earlier one-file run, and what the database holds is not an input either way.

The runner's handling of its arguments checks every file it is given before the fork (Rails' `extract_filters`,
RSpec's `files_to_run`); a one-file run checks only its own. Those checks, made from the loader's frames before the
fork, are dropped from every other file's process (`Batch.loader_check`): otherwise renaming any test file would run
every file batched with it.

macOS: the Objective-C runtime kills a forked process that touches a class another thread was initialising at the fork
(`+[__NSCFConstantString initialize] may have been in progress in another thread when fork() was called`: vex-api's
boot, every file). vci sets `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` for batch processes on macOS (read by the
runtime only).

**B2. Output.** Each file's `<sha256(id)>.jsonl` is written by its own process, in the format of a one-file run.
`batch/files.jsonl` has a line per file: `{"id", "exit"}` (its process's exit status, `null` for a signal) or
`{"id", "why"}`, and the driver ends it with `{"done": true}`. The adapter reads each file's output with its own exit
status as it reads a one-file run's (a pass whose process exited non-zero is refused, `vci:process-exit:`), and the
exit code of `vci run` is the first non-zero one of the files' own processes (a failed result whose process exited 0
counts as 1: a Minitest without `allow_fork` sets the status only in the process that registered its `at_exit`). The driver's own exit status is only logged (`vci: ruby bin/rails test <50 files> --seed 0, booted
once, one process per file (exit 1)`).

**B3. What goes back to one process per file.** vci runs these files again on their own and says so (`vci: 2 of 2
file(s) of the batch run again one process per file:` and why each):

- the group's first statement failed in the boot's process (a database that does not exist yet, a helper that
  raises): its files; the boot's process died (a signal): its files;
- a file's process wrote no output (killed, or the collector failed): that file;
- a file's process changed a file the boot left in vci's temp dir: the files after it in its group;
- the loader never asked for a file of the batch (a runner vci does not recognise): every file, after the driver
  ran them all itself (nothing of that run is used);
- no `batch/files.jsonl`, or a line vci cannot read: every file.

**B4. Run conditions.** As before: `PARALLEL_WORKERS=1` (Rails' `parallelize` takes the variable over its argument and
does not fork), the fixed seed, no Spring, no Bootsnap. A fork that a test makes is still refused (`process:fork`);
the batch's own forks are not a test's and are not. Minitest's `allow_fork` is set in each file's process (Minitest
6's `at_exit` would otherwise keep a forked process's status at 0).

**B5. Parallel workers: `PARALLEL_WORKERS=1`.** What that costs, measured with plain `bin/rails test <files> --seed 0`
(vci's run conditions, no collector), vex-api's own `parallelize(workers: :number_of_processors)` (14 here) against
`PARALLEL_WORKERS=1`:

| files | `PARALLEL_WORKERS=1` | 14 workers |
|---|---|---|
| 50 of the `application` group | 66.1 s | 99.3 s (every worker loads the schema and Oaken's seeds into its own database) |
| the `application` group, 925 | 1364.4 s | 336.3 s |

So one file at a time costs a factor of four on a whole group, and nothing on a partition's share of a few dozen
files. `vci ci --partition I/N` gets the parallelism back across jobs, each attesting its share. Running a group's
file processes in parallel would need a database per process, as `parallelize` makes.

**B6. A stub saved by alias broke every later call of the method (collector, all modes).** The first batch run of 50
vex-api files overflowed the stack:

```
vci_collector.rb:2076:in 'block (2 levels) in <module:EnvHooks>'
vci_collector.rb:2077:in 'block (2 levels) in <module:EnvHooks>'
 ... 9351 levels...
```

vex-api's `test_helper.rb` defines `Object#stub` (Minitest 6 no longer ships `minitest/mock`) the way Minitest's own
`stub` works: `alias_method "__vex_stub__#{name}", name`, `define_method(name)`, and in `ensure` `alias_method name,
"__vex_stub__#{name}"`. On `ENV`, `alias_method` resolves `[]` to the collector's hook (`EnvHooks`, prepended to `ENV`'s
singleton class), so the stub saved the hook and the restore put a copy of the hook in the singleton class, whose
`super` (looked up after `EnvHooks`) is that copy again: every later `ENV[...]` recursed, the collector's own reads at
exit too, so the file's output was lost and it was never attested. `HEAD`'s collector does the same (reproduced with a
ten-line script). The collector now prepends `Module` with an `alias_method` that, for a method a collector hook
prepended to that very class wraps, aliases the wrapped method instead (`AliasGuard`): the stub replaces and restores
the real method and the hook keeps recording around it. An alias in a subclass (`File.read`, hooked on `IO`'s
singleton class) is left alone: its copy's `super` goes on to the superclass, as it should. `collector_test.rb`:
`test_alias_stub_of_a_hooked_method_restores_it`.

**B7. Soundness notes.**

- **Eager loading.** With `config.eager_load = true` (vex-api sets it from `CI`, and its vci.toml declares `CI=true`)
  every application file is loaded at boot: an input of every test file, in per-file and batch mode alike, so any
  application change runs every Rails file. Without eager loading a constant is autoloaded by the file's process that
  uses it, and is an input of that file only, as in its own run.
- **The boot is the first statement of each file of its group**, run once, from the same place in the runner as in a
  one-file run (inside its request for a test file). A helper that inspects how it was required (the caller's file)
  sees the collector instead of the test file; none of the fixtures' or vex-api's helpers do.
- **What a file's process inherits but its own run would not have**: nothing recorded (the loader's checks of the other
  files are dropped, B1); in memory, `ARGV` still lists every file of the batch.

**Tests.** `crates/vci-cli/tests/e2e_rails.rs`, `rails_batch_mode_gives_what_one_process_per_file_gives`: twenty files,
one or two per finding above (an inherited failing test, a file requiring another, a top-level monkey patch, Minitest
threads, lazily loaded code reading `/etc/hosts`, a memoized helper, a cache in `Dir.tmpdir`, a probe of a path
another file writes, a file that does not load, a top-level constant that breaks another file's load, a skip), run by
`vci run --key` in batch mode and, in another copy of the repository, one process per file: the same files are
attested and refused for the same reasons, the attested files' manifests are equal entry for entry, the exit code is
the same, and changes to what a file read (the base test file, the memoized data, the cache's source, the probed path)
run that file. Before the change the test failed on every finding (the reproductions above). `e2e_rspec.rs`,
`rspec_batch_mode_gives_what_one_process_per_file_gives`: the RSpec fixture's specs, a failing and a pending spec, a
spec defining shared examples at its top level and one using them without requiring it; two boots (`rails_helper`,
`spec_helper`). Both e2e harnesses now run every test in batch mode, as `vci run` does by default
(`VCI_E2E_RAILS_PER_FILE=1` runs them one process per file); all pass both ways, including
`rails_active_storage_with_libvips`, which the first design failed (a native library one file opened at load time was
in every file's inputs). `collector_test.rb`: `test_batch_mode_runs_each_file_in_a_process_of_its_own` (a file's output
equals its own run's, a top-level constant and a patch do not reach the next file, the temp dir is cleaned),
`test_batch_mode_sends_back_what_it_cannot_run_per_file` (no loader, a boot that raises, a boot killed, a changed temp
file). The adapter: `batch_output_is_read_per_file`.

**Measurements (vex-api).** 50 files of the `application` group (every 18th of its sorted list, as
`scripts/ci/rails-tests.sh` makes the group), from a clone of vex-git master `2b59eb17cc` (no remote, never pushed),
its own test database, a release `vci` built from this tree, a throwaway key, `/usr/bin/time -l mise exec -- vci run
<50 files> --key <key>`:

| | wall | user + sys | attested / refused |
|---|---|---|---|
| one process per file (`VCI_RAILS_PER_FILE=1`; measured for the first design) | 2034.7 s | 448.6 s + 175.7 s | 47 / 3 |
| batch: one boot, one process per file | 1110.0 s | 215.0 s + 69.7 s | 47 / 3, the same three (one without tests, two that skip one) |
| the first design's single process (unsound, see B1) | 117.7 s | 62.0 s + 51.0 s | 47 / 3 |

The files' processes reported 855.8 s of test time in all (10.6 to 34.2 s each, 218 tests): most of it is vex-api's
Oaken `replant_seed` (truncate every table, load `db/seeds/test/**`) in each process's first test. Oaken runs it "once"
by removing its `before_setup` after the first call, in memory, so every file's process does it again, as every one-file
run does; the shared process of the first design did it once for all 50 files, which is most of what it saved. On
vex-api batch mode therefore saves the boot (about 20 of the 41 s a one-file run took) and keeps the reseed: the
`application` group (925 files) would take about 5.7 h in one job at 22 s a file, which `vci ci --partition I/N`
divides by N.

What a project can do about that is its own business, and vex-api can: an experiment in a scratch clone (never
committed to vex) replaced Oaken's first-test reseed by a reseed in `test_helper.rb` itself (`Oaken.loader.replant_seed`
after `include Oaken.loader.test_setup`, and Oaken's `before_setup` removed), so the boot seeds once and every file's
process inherits the seeded database (its tests run in transactions, as before). The same 50 files: **265.0 s** (201.6 s
user, 57.8 s sys), 47 attested and the same 3 refused, 37.6 s of test time in all. What is left is about 5 s a file:
the collector writing the file's output at exit (about 3.3 s, measured in three file processes: 2.3 s classifying
~13,800 observations, 0.6 to 1.1 s checking the used gems' files against their archives), vci checking and signing
(about 1.1 s), and the fork. A one-file run pays the same per file. The trade-off is the project's: with the seed in the
helper, a file's process starts from the database the previous file's non-transactional tests left, where a one-file
run with Oaken's own setup starts from a fresh reseed; vci does not record the database either way.

Manifests: four of the 50 files run one process per file with the same build and database (`VCI_RAILS_PER_FILE=1`,
151.8 s) have the same input root as in the batch for three (`slack_run_preview_job_test.rb`,
`email_verification_test.rb`, `openapi_from_routes_test.rb`; 13806, 13811 and 13914 inputs), and for
`inbox_page_test.rb` the same 13902 entries but for six `absent` probes of `public/api/v1/organizations/org-<random
id>/pages/inbox{,.br,.gz,.html,...}` (`ActionDispatch::Static` looking up a request path whose id is random per run).
`app_access_controller_test.rb` run on its own, then in a batch of two: the same root (`ef8fed40bdd1022a`, 13880
inputs). Against the first design's one-process-per-file run (an older build): every batch manifest has about 90 more
`absent` probes, of `lib/` and `vendor/` for `active_record/fixture_set/*` and `action_view/template/handlers/*` (the
load-path lookups of features; this build records them one process per file too, as the equal roots above show), and
misses only random request paths (245 entries over 47 files).

macOS needed `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` (B1: without it every file's process died and all 50 went back
to one process per file), and the boot's database connections had to be closed before each fork (B1: the second
file's first test lost its MySQL connection).

## Not done

- **Batch files in parallel**: a batch runs its files' processes one at a time (B5); in parallel each would need a
  database of its own, as Rails' `parallelize` makes.
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
