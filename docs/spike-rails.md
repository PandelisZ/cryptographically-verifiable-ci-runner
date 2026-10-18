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

**B8. A stub that calls the method it captured looped (collector, collect mode).** vex-api's
`manual_image_deploy_service_test.rb` (`services` group) does

```ruby
original_env = ENV.method(:[])
ENV.stub(:[], ->(key) { key == "..." ? @service.public_id : original_env.call(key) }, &block)
```

Without the collector `original_env` is Ruby's own `ENV.[]`. Under it, it is the collector's hook (`EnvHooks`, prepended
to `ENV`'s singleton class, is what `ENV.method(:[])` finds), and the hook's `super` is whatever the singleton class
defines now: the stub, which calls `original_env`, which is the hook again. 5 of the file's 35 tests failed with
`SystemStackError: 10279 -> 41`, one process per file and in a batch; plain `bin/rails test` passes 35 of 35. B6's
`AliasGuard` does not help: nothing is aliased. The collector now watches every name its hooks wrap in the class they
are prepended to (`method_added`, `singleton_method_added`; `VciCollector::Redefined`). A redefinition there (a stub,
`define_singleton_method`) is wrapped: the wrapper runs it, and when the hook is re-entered from
inside it on the same thread through a captured object (the frame that called the hook is `Method#call`, `Method#[]`,
`Method#===` or `UnboundMethod#bind_call`), it calls the method the class defined before it was hooked instead. The hook
still records that call (the captured object is the hook), so the stub's real reads are inputs. A direct call from
inside the stub (`ENV[k]` in the stub, or in a block a stubbed `File.open` yields) runs the stub again, as without the
collector. An object captured and called some other way (`&original`, `to_proc`, `curry`) is not told apart from a direct
call: after 16 nested runs of the stub on one thread the original is called (the recursion ends where it overflowed the
stack). Restoring the original (Minitest's alias back) is not wrapped; a hooked call costs nothing more when no stub is
active. RSpec's `SimpleCovConfigGuard` (`File.exist?`, every mode) is watched the same way. `collector_test.rb`:
`test_stub_calling_a_captured_hooked_method` (`ENV.method(:[])` + `ENV.stub`, an `UnboundMethod#bind_call` of `fetch`,
`File.method(:exist?)` + `File.stub`, a lasting `define_singleton_method`, a stub in another thread, a direct call from
inside a stub, a captured `to_proc`); it fails on the previous collector. vex-api, the two files below in one `vci run`
(2 slots, `VCI_RUBY_COLLECTOR` pointing at each collector, a release `vci` of `HEAD`): before, 35 runs, 5 errors, not
attested; after, 35 runs, 0 failures, attested (2,710 inputs), also alone (one process per file).

**B9. A batch file's child Ruby printed to stderr (collector, batch mode).** vex-api's
`merge_queue/reconciliation/batch_interaction_test.rb` runs `Open3.capture3(RbConfig.ruby, "-e", ...)` and asserts an
empty stderr. The child inherits `RUBYOPT` (the collector) and `VCI_OUT`, but not a test id: a batch gives a file's
process its id in memory (`VciCollector.test_id`), not in its environment, and the child is not the batch's own process
(`VCI_RAILS_BATCH_PID`). It hooked everything, then said `vci_collector: VCI_OUT or VCI_TEST_ID not set; nothing written`
at exit, and the test failed (one process per file it passes: the child inherits `VCI_TEST_ID` there). A process in
collect mode with `VCI_OUT` set, no `VCI_TEST_ID` and not the batch's own now returns at the top of the collector, as
an engine child does: no hooks, no output, nothing printed. What it does is already its parent's taint
(`process:spawn`, `process:system`, ...). Loaded by hand without `VCI_OUT`, the collector still says it wrote nothing.
`collector_test.rb`: `test_batch_child_process_says_nothing` (a child `ruby -e` in a batch, with and without slots,
prints nothing and has no `VciCollector`); it fails on the previous collector. vex-api, the same run as B8: before,
`Expected "vci_collector: VCI_OUT or VCI_TEST_ID not set; nothing written\n" to be empty`, not attested; after, 1 run,
0 failures, attested (`waived: process:spawn`, 2,773 inputs).

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

## Slots: a batch's files in parallel, one database per slot (vci 2.1)

Date: 2026-10-18. Same machine (14 cores, 36 GB), Ruby 3.4.9, Rails 8.1.3.1, Minitest 6.0.6, Oaken 1.0.0; vex-api from
a clone of vex-git master `3738f8486d` (no remote, never pushed), MySQL 8 in Docker on 127.0.0.1:3306.

Batch mode ran a group's files one at a time because they shared the test database (B5). On vex-api that cost about
17 s of Oaken's `replant_seed` in every file's process (B "Measurements"), and a group of 925 files about 5.7 h. Rails'
own parallel mode, which vex's CI uses, gives each worker a database of its own and seeds it once. Slots do the same
for a batch. The decision behind it (the user's): an attestation need not be deterministic at the database level.
Files may share seeded database state and run at the same time against separate databases, as Rails' workers do.
What stays: each file's inputs, verdict and exit status are its own (the process per file), and everything fails
open.

**S1. What runs.** W slots (`VCI_RAILS_JOBS`, else `PARALLEL_WORKERS` above 1 in vci's environment, else `VCI_JOBS`,
else the processor count; at most what the project's `parallelize(workers: n)` asks for unless vci's `PARALLEL_WORKERS`
says, as in Rails, where the variable overrides `workers:`; at most one per file of the group). The collector learns
`workers:` by wrapping `ActiveSupport::TestCase.parallelize` (`Batch::ParallelizeCall`): under vci's
`PARALLEL_WORKERS=1` Rails' executor always has size 1. After the boot (one per helper group, as in B1), the
group's process does what Rails' `Parallelization#start` does before it forks its workers: the before-fork hooks
(Rails' own closes the Active Record connections), then forks one long-lived process per slot. A slot does what Rails'
`Parallelization::Worker#after_fork` does: `ActiveSupport::TestCase.parallel_worker_id = i`, then every after-fork
hook with `i`, in registration order. In Rails 8.1.3.1 (activesupport `testing/parallelization{,/worker}.rb`,
activerecord `test_databases.rb`, `rails/test_help` includes `ActiveRecord::TestDatabases`) these are: Active Record's
`create_and_load_schema(i, env_name:)` when `ActiveSupport.parallelize_test_databases` (it renames every test
configuration to `<database>_<i>`, `reconstruct_from_schema`s it, which purges and loads `db/schema.rb` or, when the
database is current, truncates its tables, then `establish_connection`), then the project's `parallelize_setup`
blocks (vex-api: Active Storage roots under `tmp/storage/worker-<pid>`; Oaken's `TestSetup#included` registers `{
@loader.load_seed }`). The slot then forks one process per file, one at a time: slot i's first file is the group's
i-th, the rest come from a queue the slots share, in the group's order (a slot that finishes early takes the next).
Each file's process is the one-file run of B1, against the slot's database: the loader's requests for other files
skipped, its file loaded, its tests run, its output written at exit, its own exit status. At its end the slot runs
the cleanup hooks (`parallelize_teardown`), as a worker does before it exits. Active Record connections are closed
before every fork (group → slots, slot → files); a file's process reconnects through the renamed configuration, to
its slot's database.

**S2. No reseed in a file's process.** Oaken's `TestSetup#before_setup` runs `loader.replant_seed` (truncate every
table, load `db/seeds/test/**`) in the first test of a process unless `Minitest.parallel_executor` answers
`should_parallelize?` with true, which Rails' `ParallelizeExecutor` does only when it forks workers (never under
vci's `PARALLEL_WORKERS=1`). A slot extends the executor object it inherited (`Batch::SlotExecutor`):
`should_parallelize?` is true for everyone but the executor's own `start` (which still sees its own answer and forks
nothing). The object stays Rails' (`ActiveSupport::Testing::Isolation` tests `is_a?(ParallelizeExecutor)` to decide
whether to `parallelize_me!`; a wrapper would have made it send tests to an executor that drops them). Measured on
vex-api, below: the 50 files' processes reported 1,126 s of test time one at a time and 63.6 s in slots
(`cli_release_test.rb`, one test: 20.4 s one at a time, 3.9 s in a slot).

**S3. When slots run.** When the boot called Rails' `parallelize` with processes (`Minitest.parallel_executor` is an
`ActiveSupport::Testing::ParallelizeExecutor` with `parallelize_with == :processes`): the project's test setup is
made for workers with a database each. Not when the project turned its workers off: `parallelize(workers: 1)` (its
tests must not run at once), or `PARALLEL_WORKERS` set to 1 (or 0) in vci's environment, as Rails users turn
parallelism off (vci then passes one slot). Never for a group without a boot (its files' first statement is not a
plain require of a helper): nothing is loaded when its slots would fork, so the after-fork hooks the files' own
`require "test_helper"` registers would come after the fork, and the files would run at once on one database; such a
group runs one file at a time, `VCI_RAILS_JOBS` or not. Or when `VCI_RAILS_JOBS` is set (any project, `1`: one at a time, vci 2.0's
batch). A project without `parallelize` and without `VCI_RAILS_JOBS` keeps one file at a time: its files share one
database, which nothing in its setup prepares for parallel processes. With `VCI_RAILS_JOBS` such a Minitest project
still gets Rails' after-fork hooks (`rails/test_help` registers Active Record's whatever `parallelize` says): a
database per slot (`db/test.sqlite3_<i>` for SQLite). RSpec has no parallel mode (rspec-rails registers no hooks, and
`TEST_ENV_NUMBER` of parallel_tests is read when `config/database.yml` is evaluated, at boot, before the slots fork):
with `VCI_RAILS_JOBS` its slots share the test database (a project whose specs cannot share it should not set it);
without it, one file at a time.

**S4. What slots share, and what vci does about it.**

- *The database server.* Each slot's database is its own; a file's process starts from what the slot's seed and the
  earlier files of the slot left (their transactional tests rolled back, their non-transactional ones not), as a test
  in a Rails worker starts from what that worker's earlier tests left. Not an input, as before.
- *vci's temp dir.* Each slot gets its own (`$TMPDIR/vci-slots/<i>`, set as `TMPDIR` in the slot; RSpec's example
  status file and SimpleCov's directory move there too), cleaned after each file's process as in B1; a slot whose
  file changed what the slot's setup left there takes no more files (the others take them). Outside the slots' dirs,
  the temp dir is snapshotted after the before-fork hooks; a change there (a path the boot computed before the slots
  existed, written by a file's process) could have been read by any file of any slot: the slots stop taking files
  and every file of the group runs again one process per file (`a process of the batch changed <path> in vci's temp
  directory, outside its slot's`). A change undone before the slots end counts too: a slot that sees one after a
  file notes it for the group's process (`batch/tmp-shared-<pid>`), and so does any process of a slot (its setup,
  its files) when it writes there (`Batch.slot_wrote`, from the collector's write hooks), at the moment it writes:
  a file that wrote `BOOT_TMP/flag` and removed it 3 s later while a file of another slot found it there used to be
  attested for both (the reader fails on its own). A write vci cannot see (a C extension's) is caught only by the
  snapshots. After a group, the driver removes what the group's processes left in vci's temp dir (the boot's files,
  the slots' dirs and what their setup and cleanup hooks wrote there), so the next group's slots and files start
  from what the one-file runs start from; if the group changed something that was there before it, the next groups'
  files run on their own. (vci 2.0's batch left a boot's temp files to the next group.)
- *The repository's scratch directories and files.* As between one-file runs, plus concurrency: a file reading a path
  another slot's file is writing records what it read. Files that write inside the repository are refused anyway
  (`wrote inside the repository`); a reader of such a path in another slot can see the write (in the fixture,
  `pr2_test.rb` writes and removes `config/flag.yml` while `pr1_test.rb` checks it is absent: a window of microseconds,
  not seen in the runs below).
- *The database connections the slot's setup makes.* Active Record's tasks connect to the configured server without a
  database (MySQL: `configuration_hash_without_database`; PostgreSQL: `postgres`) to create or purge the slot's
  database. The collector accepts such a connection to a configured server only while a slot runs its after-fork
  hooks (`Batch.slot_setup?`); a slot's `<database>_<i>` (and, for SQLite, `<file>_<i>` and its siblings) counts as
  configured in the slot's processes (`DB.server_configs`, `DB.sqlite_files`). Before this, the slot's purge tainted
  every file (`network:mysql2 (an Active Record connection to 127.0.0.1:<port>/, not one of the test environment's
  databases)`, `rails_mysql_test_database` under `VCI_RAILS_JOBS=3`) and SQLite slot files were "not one of the test
  environment's databases" (`rails:sqlite-file:.../db/test.sqlite3_0`).

**S5. Inputs.** A file's manifest in a slot is its one-file run's plus what its slot's setup recorded before the
file's process forked: the schema load requires `active_record/schema`, `active_record/tasks/*_database_tasks`,
`active_record/migration/compatibility` and `active_support/benchmark`, whose load-path lookups in the project's `lib/`
and `vendor/` are `absent` entries (in the fixture `active_record/schema`, `.../tasks/sqlite_database_tasks` and
others, 30 entries; on vex-api, whose boot loads more, `active_record/migration/compatibility`,
`.../tasks/abstract_tasks` and `.../tasks/mysql_database_tasks` as `.rb`, `.so` and `.bundle` in both directories, 18
entries), and `create_and_load_schema` reads `VERBOSE` (absent). Oaken's seed files, read by the slot's `load_seed`, are inputs of every file of the slot, as
they are of a one-file run (which reads them in `replant_seed`). A slot whose database is already current only
truncates it and requires less; its files' manifests then lack some of those lookups. These extra entries make the
attestation keys of slot runs differ from one-file runs; they never drop an input (`own ⊆ slot` for every file,
checked below).

**S6. Fallbacks (fail open).** Whatever a slot cannot run goes back to one process per file, with why: a slot whose
after-fork hooks raise (`slot <i>'s setup (Rails' after-fork hooks: its database, parallelize_setup) failed: ...`)
gives its first file back to the queue and takes none (the other slots run the group; if none can, every file runs on
its own: `no slot of the batch ran it (...)`); before-fork hooks that raise send the group back; a slot that dies
leaves its unsaid files to the group's process, which sends them back; B3's cases stand. `VCI_RAILS_PER_FILE=1` still
runs one process per file from the start.

**S7. Output.** `batch/files.jsonl` lines gain `"slot"` (and `"ms"`, the file's process's wall time); a slot says
`{"slot", "setup_ms"}` when set up, `{"slot", "why"}` when it stops or cannot set up; a later `{"id", "why"}` overrides
an earlier `{"id", "exit"}` (`read_batch`). Lines are appended with one `write` each (the slots append concurrently).
The exit code is the first non-zero of the files' processes, in the order the files were given, as before. `vci run`
logs `vci: ruby bin/rails test <50 files> --seed 0, booted once, one process per file (exit 0), 8 slots at once` and
`vci: slots set up in 70.9 s at most; a file's process took 5.5 s on average, 12.1 s at most`.

**Tests.** `e2e_rails.rs`: `rails_slots_give_what_one_process_per_file_gives` runs the twenty files of
`rails_batch_mode_gives_what_one_process_per_file_gives` with `VCI_RAILS_JOBS=3` against one process per file in
another copy: the same files attested and refused for the same reasons (the three failing files fail only
themselves), the same exit code, every one-file entry in the slot run's manifest and nothing else but absent lookups in
`lib/` and `vendor/` (`same_entries`), the plan afterwards and changes that re-run files; then two files that collide
on one database (each, without transactions, inserts a row named `collide`, sleeps 2 s and expects to be the only one)
and a failing file, three slots: both attested, the failure refused, exit 1, `db/test.sqlite3_{0,1,2}` made. With
`ActiveSupport.parallelize_test_databases = false` (slots sharing `db/test.sqlite3`), the same two files fail
(`Expected: [1] Actual: [1, 2]`), so the test tells shared from separate databases. The whole of `e2e_rails.rs` and
`e2e_rspec.rs` passes with the default (no `parallelize` in the fixtures: one at a time), `VCI_RAILS_JOBS=1` and
`VCI_RAILS_JOBS=3`; under slots three assertions that compare a slot run with a one-file run allow the slot's setup
(`same_entries`, the slot databases in `db/`'s listing, and B's attestation count in
`rails_database_contents_are_not_an_input`), and the batch log assertions match its new tail. `collector_test.rb`:
`test_batch_slots_run_files_as_rails_workers` (a stand-in for Rails' Parallelization hooks and ParallelizeExecutor:
before-fork hooks once in the group, after-fork hooks once per slot with its index, what they read in each file's
inputs, `should_parallelize?` true in a file's process while the executor's own `start` sees false, each slot's
temp dir and its cleanup between files, the cleanup hooks at the end, the deal of the first files, results and exit
statuses per file), `test_batch_slots_send_back_what_they_cannot_run` (no `parallelize`: one at a time; asked: slots;
one slot's setup failing: the other runs both files; every slot's failing: files sent back; a write where the boot's
temp dir is: every file sent back), `test_batch_slots_send_back_a_transient_write_outside_their_temp_dirs` (a file
writes `BOOT_TMP/flag` and removes it while a file of the other slot finds it: both sent back),
`test_batch_groups_do_not_see_what_earlier_groups_left_in_the_temp_dir` (a boot's file and a slot's cleanup hook's
file are gone for the next group, one at a time and in slots), `test_batch_slots_follow_the_projects_parallelize_workers`
(`workers: 1`: one at a time; `workers: 2`: two slots; vci's `PARALLEL_WORKERS` or `VCI_RAILS_JOBS` overrides it),
`test_batch_files_without_a_boot_run_one_at_a_time`; each fails with its fix taken out. The adapter:
`batch_output_is_read_per_file` (slots, a slot's own lines, a later why overriding an exit, timings),
`rails_slots_follow_the_environment` (`PARALLEL_WORKERS=1` or `0`: one slot).

**Measurements (vex-api).** Release `vci` built from this tree, a throwaway key, a clone with its own test database
(`vex_slots`; slots `vex_slots_0..7`), `/usr/bin/time -l env VCI_RAILS_JOBS=<W> mise exec -- vci run <files> --key
<key>`:

| | wall | user + sys | test time (files' own) | attested / refused |
|---|---|---|---|---|
| 50 files (B's list), W=1 (vci 2.0's batch; B measured 1,110.0 s on master `2b59eb17cc`) | 1432.9 s | 226.1 s + 83.2 s | 1126.0 s | 47 / 3 |
| 50 files, W=8 | 167.6 s | 249.8 s + 79.5 s | 63.6 s | 47 / 3, the same three |
| the `application` group, 939 files (`scripts/ci/rails-test-group.rb application` of every `test/**/*_test.rb`), W=8 | 1890.8 s | 4694.2 s + 1562.2 s | — | 894 / 45 |

The W=8 run of 50 files: slots set up in 70.9 s at most (eight concurrent `load_seed`s into eight databases, six of them
new), then 5.5 s per file's process on average (12.1 s at most): about 1.3 s of tests and the rest the collector's
output at exit (B: ~3.3 s) and the fork; 47 files signed afterwards. Against W=1 the same 47 files are attested and the
same 3 refused for the same reasons; their manifests (`dumpman` over the clone's store, the 47 pairs) differ by 660
`absent` lookups under `lib/active_record` and `vendor/active_record` (S5: 18 for 36 files, 12 for one, none for the
ten files of slots whose database was already current and only truncated), `VERBOSE` (absent) in `env`,
and the random request paths B found (243 only in the slot run, 245 only in W=1, `public/api/v1/organizations/org-<id>/...`):
nothing of a file's own run is missing otherwise.

The `application` group at W=8: 939 files in 1890.8 s, 2.0 s a file. About 950 s of it is the Ruby batch (the slots
set up in 57.0 s at most; a file's process took 5.5 s on average, 144.7 s at most) and about 940 s `vci` checking and
signing the 939 results one after another afterwards (the `attested`/`not attesting` lines arrived at one a second:
882 of them at 02:17:57, 939 at 02:18:54, the run having started at 01:47:23), so signing, not the tests, is now half
of the wall time. No file went back to one process per file. Refused: 6 with a skipped test, 2 without tests, 2 for
request paths that collide under case folding (`public/api/v1/organizations/ACME` and `.../acme` probed by one file:
not slot-related), and two kinds slots cause:

- 34 files `capturing inputs: vex-api/tmp/storage/worker-<pid>[/...] was read by the test but does not exist now`.
  vex-api's `parallelize_setup` points Active Storage at `tmp/storage/worker-#{Process.pid}` (the slot's process) and
  its `parallelize_teardown` removes that directory, as Rails' workers do when they exit; vci hashes a file's inputs
  after the batch, when the slot's teardown has removed what the files read there. Refused, as it must be (fail
  open). A per-worker root that survives the run (`worker-#{parallel_worker_id}` without the `rm_rf`, or cleaned in
  `parallelize_setup` instead) would let them be attested; whether they could then be skipped in CI is Lane C's
  question (tmp/ does not exist in a fresh checkout).
- 1 file `input changed during the run: vex-api/tmp/bazel-blobs/.../action_result/ddd...: modified during the run`:
  two slots' files wrote the same path in the repository's `tmp/` (S4); vci noticed and refused it.

At 16 slots (vex's CI runners have 16 cores) the Ruby batch would take about 939 × 5.5 s / 16 + 57 s ≈ 380 s if a
file's process kept its 5.5 s (this run used about 6.6 of the 14 cores on average: 6,256 CPU seconds over ~950 s),
and checking and signing another ~940 s unless they run in parallel too: about 22 minutes for the group in one job,
against 5 minutes for vex's plain `bin/rails test` with 16 workers. `vci ci --partition I/N` divides both.

**S8. Two batch-mode bugs this measurement found (vci 2.0's batch had both).** Neither shows in the 50 files; both
ran files of the `application` group again (two runs, stopped by hand, had run files 1,098 and 1,002 times for 939
files, and sent every file back):

- *A child Ruby process of a test took itself for the batch.* vex-api's `config/solid_queue_shutdown_test.rb` runs
  `ruby bin/rails runner <script>`, which inherits `RUBYOPT` (the collector) and `VCI_RAILS_BATCH`; the runner never
  asks for a test file, so at its exit the child said that every file of the batch must run on its own
  (`Batch.undriven!`; ten `{"done": true}` lines in one run). The first process to load the collector now names
  itself in `VCI_RAILS_BATCH_PID`, and only a process with that id is the batch: a child is a process without a test
  id and writes nothing (`test_batch_child_processes_are_not_the_batch`, which also starts a child running the loader
  on a file of the batch; it fails without the change), while a runner that execs Ruby again (a binstub or wrapper:
  the same id) stays the batch (`test_batch_runner_that_execs_ruby_again`; removing `VCI_RAILS_BATCH` at load, the
  first fix, lost the batch there and ran every file one process per file).
- *A boot that is a test file of the batch drove the batch again.* `ci/batch_queue_result_reuse_test.rb` starts with
  `require_relative "queue_result_reuse_test"`, another file of the batch, which is therefore its group's boot. The
  group's process required it from inside the runner's request for the first file, so the gate took it for the
  runner's request for a file of the batch and, `@target` being unset in a group's process, drove the whole batch again
  from there. The boot now loads as a plain require (`Batch.preload`: as the file's first statement loads it in a
  one-file run, its tests with it) (`test_batch_boot_that_is_a_test_file`; fails with 2.0.4's collector).

## Shared output: what a boot's files share, written once (vci 2.1)

Date: 2026-10-18. Same machine, Ruby 3.4.9, Rails 8.1.3.1; vex-api from a clone of vex-git master `3738f8486d` (no
remote, never pushed), its own test database (`vex_laneb`; slots `vex_laneb_0..7`), MySQL 8 in Docker.

At exit a file's process wrote its whole output, ~14,500 lines on vex-api, of which ~14,400 are what its boot had
recorded before the fork (the same for every file of the group): 3.5 s a file (B measured ~3.3 s), profiled in four
file processes as 1.8 to 2.0 s classifying ~21,500 records (`Output.classify`: real paths, gem lookups), 0.5 to 1.7 s
comparing the used gems' files with their archives (`GemVerify`), 0.3 to 0.4 s writing the lines, the rest under 0.1 s.

**O1. What is written once.** In the process files' processes fork from (the group's process, one file at a time; or
each slot, after its setup), before the first fork, `Batch.share!` forks a child that makes the output this process
would write if it ended now (`Output.lines_of(shared: true)`: no meta, no taints, no result, each line once; the
runner's checks of the batch's files, `loader_check`, left out), writes it to `$VCI_OUT/batch/shared-<pid>.jsonl`,
and sends back over a pipe (Marshal) how it classified each path, what it found in the gems' archives, the lines and
their sha256. The parent keeps these; every file's process inherits them. The child does the work because making
those lines loads and memoizes things (`DB.schema_files` requires Active Record's database tasks, `GemVerify`
requires `rubygems/package` and zlib, `Tz.source` may set up TZInfo's data source): in the parent they would be
loaded in every file's process, whose own run may load them (and record that) or not. Under slots the group's process
does it once before the slots fork (classifications only, no file), so a slot's own `share!` classifies only what
its setup recorded (0.8 to 1.4 s on vex-api against 3.0 to 3.6 s for a group's).

**O2. What a file's process writes.** At exit it still makes all of its lines, as before (`Output.lines_of`), but a
path the boot classified is not classified again and a gem file the boot compared with its archive is not compared
again (the same functions, given the boot's answers; `GemVerify` keeps each file's result and its place in the archive
so the taints come out in the same order). `Batch.split` then writes: its meta line; `{"kind":"shared", "base":
"shared-<pid>.jsonl", "sha256": <of that file>, "drop": [<indexes of shared lines that are not this file's>]}`; and
every line of its own that is not one of the shared lines (a line it has twice: once more), taints and result last as
before. Lines are compared as values (`Hash#eql?`), so a line that differs in any way is the file's own and the
shared line it replaces is dropped. On vex-api a file drops one or two lines (an `env` line whose `where` list grew:
`PARALLEL_WORKERS`, `FORCE_DATABASE_SELECTOR` read again from another place) and writes 6 to 120 of its own (its
test file, what it autoloaded, absent lookups, its result).

**O3. Reading it.** `read_batch` (rails.rs) reads each file's output with the shared lines it names
(`merge_shared`): the named file in `batch/` (a plain name, no path), checked against the sha256, then its lines but
those dropped, then the file's own lines but the `shared` line, parsed as one output (`parse_jsonl_text`). The
parser's sets do not depend on order, and taints are only in the file's own lines, so `Observed` is what the whole
output gives, taints in the same order. A file whose shared lines cannot be read as named (missing, another sha256,
an index they do not have, two `shared` lines, a bad name) runs again one process per file (`its output names lines
it shares with the other files of its boot, which vci could not read (...)`). An output with a `shared` line read
anywhere else is refused (`vci:unknown-record-kind:shared`).

**O4. Why it is sound.** The shared lines hold only what the process the files fork from had recorded before the
fork, which each file's process inherits. Nothing recorded after a fork is shared, and a file's process does not
trust the shared lines to be its own: it makes all of its lines and writes the difference both ways (its lines that
are not shared, the shared lines that are not its), so the two read together are its lines whatever happened after
the fork (a path written that the boot probed, a record deleted, a classification depending on a file's state such
as `DB.exempt`). What it reuses is the boot's classification of a path recorded before the fork and the boot's
comparison of a gem file with its archive: both depend only on the path and on files that do not change during a run
(the gems, the zone database, Ruby's directories), and a classification needing a gem the file's process does not
have is made again. Anything that fails in `share!` (the child dies, the pipe is garbled) leaves `@shared` unset and
every file's process writes all of its output; anything that fails in `split` writes all of that file's output.
`VCI_RAILS_SHARED_OUTPUT=0` (in vci's environment, passed on) does the same for the whole run.

**O5. Same output, checked.** Five vex-api files (the first five of B's 50), at W=1 and at W=3, with a scratch copy
of the collector (`scratchpad/laneB/dual`) that also kept, in each file's process, its whole lines (as above) and its
lines made again with the boot's classifications and gem checks forgotten (vci 2.0's output; only the result's
`durationMs`, the time it is made, differs): for every file, the split output read with its shared lines is, sorted,
byte for byte the whole output (14,407 to 14,519 lines at W=1; 14,422 to 14,521 at W=3); the whole output is line for
line, in the same order, vci 2.0's; and Rust's `Observed` of the two (`parse_jsonl_text`; `scratchpad/laneB/obscmp`) is
equal for all ten (10,046 to 10,140 probes, ~3,410 modules, 137 externals each). `cmp_shared.py`, output in
`scratchpad/laneB/cmp-w{1,3}.txt`.

**O6. Measurements (50 files, B's list).** Release `vci` built from this tree, a throwaway key, `/usr/bin/time -l env
VCI_RAILS_JOBS=<W> [VCI_RAILS_SHARED_OUTPUT=0] VCI_TIMING=1 mise exec -- vci run <files> --key <key>`, one run after
the other on this Mac (not otherwise idle). `a file's process wrote its output` is timed in each file's process from
the start of `Output.write!` to its end (`batch/output.jsonl`, which `vci run` now logs):

| | wall | user + sys | a file's output: average, longest | shared lines written | attested / refused |
|---|---|---|---|---|---|
| W=1, each file writes all (`VCI_RAILS_SHARED_OUTPUT=0`) | 1004.96 s | 214.70 s + 83.86 s | 3.50 s, 5.38 s | — | 47 / 3 |
| W=1, shared | 851.58 s | 88.87 s + 61.46 s | **0.17 s**, 1.42 s | once, 3.6 s | 47 / 3, the same |
| W=8, each file writes all | 136.79 s | 236.08 s + 78.68 s | 3.82 s, 6.34 s | — | 47 / 3, the same |
| W=8, shared | 135.18 s | 87.76 s + 57.61 s | **0.13 s**, 0.24 s | 8 times (once per slot), 0.8 s at most | 47 / 3, the same |

At W=1 the batch is 153 s shorter (3.3 s a file); the CPU time of the run drops from 299 s to 150 s. At W=8 a file's
process took 1.2 s on average instead of 4.9 s, but the wall time is the same: the slots' setup varied from run to
run (47.7 s and 62.2 s at most, eight concurrent seed loads) and vci checks and signs the 47 results one after another
afterwards. W=1's 1,005 s against S's 1,432.9 s for the same files and build: the machine, not the code (the files'
tests are most of it, B).

**O7. What is left per file.** The collector's work at exit is now ~0.1 to 0.2 s (making the ~14,500 lines from the
boot's answers, comparing them, writing ~100). Next: vci's own checking and signing of each result after the batch,
one after another (~1 s a file, `ssh-keygen -Y sign` per attestation; S7: about half of the `application` group's
wall time at W=8), and on the vci side parsing and hashing ~14,500 inputs per file, which the shared lines could let
it do once per boot (not done: `Observed` and the store are unchanged).

**Tests.** `collector_test.rb`: `test_batch_shared_output_is_each_files_own_output` (a file writing a path the boot
found absent, a file reading an environment variable the boot read elsewhere, the runner's checks of each file; one
at a time and in two slots: each file's output read with its shared lines is, sorted, the output written with
`VCI_RAILS_SHARED_OUTPUT=0`; the probe is dropped for the file that wrote the path only; one shared file per boot or
slot; it fails when the drops are not written); the batch helper reads every batch test's outputs as vci does, so the
existing batch tests check the merged output. rails.rs: `batch_shared_output_is_merged` (a merged `Observed` equals the
whole output's; another sha256, a missing index, a missing file, two references and a name outside `batch/` fall
back; the timings). `e2e_rails.rs`/`e2e_rspec.rs`: the batch tests now also check that the shared lines were used; the
manifests they compare, batch against one process per file, are the merged ones.

## Not done

- **Slots for RSpec with a database each**: rspec-rails has no parallel workers; a project using parallel_tests
  (`TEST_ENV_NUMBER` in `config/database.yml`) would need the configuration evaluated again in each slot. With
  `VCI_RAILS_JOBS`, RSpec slots share the test database (S3).
- **Signing in parallel**: after the slots, `vci` checks and signs each file one after another (about 1.1 s a file, B).
- **Reading the shared lines once in vci**: `read_batch` puts each file's output back together and parses ~14,500
  lines per file; the store and manifests are unchanged (Shared output, O7).
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
