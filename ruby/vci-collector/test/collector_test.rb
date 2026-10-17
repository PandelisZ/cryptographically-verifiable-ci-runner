# frozen_string_literal: true

# Tests of vci_collector.rb's mechanisms, each in a fresh Ruby process with
# the collector loaded through RUBYOPT (as `vci run` does), in a throwaway
# "repository". No Rails and no Bundler: what Rails adds is covered by the
# end-to-end tests (crates/vci-cli/tests/e2e_rails.rs).
#
#   ruby ruby/vci-collector/test/collector_test.rb

require "minitest/autorun"
require "json"
require "tmpdir"
require "fileutils"
require "digest"
require "rbconfig"

# VCI_COLLECTOR: run these tests against another copy (e.g. an older one,
# to see a regression test fail).
COLLECTOR = ENV["VCI_COLLECTOR"] || File.expand_path("../vci_collector.rb", __dir__)

class CollectorTest < Minitest::Test
  def setup
    @tmp = Dir.mktmpdir("vci-collector-test-")
    @repo = File.realpath(File.join(@tmp, "repo").tap { |d| FileUtils.mkdir_p(d) })
    @out = File.join(@tmp, "out").tap { |d| FileUtils.mkdir_p(d) }
    @tmpdir = File.realpath(File.join(@tmp, "t").tap { |d| FileUtils.mkdir_p(d) })
  end

  def teardown
    FileUtils.rm_rf(@tmp)
  end

  def put(rel, body = "")
    p = File.join(@repo, rel)
    FileUtils.mkdir_p(File.dirname(p))
    File.write(p, body)
    p
  end

  # Run `script` (Ruby source) in the repository with the collector on;
  # returns the parsed records.
  def collect(script, env: {}, args: [])
    put("script.rb", script)
    e = {
      "RUBYOPT" => "-r#{COLLECTOR}", "VCI_RAILS_MODE" => "collect", "VCI_OUT" => @out,
      "VCI_TEST_ID" => "script.rb", "VCI_ROOT" => @repo, "VCI_REPO" => @repo, "TMPDIR" => @tmpdir,
      "RUBYLIB" => nil, "BUNDLE_GEMFILE" => nil
    }.merge(env)
    out = IO.popen(e, [RbConfig.ruby, "script.rb", *args], chdir: @repo, err: %i[child out], &:read)
    file = File.join(@out, "#{Digest::SHA256.hexdigest("script.rb")}.jsonl")
    assert File.file?(file), "no collector output; process said:\n#{out}"
    File.readlines(file).map { |l| JSON.parse(l) }
  ensure
    FileUtils.rm_f(Dir[File.join(@out, "*")])
  end

  def installed?(name)
    Gem::Specification.find_by_name(name)
    true
  rescue Gem::MissingSpecError
    false
  end

  def paths(recs, kind)
    recs.select { |r| r["kind"] == kind }.map { |r| r["path"].delete_prefix("#{@repo}/") }
  end

  # Taints other than "not under Bundler" (these scripts never are).
  def taints(recs)
    recs.select { |r| r["kind"] == "taint" }.map { |r| r["reason"] }.reject { |t| t.start_with?("ruby:no-bundler") }
  end

  def test_require_records_shadowing_candidates_and_misses
    put("a/.keep")
    put("b/mod.rb", "MOD = 1\n")
    recs = collect(<<~RUBY)
      $LOAD_PATH.unshift(File.expand_path("b"))
      $LOAD_PATH.unshift(File.expand_path("a"))
      require "mod"
      begin
        require "optional_thing"
      rescue LoadError
      end
      begin
        require_relative "lib/missing"
      rescue LoadError
      end
    RUBY
    probes = paths(recs, "probe")
    assert_includes paths(recs, "module"), "b/mod.rb"
    %w[a/mod.rb a/mod.so a/mod.bundle].each { |p| assert_includes probes, p }
    refute_includes probes, "b/mod.so", "nothing after the hit"
    %w[a/optional_thing.rb b/optional_thing.rb b/optional_thing.bundle].each { |p| assert_includes probes, p }
    %w[lib/missing.rb lib/missing.so].each { |p| assert_includes probes, p }
  end

  def test_file_reads_stats_and_probes
    put("data/x.txt", "x\n")
    put("data/y.txt", "y\n")
    put("data/z.txt", "z\n")
    put("data/p.txt", "p\n")
    put("data/k.txt", "k\n")
    recs = collect(<<~RUBY)
      require "pathname"
      File.read("data/x.txt")
      Pathname.new("data/y.txt").read
      IO.readlines("data/z.txt")
      File.foreach("data/p.txt") { }
      open("data/k.txt") { |f| f.read }
      File.exist?("data/nope.txt")
      File.file?("data/x.txt")
      Pathname.new("data/also_nope").exist?
      test(?e, "data/test_nope")
      begin
        File.read("data/gone.txt")
      rescue Errno::ENOENT
      end
    RUBY
    reads = paths(recs, "read")
    %w[data/x.txt data/y.txt data/z.txt data/p.txt data/k.txt].each { |p| assert_includes reads, p }
    probes = paths(recs, "probe")
    %w[data/nope.txt data/also_nope data/test_nope data/gone.txt].each { |p| assert_includes probes, p }
    assert_includes paths(recs, "stat"), "data/x.txt"
    assert_empty taints(recs)
  end

  # Entry points that open files in C.
  def test_c_level_openers
    put("src/compiled.rb", "1\n")
    put("data/reopened.txt", "r\n")
    put("data/sys.txt", "s\n")
    put("data/a.txt", "a\n")
    recs = collect(<<~RUBY, args: ["data/a.txt"])
      RubyVM::InstructionSequence.compile_file("src/compiled.rb")
      io = File.open(__FILE__)
      io.reopen("data/reopened.txt")
      IO.new(IO.sysopen("data/sys.txt")).close
      ARGF.read
    RUBY
    reads = paths(recs, "read")
    %w[src/compiled.rb data/reopened.txt data/sys.txt].each { |p| assert_includes reads, p }
    assert(taints(recs).any? { |t| t.start_with?("ruby:ARGF.read") }, taints(recs).inspect)
  end

  def test_globs_and_listings
    put("cfg/locales/en.yml")
    put("cfg/locales/deep/fr.yml")
    put("cfg/other.txt")
    put("views/a.erb")
    recs = collect(<<~RUBY)
      Dir.glob("cfg/locales/**/*.{yml,rb}")
      Dir["views/*.erb"]
      Dir.children("cfg")
      Dir.glob("absent/*.rb")
    RUBY
    dirs = paths(recs, "readdir")
    %w[cfg/locales cfg/locales/deep views cfg].each { |d| assert_includes dirs, d }
    assert_includes paths(recs, "probe"), "absent"
  end

  def test_writes_and_self_produced_reads
    put("tmp/.keep")
    put("tmp/old.txt", "old")
    recs = collect(<<~RUBY)
      File.write("tmp/new.txt", "mine")
      File.read("tmp/new.txt")
      File.exist?("tmp/fresh.txt")
      File.open("tmp/fresh.txt", "w") { |f| f.write("x") }
      File.read("tmp/fresh.txt")
      File.read("tmp/old.txt")
      File.open("tmp/old.txt", "a") { |f| f.write("+") }
      FileUtils.mkdir_p("tmp/made/here") if defined?(FileUtils)
    RUBY
    writes = paths(recs, "write")
    %w[tmp/new.txt tmp/fresh.txt tmp/old.txt].each { |p| assert_includes writes, p }
    reads = paths(recs, "read")
    refute_includes reads, "tmp/new.txt", "the process's own output is not an input"
    refute_includes reads, "tmp/fresh.txt"
    refute_includes paths(recs, "probe"), "tmp/fresh.txt", "probed, then created by the process"
    assert_includes reads, "tmp/old.txt", "content that existed before the process"
  end

  def test_env_reads_and_enumeration
    recs = collect(<<~RUBY, env: { "APP_X" => "1" })
      ENV["APP_X"]
      ENV.fetch("APP_Y", nil)
      ENV.key?("APP_Z")
      ENV.to_h
    RUBY
    keys = recs.select { |r| r["kind"] == "env" }.map { |r| r["key"] }
    %w[APP_X APP_Y APP_Z * TZ].each { |k| assert_includes keys, k }
  end

  def test_processes_sockets_and_forks_taint
    recs = collect(<<~RUBY)
      `true`
      system("true")
      pid = spawn("true"); Process.wait(pid)
      IO.popen(["true"]) { |io| io.read }
      Kernel.system("true")
      if Process.respond_to?(:fork)
        pid = fork { exit!(0) }
        Process.wait(pid)
      end
      require "socket"
      begin
        TCPSocket.new("127.0.0.1", 1)
      rescue SystemCallError
      end
    RUBY
    t = taints(recs).join("\n")
    %w[process:backtick process:system process:spawn process:IO.popen process:Kernel.system process:fork
       network:TCPSocket.new].each { |want| assert_includes t, want }
  end

  def test_file_descriptors_opened_unseen_taint
    put("data/x.txt", "x")
    put("data/hidden.txt", "h")
    recs = collect(<<~RUBY)
      f = File.open("data/x.txt")
      File.new(f.fileno, autoclose: false).read # the same file: fine
      fd = VciCollector.quiet { File.open("data/hidden.txt").fileno }
      IO.for_fd(fd, autoclose: false).read # opened where vci could not see it
    RUBY
    assert_equal 1, taints(recs).count { |t| t.start_with?("ruby:fd-open:") }, taints(recs).inspect
  end

  def test_a_symlink_in_tmp_reads_the_repository_file
    put("data/secret.txt", "s")
    recs = collect(<<~RUBY)
      link = File.join(ENV["TMPDIR"], "l")
      File.symlink(File.expand_path("data/secret.txt"), link)
      File.read(link)
    RUBY
    assert_includes paths(recs, "read"), "data/secret.txt"
  end

  def test_reads_outside_the_repository_are_reported
    outside = File.join(@tmp, "outside.txt")
    File.write(outside, "o")
    recs = collect("File.read(#{outside.inspect})\n")
    # Reported as the file it is (its real path: /var -> /private/var).
    assert_includes recs.select { |r| r["kind"] == "read" }.map { |r| r["path"] }, File.realpath(outside)
  end

  def test_minitest_results
    passing = collect(<<~RUBY)
      require "minitest/autorun"
      class T < Minitest::Test
        def test_a = assert_equal(2, 1 + 1)
        def test_b = assert(true)
      end
    RUBY
    r = passing.find { |x| x["kind"] == "result" }
    assert_equal "passed", r["state"]
    assert_equal 2, r["tests"]
    skipped = collect(<<~RUBY)
      require "minitest/autorun"
      class T < Minitest::Test
        def test_a = skip("not here")
        def test_b = assert(true)
      end
    RUBY
    r = skipped.find { |x| x["kind"] == "result" }
    refute_equal "passed", r["state"]
    assert_equal 1, r["skipped"]
    empty = collect(<<~RUBY)
      require "minitest/autorun"
      class T < Minitest::Test
        def test_a = 1 + 1
      end
    RUBY
    assert_equal "no-assertions", empty.find { |x| x["kind"] == "result" }["state"]
    none = collect("1 + 1\n")
    assert_equal "failed", none.find { |x| x["kind"] == "result" }["state"]
  end

  # A test file that never loads Rails (a Minitest file under test/lib
  # requiring only minitest and plain Ruby) reports the bundle's railties
  # version, as the probe (which boots Rails) does, for both runners.
  # Regression: Minitest files reported "" and were refused ("toolchain seen
  # by the collector (... rails , ...) differs from the project's").
  def test_rails_version_without_loading_rails
    skip "railties is not installed for #{RUBY_VERSION}" unless installed?("railties")
    want = Gem::Specification.find_by_name("railties").version.to_s
    script = <<~RUBY
      gem "railties", "#{want}"
      raise "Rails was loaded" if defined?(::Rails::VERSION)
      require "minitest/autorun"
      class T < Minitest::Test
        def test_a = assert_equal(2, 1 + 1)
      end
    RUBY
    meta = collect(script).find { |r| r["kind"] == "meta" }
    assert_equal want, meta["rails"]
    meta = collect(script, env: { "VCI_RAILS_RUNNER" => "rspec" }).find { |r| r["kind"] == "meta" }
    assert_equal want, meta["rails"]
    # No railties at all: "" (a project without Rails), as the probe says.
    meta = collect("require 'minitest/autorun'\nclass T < Minitest::Test; def test_a = assert(true); end\n")
           .find { |r| r["kind"] == "meta" }
    assert_equal "", meta["rails"]
  end

  # Run `script` in probe mode (no output file): its stdout.
  def probe_run(script, env: {})
    put("script.rb", script)
    e = {
      "RUBYOPT" => "-r#{COLLECTOR}", "VCI_RAILS_MODE" => "probe", "VCI_ROOT" => @repo, "VCI_REPO" => @repo,
      "TMPDIR" => @tmpdir, "RUBYLIB" => nil, "BUNDLE_GEMFILE" => nil, "RAILS_ENV" => "test",
      "DATABASE_URL" => nil, "RAILS_GROUPS" => nil
    }.merge(env)
    IO.popen(e, [RbConfig.ruby, "script.rb"], chdir: @repo, err: %i[child out], &:read)
  end

  # `vci plan` reads the test environment's database adapters without
  # booting the application: config/database.yml as Rails reads it (ERB,
  # YAML aliases, `shared`), DATABASE_URL merged in by Active Record, hidden
  # configurations (replicas, database_tasks: false) included, as the probe
  # of the booted application (DB.adapters) reports them.
  def test_probe_without_booting_reads_the_database_adapters
    skip "activerecord is not installed" unless installed?("activerecord")
    script = "db = VciCollector::Probe.light_db\n" \
             "puts \"DB=\#{db.inspect} \#{VciCollector::Probe.instance_variable_get(:@light_db_error)}\"\n"
    db = lambda do |yml, env = {}|
      FileUtils.rm_f(File.join(@repo, "config/database.yml"))
      put("config/database.yml", yml) if yml
      out = probe_run(script, env: env)
      line = out.lines.find { |l| l.start_with?("DB=") }
      assert line, out
      line.delete_prefix("DB=").strip
    end
    default = "default: &default\n  adapter: sqlite3\n  pool: <%= ENV.fetch(\"RAILS_MAX_THREADS\") { 5 } %>\n"
    assert_equal '"sqlite3"', db.call("#{default}test:\n  <<: *default\n  database: db/test.sqlite3\n")
    assert_equal '""', db.call("#{default}development:\n  <<: *default\n"), "no test environment"
    assert_equal '"mysql2"', db.call("test:\n  adapter: <%= ENV.fetch(\"DB\", \"sqlite3\") %>\n", "DB" => "mysql2")
    assert_equal '"postgresql"', db.call("#{default}test:\n  <<: *default\n", "DATABASE_URL" => "postgres://h/d")
    multi = "test:\n  primary:\n    adapter: sqlite3\n    database: db/a.sqlite3\n" \
            "  replica:\n    adapter: sqlite3\n    database: db/a.sqlite3\n    replica: true\n" \
            "  cache:\n    adapter: mysql2\n    database: c\n    database_tasks: false\n"
    assert_equal '"mysql2;sqlite3"', db.call(multi)
    assert_equal '"sqlite3"', db.call("shared:\n  adapter: sqlite3\ntest:\n  database: db/t.sqlite3\n")
    # Without the file: DATABASE_URL alone, or no database at all.
    assert_equal '"mysql2"', db.call(nil, "DATABASE_URL" => "mysql2://h/d")
    assert_equal '""', db.call(nil)
    # ERB that needs the application: not read (vci boots it for this).
    got = db.call("test:\n  adapter: sqlite3\n  database: <%= Rails.root.join(\"db/t.sqlite3\") %>\n")
    assert got.start_with?("nil NameError"), got
  end

  # SQLite3 is loaded without booting exactly when Bundler.require(*Rails.groups)
  # (default, the environment, RAILS_GROUPS) would require it.
  def test_probe_without_booting_requires_what_bundler_require_would
    script = "require \"bundler\"\nputs \"AUTO=\#{VciCollector::Probe.autorequired?(\"sqlite3\")}\"\n"
    auto = lambda do |gemfile, env = {}|
      put("Gemfile", "source \"https://rubygems.org\"\n#{gemfile}")
      out = probe_run(script, env: { "BUNDLE_GEMFILE" => File.join(@repo, "Gemfile") }.merge(env))
      line = out.lines.find { |l| l.start_with?("AUTO=") }
      assert line, out
      line.delete_prefix("AUTO=").strip
    end
    assert_equal "true", auto.call("gem \"sqlite3\"\n")
    assert_equal "false", auto.call("gem \"sqlite3\", require: false\n")
    assert_equal "false", auto.call("group :development do\n  gem \"sqlite3\"\nend\n")
    assert_equal "true", auto.call("group :development do\n  gem \"sqlite3\"\nend\n", "RAILS_GROUPS" => "development")
    assert_equal "true", auto.call("group :test do\n  gem \"sqlite3\"\nend\n")
    assert_equal "true", auto.call("gem \"litedb\", require: [\"x\", \"sqlite3\"]\n")
    assert_equal "false", auto.call("gem \"rack\"\n")
  end

  def test_sqlite_files_outside_the_test_database_taint
    begin
      require "sqlite3"
    rescue LoadError
      skip "the sqlite3 gem is not installed for #{RUBY_VERSION}"
    end
    recs = collect(<<~RUBY)
      require "sqlite3"
      db = SQLite3::Database.new(File.join(ENV["TMPDIR"], "ok.sqlite3"))
      db.execute("select 1")
      SQLite3::Database.new("data.sqlite3").execute("select 1")
      begin
        db.execute("ATTACH DATABASE 'other.sqlite3' AS o")
      rescue SQLite3::Exception
      end
    RUBY
    t = taints(recs).join("\n")
    assert_includes t, "rails:sqlite-file:#{@repo}/data.sqlite3"
    refute_includes t, "ok.sqlite3"
    assert_includes t, "rails:sqlite-attach"
  end

  # config/database.yml as Rails reads it (Rails::Application::Configuration
  # #database_configuration, which the collector hooks): the test
  # environment's SQLite files are db/test.sqlite3 and, as in a Rails 8
  # multi-database app, storage/test_cache.sqlite3.
  RAILS_DB_CONFIG = <<~RUBY
    module Rails
      class Application
        class Configuration
          def database_configuration
            { "test" => { "primary" => { "adapter" => "sqlite3", "database" => "db/test.sqlite3" },
                          "cache" => { "adapter" => "sqlite3", "database" => "storage/test_cache.sqlite3" } },
              "development" => { "adapter" => "sqlite3", "database" => "db/development.sqlite3" } }
          end
        end
      end
    end
    Rails::Application::Configuration.new.database_configuration
  RUBY

  # The test environment's SQLite files and their -wal, -shm and -journal
  # siblings are the test engine's database: no read, stat, probe or write
  # of them is recorded and opening them is accepted; a listing of their
  # directory leaves them out (exclude records). Any other SQLite file
  # (another environment's, one elsewhere in the repository) is refused.
  def test_test_database_files_are_not_inputs
    begin
      require "sqlite3"
    rescue LoadError
      skip "the sqlite3 gem is not installed for #{RUBY_VERSION}"
    end
    put("db/schema.rb", "# schema\n")
    put("db/test.sqlite3-journal", "")
    put("storage/.keep", "")
    recs = collect(RAILS_DB_CONFIG + <<~RUBY, env: { "RAILS_ENV" => "test" })
      require "sqlite3"
      File.exist?("db/test.sqlite3")
      File.exist?("storage/test_cache.sqlite3-wal")
      db = SQLite3::Database.new("db/test.sqlite3")
      db.execute("create table t (x)")
      db.close
      SQLite3::Database.new(File.expand_path("storage/test_cache.sqlite3")).close
      File.size("db/test.sqlite3")
      File.read("db/test.sqlite3")
      File.exist?("db/test.sqlite3-journal")
      File.write("db/test.sqlite3-wal", "")
      File.delete("db/test.sqlite3-wal")
      File.write("storage/test_cache.sqlite3-shm", "")
      Dir.children("db")
      Dir.children("storage")
      File.read("db/schema.rb")
      File.exist?("db/development.sqlite3")
    RUBY
    dbish = ->(p) { p.start_with?("db/test.sqlite3", "storage/test_cache.sqlite3") }
    recs.each do |r|
      next unless r["path"]
      rel = r["path"].delete_prefix("#{@repo}/")
      refute dbish.call(rel) && r["kind"] != "exclude", "recorded: #{r.inspect}"
    end
    excluded = paths(recs, "exclude").sort
    want = %w[db/test.sqlite3 storage/test_cache.sqlite3].flat_map do |f|
      ["", "-wal", "-shm", "-journal"].map { |x| "#{f}#{x}" }
    end.sort
    assert_equal want, excluded
    assert_includes paths(recs, "readdir"), "db"
    assert_includes paths(recs, "readdir"), "storage"
    assert_includes paths(recs, "read"), "db/schema.rb"
    assert_includes paths(recs, "probe"), "db/development.sqlite3", "not the test environment's"
    assert_empty taints(recs).grep(/sqlite/)

    # Any other SQLite file is still refused: another environment's, one
    # elsewhere in the repository, and ATTACH.
    recs = collect(RAILS_DB_CONFIG + <<~RUBY, env: { "RAILS_ENV" => "test" })
      require "sqlite3"
      SQLite3::Database.new("db/development.sqlite3").close
      SQLite3::Database.new("db/other.sqlite3").close
      db = SQLite3::Database.new("db/test.sqlite3")
      begin
        db.execute("ATTACH DATABASE 'db/other.sqlite3' AS o")
      rescue SQLite3::Exception
      end
    RUBY
    t = taints(recs).join("\n")
    assert_includes t, "rails:sqlite-file:#{@repo}/db/development.sqlite3"
    assert_includes t, "rails:sqlite-file:#{@repo}/db/other.sqlite3"
    refute_includes t, "rails:sqlite-file:#{@repo}/db/test.sqlite3 "
    assert_includes t, "rails:sqlite-attach"
    # Without a test environment there is no configured database.
    recs = collect(RAILS_DB_CONFIG + "require \"sqlite3\"\nSQLite3::Database.new(\"db/test.sqlite3\").close\n",
                   env: { "RAILS_ENV" => "production" })
    assert_includes taints(recs).join("\n"), "rails:sqlite-file:#{@repo}/db/test.sqlite3"
  end

  # Only ":memory:" (plain, or as a file: URI's path) and a file: URI whose
  # last `mode` parameter is "memory" are in-memory databases (SQLite
  # decodes %HH escapes first). Any other name opens a file, however much of
  # it reads "mode=memory" or ":memory:": a file outside the test
  # environment's databases is refused.
  def test_sqlite_names_that_open_files_are_not_in_memory
    begin
      require "sqlite3"
    rescue LoadError
      skip "the sqlite3 gem is not installed for #{RUBY_VERSION}"
    end
    files = ["mode=memory.sqlite3", "data.sqlite3", "x.sqlite3", "y.sqlite3"]
    recs = collect(<<~RUBY)
      require "sqlite3"
      #{files.inspect}.each { |f| SQLite3::Database.new(f).execute("create table t (x)") }
      [
        "mode=memory.sqlite3", "file:data.sqlite3?x=mode=memory", "file:x.sqlite3?mode=memory&mode=rw",
        "file::memory:z", "file:da%74a.sqlite3", "file://localhost\#{Dir.pwd}/y.sqlite3",
        ":memory:", "file::memory:", "file:w.sqlite3?mode=rw&mode=memory", "file:v.sqlite3?mode=%6Demory", ""
      ].each { |n| SQLite3::Database.new(n).execute("select 1") }
    RUBY
    t = taints(recs)
    [*files, ":memory:z"].each do |f|
      assert t.any? { |x| x.start_with?("rails:sqlite-file:#{@repo}/#{f} ") }, "#{f} is a file: #{t.inspect}"
    end
    %w[w.sqlite3 v.sqlite3].each { |f| refute File.exist?(File.join(@repo, f)), "#{f} is in memory" }
    assert_equal files.size + 1, t.grep(/rails:sqlite-file:/).size, t.inspect
  end

  # An entry of the test environment that is not a SQLite database (a YAML
  # file under an entry Rails never opens, database_tasks: false): its reads
  # and checks are recorded like any file's. A configured database that is
  # absent or empty is SQLite's (nothing about it recorded but a read of its
  # content).
  def test_configured_files_that_are_not_sqlite_databases_are_inputs
    put("data/ref.yml", "flag: on\n")
    put("data/empty.sqlite3", "")
    config = RAILS_DB_CONFIG.sub('"cache" => {', <<~RUBY.chomp)
      "reference" => { "adapter" => "sqlite3", "database" => "data/ref.yml", "database_tasks" => false },
                          "empty" => { "adapter" => "sqlite3", "database" => "data/empty.sqlite3" },
                          "cache" => {
    RUBY
    recs = collect(config + <<~RUBY, env: { "RAILS_ENV" => "test" })
      File.read("data/ref.yml")
      File.exist?("data/ref.yml")
      File.exist?("data/ref.yml-wal")
      File.exist?("data/empty.sqlite3")
      File.read("data/empty.sqlite3")
      File.exist?("db/test.sqlite3")
      File.read("db/test.sqlite3") rescue nil
    RUBY
    assert_includes paths(recs, "read"), "data/ref.yml"
    assert_includes paths(recs, "stat"), "data/ref.yml"
    assert_includes paths(recs, "probe"), "data/ref.yml-wal"
    refute_includes paths(recs, "stat"), "data/empty.sqlite3"
    assert_includes paths(recs, "read"), "data/empty.sqlite3", "a read of its content"
    refute_includes paths(recs, "probe"), "db/test.sqlite3"
  end

  # Active Record connecting to a database server: accepted only for one of
  # the test environment's databases (config/database.yml as Rails read it
  # at boot). Another host, port or database through establish_connection,
  # a raw client made through the adapter's new_client, and a client the
  # test opens itself are refused. The servers here are closed ports: the
  # check is made before connecting.
  def test_active_record_server_connections_must_be_configured
    skip "activerecord and mysql2 are not installed" unless installed?("activerecord") && installed?("mysql2")
    db = <<~RUBY
      module Rails
        class Application
          class Configuration
            def database_configuration
              { "test" => { "primary" => { "adapter" => "mysql2", "host" => "127.0.0.1", "port" => 1, "database" => "vci_test" },
                            "replica" => { "adapter" => "mysql2", "host" => "127.0.0.1", "port" => 1, "database" => "vci_test", "replica" => true } },
                "development" => { "adapter" => "mysql2", "host" => "127.0.0.1", "port" => 1, "database" => "vci_dev" } }
            end
          end
        end
      end
      Rails::Application::Configuration.new.database_configuration
      require "active_record"
      require "mysql2"
      class Other < ActiveRecord::Base
        self.abstract_class = true
      end
      def try(config)
        Other.establish_connection(config)
        Other.connection.execute("select 1")
      rescue ActiveRecord::ActiveRecordError, Mysql2::Error
        nil
      end
    RUBY
    run = lambda do |script|
      taints(collect(db + script, env: { "RAILS_ENV" => "test" })).grep(/network:/)
    end
    assert_empty run.call("try(adapter: \"mysql2\", host: \"127.0.0.1\", port: 1, database: \"vci_test\")\n")
    assert_empty run.call("try(ActiveRecord::DatabaseConfigurations.new(Rails::Application::Configuration.new.database_configuration)" \
                          ".configs_for(env_name: \"test\").first)\n")
    {
      "try(adapter: \"mysql2\", host: \"127.0.0.1\", port: 1, database: \"other\")\n" => "127.0.0.1:1/other",
      "try(adapter: \"mysql2\", host: \"127.0.0.1\", port: 2, database: \"vci_test\")\n" => "127.0.0.1:2/vci_test",
      "try(adapter: \"mysql2\", host: \"127.0.0.1\", port: 1, database: \"vci_dev\")\n" => "127.0.0.1:1/vci_dev",
      "ENV[\"DATABASE_URL\"] = \"mysql2://127.0.0.1:2/x\"\ntry(adapter: \"mysql2\", host: \"127.0.0.1\", port: 1, database: \"vci_test\")\n" =>
        "DATABASE_URL",
      "require \"active_record/connection_adapters/mysql2_adapter\"\n" \
      "ActiveRecord::ConnectionAdapters::Mysql2Adapter.new_client(host: \"127.0.0.1\", port: 2) rescue nil\n" =>
        "127.0.0.1:2/"
    }.each do |script, where|
      t = run.call(script)
      assert t.any? { |x| x.start_with?("network:mysql2 (an Active Record connection to ") && x.include?(where) },
             "#{script}: #{t.inspect}"
    end
    t = run.call("Mysql2::Client.new(host: \"127.0.0.1\", port: 1, database: \"vci_test\") rescue nil\n")
    assert t.any? { |x| x.start_with?("network:mysql2 client") }, t.inspect
    # A file of the repository under a path that reads like Active Record's.
    put("lib/active_record/connection_adapters/sneaky.rb", "def sneaky = Mysql2::Client.new(host: \"127.0.0.1\", port: 2)\n")
    t = run.call("require_relative \"lib/active_record/connection_adapters/sneaky\"\nsneaky rescue nil\n")
    assert t.any? { |x| x.start_with?("network:mysql2 client") }, t.inspect
  end

  # PG: the target is what libpq would reach, from keywords, a connection
  # string or URL alike; PG::Connection.new's own connect_start (with the
  # addresses it resolved) is not checked again.
  def test_active_record_postgresql_connections_must_be_configured
    skip "activerecord and pg are not installed" unless installed?("activerecord") && installed?("pg")
    db = <<~RUBY
      module Rails
        class Application
          class Configuration
            def database_configuration
              { "test" => { "adapter" => "postgresql", "url" => "postgres://127.0.0.1:1/vci_test" } }
            end
          end
        end
      end
      Rails::Application::Configuration.new.database_configuration
      require "active_record"
      require "pg"
      def try(config)
        ActiveRecord::Base.establish_connection(config)
        ActiveRecord::Base.connection.execute("select 1")
      rescue ActiveRecord::ActiveRecordError, PG::Error
        nil
      end
    RUBY
    run = ->(script) { taints(collect(db + script, env: { "RAILS_ENV" => "test" })).grep(/network:/) }
    assert_empty run.call("try(:test)\n")
    assert_empty run.call("try(adapter: \"postgresql\", host: \"127.0.0.1\", port: 1, database: \"vci_test\")\n")
    t = run.call("try(adapter: \"postgresql\", url: \"postgres://127.0.0.1:1/other\")\n")
    assert t.any? { |x| x.start_with?("network:postgresql (an Active Record connection to 127.0.0.1:1/other") }, t.inspect
    t = run.call("PG.connect(\"postgres://127.0.0.1:1/vci_test\") rescue nil\n")
    assert t.any? { |x| x.start_with?("network:postgresql client") }, t.inspect
  end

  # The schema files of every database of the test environment are inputs
  # once Active Record is loaded, whether or not the process read them (on
  # a fresh database `bin/rails db:test:prepare`, the engine's child, loads
  # them): read when present, probed when absent. A database whose schema
  # is not dumped (schema_dump: false) has none.
  def test_schema_files_of_the_test_databases_are_inputs
    skip "activerecord is not installed" unless installed?("activerecord")
    put("db/schema.rb", "# schema\n")
    config = RAILS_DB_CONFIG.sub('"cache" => {', <<~RUBY.chomp)
      "queue" => { "adapter" => "sqlite3", "database" => "storage/test_queue.sqlite3", "schema_dump" => false },
                          "cache" => {
    RUBY
    recs = collect(config + <<~RUBY, env: { "RAILS_ENV" => "test" })
      require "active_record"
      ActiveRecord::Base
      ActiveRecord::Tasks::DatabaseTasks.db_dir = "db"
    RUBY
    assert_includes paths(recs, "read"), "db/schema.rb"
    assert_includes paths(recs, "probe"), "db/cache_schema.rb"
    refute recs.any? { |r| r["path"].to_s.include?("queue_schema") }, "schema_dump: false"
    assert_empty taints(recs).grep(/schema-files/)
    put("db/cache_schema.rb", "# cache\n")
    recs = collect(config + "require \"active_record\"\nActiveRecord::Base\nActiveRecord::Tasks::DatabaseTasks.db_dir = \"db\"\n",
                   env: { "RAILS_ENV" => "test" })
    assert_includes paths(recs, "read"), "db/cache_schema.rb"
    # Without Active Record: nothing.
    recs = collect(config, env: { "RAILS_ENV" => "test" })
    refute_includes paths(recs, "read"), "db/schema.rb"
  end

  # Active Record's schema maintenance (ActiveRecord::Migration.load_schema!,
  # which maintain_test_schema! calls when the test database's schema is not
  # current) runs `system("bin/rails db:test:prepare")` in Rails.root: that
  # child is the engine's (not refused), and runs with VCI_RAILS_MODE=engine,
  # where the collector does nothing. The same call from anywhere else (the
  # test, a copy of migration.rb in the repository), another command, or the
  # same command in another directory is refused.
  def test_active_record_schema_maintenance_child_is_the_engines
    gem_dir = File.join(@tmp, "gems", "activerecord-9.9.9")
    migration = <<~RUBY
      module ActiveRecord
        class Migration
          def self.load_schema!(root, cmd = "bin/rails db:test:prepare")
            Dir.chdir(root) do
              system(cmd)
            end
          end
        end
      end
    RUBY
    FileUtils.mkdir_p(File.join(gem_dir, "lib/active_record"))
    File.write(File.join(gem_dir, "lib/active_record/migration.rb"), migration)
    put("lib/active_record/migration.rb", migration.sub("module ActiveRecord", "module Fake"))
    child = File.join(@tmpdir, "child.txt")
    rails = "#!#{RbConfig.ruby}\nFile.write(ENV.fetch(\"VCI_TEST_CHILD_OUT\"), [ENV[\"VCI_RAILS_MODE\"], defined?(VciCollector).inspect].join(\" \"))\n"
    elsewhere = File.join(@tmp, "elsewhere")
    [@repo, elsewhere].each do |d|
      FileUtils.mkdir_p(File.join(d, "bin"))
      File.write(File.join(d, "bin/rails"), rails)
      File.chmod(0o755, File.join(d, "bin/rails"))
    end
    setup = <<~RUBY
      spec = Gem::Specification.new { |s| s.name = "activerecord"; s.version = "9.9.9" }
      spec.instance_variable_set(:@full_gem_path, #{gem_dir.inspect})
      Gem.loaded_specs["activerecord"] = spec
      load #{File.join(gem_dir, "lib/active_record/migration.rb").inspect}
    RUBY
    env = { "VCI_TEST_CHILD_OUT" => child }
    recs = collect(setup + "ActiveRecord::Migration.load_schema!(Dir.pwd)\n", env: env)
    assert_equal "engine nil", File.read(child), "the child's collector did nothing"
    refute_includes taints(recs).join("\n"), "process:"
    assert recs.any? { |r| r["kind"] == "meta" }, "the parent's output is its own"

    refused = lambda do |script, why|
      File.delete(child) if File.exist?(child)
      recs = collect(setup + script, env: env)
      assert_includes taints(recs).join("\n"), "process:system", why
      assert File.read(child).start_with?("collect "), "#{why}: the child runs with the collector as it is" if File.exist?(child)
    end
    refused.call("require_relative \"lib/active_record/migration\"\nFake::Migration.load_schema!(Dir.pwd)\n",
                 "a copy of migration.rb that is not the activerecord gem's")
    refused.call("ActiveRecord::Migration.load_schema!(#{elsewhere.inspect})\n", "another directory")
    refused.call("ActiveRecord::Migration.load_schema!(Dir.pwd, \"bin/rails db:test:prepare; true\")\n",
                 "another command")
    refused.call("system(\"bin/rails db:test:prepare\")\n", "the test's own call")
  end

  # Under Bundler on Ruby 3.4, bundled_gems.rb redefines Kernel#require to
  # call Kernel.no_warning_require (an alias of Kernel.require): a plain
  # require must still be seen (its shadowing candidates recorded, and the
  # libraries it loads hooked).
  def test_requires_under_bundler_reach_the_hook
    put("Gemfile", "source \"https://rubygems.org\"\n")
    put("ext1/.keep")
    put("ext2/feat.rb", "FEAT = \"ext2\"\n")
    recs = collect(<<~RUBY)
      require "bundler/setup"
      raise "bundled_gems is not active" unless Kernel.respond_to?(:no_warning_require, true) || Kernel.singleton_class.respond_to?(:no_warning_require, true)
      $LOAD_PATH.unshift(File.expand_path("ext2"))
      $LOAD_PATH.unshift(File.expand_path("ext1"))
      require "feat"
      require "pty"
      PTY.spawn("true") { |r, w, pid| Process.wait(pid) }
      require "fiddle"
      Fiddle.dlopen(nil)
    RUBY
    assert_includes paths(recs, "probe"), "ext1/feat.rb", "the candidate that would shadow ext2/feat.rb"
    t = taints(recs).join("\n")
    assert_includes t, "process:PTY.spawn"
    assert_includes t, "native:Fiddle"
  end

  # A database client required lazily under Bundler (gem "pg", require: false).
  def test_database_client_required_lazily_under_bundler
    skip "the pg gem is not installed for #{RUBY_VERSION}" unless installed?("pg")
    v = Gem::Specification.find_by_name("pg").version
    put("Gemfile", "source \"https://rubygems.org\"\ngem \"pg\", \"#{v}\", require: false\n")
    recs = collect(<<~RUBY, env: { "BUNDLE_GEMFILE" => File.join(@repo, "Gemfile") })
      require "bundler/setup"
      require "pg"
      begin
        PG.connect(host: "/nonexistent-vci-socket-dir")
      rescue PG::Error
      end
    RUBY
    assert_includes taints(recs).join("\n"), "network:postgresql client"
  end

  # A library loaded where no require hook sees it is still hooked (when its
  # constants are defined).
  def test_libraries_loaded_unseen_are_hooked
    recs = collect(<<~RUBY)
      VciCollector.quiet { require "pty" }
      PTY.spawn("true") { |r, w, pid| Process.wait(pid) }
    RUBY
    assert_includes taints(recs).join("\n"), "process:PTY.spawn"
  end

  def test_fiddle_and_ffi_calls_taint
    recs = collect(<<~RUBY)
      require "fiddle"
      libc = Fiddle::Handle::DEFAULT
      Fiddle::Function.new(libc["getpid"], [], Fiddle::TYPE_INT).call
    RUBY
    assert_includes taints(recs).join("\n"), "native:Fiddle::Function"
    skip "the ffi gem is not installed for #{RUBY_VERSION}" unless installed?("ffi")
    recs = collect(<<~RUBY)
      require "ffi"
      module L
        extend FFI::Library
        ffi_lib FFI::Library::LIBC
        attach_function :getpid, [], :int
      end
      L.getpid
    RUBY
    assert_includes taints(recs).join("\n"), "native:FFI call L.getpid"
    # attach_function without ffi_lib (the process's own symbols), a
    # Function called directly, a function attached by hand.
    recs = collect(<<~RUBY)
      require "ffi"
      module M
        extend FFI::Library
        ffi_lib FFI::CURRENT_PROCESS
        attach_function :getpid, [], :int
      end
      M.getpid
      fn = FFI::Function.new(:int, [], FFI::DynamicLibrary.open(nil, 0).find_function("getpid"))
      fn.call
      module N; end
      FFI::Function.new(:int, [], FFI::DynamicLibrary.open(nil, 0).find_function("getppid")).attach(N, "pp")
      N.pp
    RUBY
    t = taints(recs).join("\n")
    assert_includes t, "native:FFI call M.getpid"
    assert_includes t, "native:FFI FFI::Function#call"
    assert_includes t, "native:FFI call N.pp"
    # A variadic function: its call is the attached method's, not a direct one.
    recs = collect(<<~RUBY)
      require "ffi"
      module V
        extend FFI::Library
        ffi_lib FFI::Library::LIBC
        attach_function :snprintf, [:pointer, :size_t, :string, :varargs], :int
      end
      buf = FFI::MemoryPointer.new(:char, 8)
      V.snprintf(buf, 8, "%d", :int, 42)
    RUBY
    t = taints(recs)
    assert_includes t.join("\n"), "native:FFI call V.snprintf"
    assert_empty t.grep(/VariadicInvoker/), t.join("\n")
  end

  # Loading a library is not a read of test inputs: it is recorded (an
  # external "native:<file name>" hashed by content), and only calling into
  # it refuses the file. A failed ffi_lib records and refuses nothing.
  # Regression: ffi_lib tainted before calling super, so a LoadError (an
  # optional library that is not installed) still refused the file.
  def test_ffi_library_loads_are_recorded_and_failed_loads_are_nothing
    skip "the ffi gem is not installed for #{RUBY_VERSION}" unless installed?("ffi")
    recs = collect(<<~RUBY)
      require "ffi"
      module Optional
        extend FFI::Library
        begin
          ffi_lib "vci_no_such_library_#{Process.pid}"
          attach_function :nothing, [], :int
        rescue LoadError
        end
      end
      module L
        extend FFI::Library
        ffi_lib FFI::Library::LIBC
        attach_function :getpid, [], :int
      end
    RUBY
    assert_empty taints(recs).grep(/FFI|native/), taints(recs).join("\n")
    natives = recs.select { |r| r["kind"] == "external" && r["name"].start_with?("native:") }
    refute_empty natives
    refute natives.any? { |r| r["name"].include?("vci_no_such_library") }, natives.inspect
  end

  def vips_available?
    installed?("ruby-vips") && installed?("ffi") &&
      system(RbConfig.ruby, "-e", "require 'vips'", out: File::NULL, err: File::NULL)
  end

  PNG_3x2 = "iVBORw0KGgoAAAANSUhEUgAAAAMAAAACCAAAAAC4HznGAAAAtGVYSWZJSSoACAAAAAYAEgEDAAEAAAABAAAAGgEFAAEAAABWAAAAGwEFAAEAAABeAAAAKAEDAAEAAAACAAAAEwIDAAEAAAABAAAAaYcEAAEAAABmAAAAAAAAADhjAADoAwAAOGMAAOgDAAAGAACQBwAEAAAAMDIxMAGRBwAEAAAAAQIDAACgBwAEAAAAMDEwMAGgAwABAAAA//8AAAKgBAABAAAAAwAAAAOgBAABAAAAAgAAAAAAAABtADtDAAAACXBIWXMAAAPoAAAD6AG1e1JrAAAAC0lEQVQImWNggAAAAAgAAa9T6iIAAAAASUVORK5CYII="

  def put_png(rel)
    require "base64"
    put(rel, Base64.strict_decode64(PNG_3x2))
  end

  # ruby-vips over libvips: loading it and working on images in memory is
  # attestable; the files libvips reads and writes through ruby-vips' entry
  # points are recorded; everything else that could touch a file refuses.
  def test_vips_loads_and_records_its_file_entry_points
    skip "ruby-vips with libvips is not available" unless vips_available?
    put_png("img/a.png")
    put("out/.keep")
    recs = collect(<<~RUBY)
      require "vips"
      Vips.block_untrusted(true)
      raise "version" unless Vips.at_least_libvips?(8, 0)
    RUBY
    assert_empty taints(recs), taints(recs).join("\n")
    lib = recs.find { |r| r["kind"] == "external" && r["name"].match?(/\Anative:(lib)?vips/) }
    assert lib, recs.select { |r| r["kind"] == "external" }.inspect
    assert_match(/\Asha256:[0-9a-f]{64}\z/, lib["version"])

    recs = collect(<<~RUBY)
      require "vips"
      im = Vips::Image.new_from_file("img/a.png", access: :sequential)
      raise "size" unless [im.width, im.height] == [3, 2]
      raise "avg" unless im.avg.zero?
      t = Vips::Image.thumbnail("img/a.png", 2)
      (im + 1).write_to_file("out/b.png")
      buf = File.binread("img/a.png")
      Vips::Image.new_from_buffer(buf, "").write_to_buffer(".png")
      Vips::Image.new_from_source(Vips::Source.new_from_file("img/a.png"), "").avg
      Vips::Image.black(2, 2).embed(1, 1, 4, 4).write_to_buffer(".jpg[Q=90,profile=srgb]")
      Vips::Image.thumbnail("img/a.png", 2, export_profile: "srgb")
    RUBY
    assert_empty taints(recs), taints(recs).join("\n")
    assert_includes paths(recs, "read"), "img/a.png"
    assert_includes paths(recs, "write"), "out/b.png"
  end

  def test_vips_file_access_vci_cannot_see_refuses
    skip "ruby-vips with libvips is not available" unless vips_available?
    put_png("img/a.png")
    {
      # libvips functions called directly: an operation built outside
      # Operation.call, a descriptor source, a function vci does not know.
      <<~RUBY => "native:vips:pngload built outside Vips::Operation.call",
        require "vips"
        op = Vips::Operation.new("pngload")
        op.set("filename", "img/a.png", nil, 0, GObject::GSTR_TYPE, false)
        op.build
      RUBY
      <<~RUBY => "native:vips:vips_source_new_from_descriptor",
        require "vips"
        Vips::Source.new_from_descriptor(File.open("img/a.png").fileno)
      RUBY
      <<~RUBY => "native:vips:text",
        require "vips"
        Vips::Image.text("hello")
      RUBY
      <<~RUBY => "native:vips:svgload",
        require "vips"
        File.write("img/x.svg", "<svg xmlns='http://www.w3.org/2000/svg' width='2' height='2'/>")
        Vips::Image.svgload("img/x.svg") rescue nil
      RUBY
      <<~RUBY => "native:vips:icc_transform with the ICC profile",
        require "vips"
        Vips::Image.black(2, 2).icc_transform("/tmp/vci-no-such.icc") rescue nil
      RUBY
      <<~RUBY => "native:vips:option string \"[filename=/etc/hosts]\" names a file",
        require "vips"
        Vips::Image.new_from_file("img/a.png[filename=/etc/hosts]") rescue nil
      RUBY
      <<~RUBY => "native:vips:thumbnail with the ICC profile \"/tmp/vci-no-such.icc\"",
        require "vips"
        Vips::Image.thumbnail("img/a.png", 2, import_profile: "/tmp/vci-no-such.icc") rescue nil
      RUBY
      <<~RUBY => "names an ICC profile file",
        require "vips"
        Vips::Image.black(2, 2).write_to_buffer(".jpg[profile=/tmp/vci-no-such.icc]") rescue nil
      RUBY
      # A function of libvips attached by the test itself is not ruby-vips'.
      <<~RUBY => "native:FFI call Mine.vips_version",
        require "vips"
        module Mine
          extend FFI::Library
          ffi_lib Vips.ffi_libraries.first.name
          attach_function :vips_version, [:int], :int
        end
        Mine.vips_version(0)
      RUBY
    }.each do |script, want|
      t = taints(collect(script)).join("\n")
      assert_includes t, want, script
    end
  end

  def test_dir_open_and_opendir
    put("d/listed/a")
    put("d/listed/b")
    put("d/each/a")
    put("d/popen/a")
    recs = collect(<<~RUBY)
      require "pathname"
      Dir.open("d/listed") { |d| d.children.sort }
      Dir.open("d/each").each_child.to_a
      begin
        Dir.open("d/nodir")
      rescue Errno::ENOENT
      end
      Pathname.new("d/popen").opendir { |d| d.children }
      begin
        Dir.open("d/listed") { |_| File.read("d/missing.txt") }
      rescue Errno::ENOENT
      end
    RUBY
    dirs = paths(recs, "readdir")
    %w[d/listed d/each d/popen].each { |d| assert_includes dirs, d }
    probes = paths(recs, "probe")
    assert_includes probes, "d/nodir"
    refute_includes probes, "d/listed", "an error raised in the block is not a failed open"
    fd = collect(<<~RUBY)
      d = VciCollector.quiet { Dir.new("d/listed") }
      Dir.for_fd(d.fileno).children
    RUBY
    assert(taints(fd).any? { |t| t.start_with?("ruby:Dir.for_fd") }, taints(fd).inspect)
  end

  # What a scratch file held before the process replaced it is an input: a
  # read (or check) made before a truncating write, an atomic rewrite or a
  # delete is recorded; reads after it are the process's own output.
  def test_reads_before_a_scratch_file_is_replaced_are_inputs
    put("tmp/marker", "seen")
    put("tmp/atomic", "a1")
    put("tmp/gone", "g1")
    put("tmp/checked", "c1")
    put("tmp/unread", "u1")
    put("tmp/left/.keep")
    recs = collect(<<~RUBY)
      prev = File.exist?("tmp/marker") ? File.read("tmp/marker") : "none"
      File.write("tmp/marker", "seen")
      File.read("tmp/marker")
      File.read("tmp/atomic")
      tmp = "tmp/atomic.tmp"
      File.write(tmp, "a2")
      File.rename(tmp, "tmp/atomic")
      File.read("tmp/atomic")
      File.read("tmp/gone")
      File.delete("tmp/gone")
      File.write("tmp/gone", "g2")
      File.exist?("tmp/checked")
      File.write("tmp/checked", "c2")
      File.delete("tmp/unread")
      File.write("tmp/left/new.txt", "n")
    RUBY
    reads = paths(recs, "read")
    %w[tmp/marker tmp/atomic tmp/gone].each { |p| assert_includes reads, p, "read before it was replaced" }
    stats = paths(recs, "stat")
    assert_includes stats, "tmp/checked", "checked before it was replaced"
    assert_includes stats, "tmp/unread", "deleting it needs it to exist"
    assert_includes stats, "tmp/left", "writing tmp/left/new.txt needs the directory"
    refute_includes paths(recs, "probe"), "tmp/atomic.tmp"
    # The existing behaviour: reading back a file the process created.
    own = collect(<<~RUBY)
      File.write("tmp/own.txt", "mine")
      File.read("tmp/own.txt")
      File.exist?("tmp/own.txt")
    RUBY
    refute_includes paths(own, "read"), "tmp/own.txt"
    refute_includes paths(own, "stat"), "tmp/own.txt"
  end

  def test_bootsnap_compile_cache_taints
    skip "the bootsnap gem is not installed for #{RUBY_VERSION}" unless installed?("bootsnap")
    put("data/a.yml", "--- y1\n")
    recs = collect(<<~RUBY)
      require "yaml"
      require "bootsnap"
      Bootsnap.setup(cache_dir: File.expand_path("tmp/cache"), load_path_cache: false, compile_cache_iseq: false,
                     compile_cache_yaml: true)
      YAML.load_file("data/a.yml")
    RUBY
    assert(taints(recs).any? { |t| t.start_with?("ruby:bootsnap-compile-cache") }, taints(recs).inspect)
  end

  # A gem directory outside the bundle (here: none) holds whatever this
  # machine has installed.
  def test_reads_under_gem_roots_outside_the_bundle_taint
    root = File.join(@tmp, "gemroot")
    FileUtils.mkdir_p(File.join(root, "gems/fakegem-1.0"))
    File.write(File.join(root, "gems/fakegem-1.0/data.txt"), "r1\n")
    gem_path = ([root] + Gem.path).join(File::PATH_SEPARATOR)
    recs = collect(<<~RUBY, env: { "GEM_PATH" => gem_path })
      File.read(#{File.join(root, "gems/fakegem-1.0/data.txt").inspect})
      File.directory?(#{File.join(root, "gems/fakegem-2.0").inspect})
    RUBY
    t = taints(recs).join("\n")
    assert_includes t, "ruby:read-outside-bundle:read #{root}/gems/fakegem-1.0/data.txt"
    assert_includes t, "ruby:read-outside-bundle:probe #{root}/gems/fakegem-2.0"
    # RubyGems' own lookups there are not the test's.
    quiet = collect(<<~RUBY, env: { "GEM_PATH" => gem_path })
      Gem::Specification.find_all_by_name("fakegem")
      Gem.path
    RUBY
    refute(taints(quiet).any? { |x| x.start_with?("ruby:read-outside-bundle") }, taints(quiet).inspect)
  end

  # RubyGems' helpers reading, listing or evaluating a file of a gem that
  # is not in the bundle for a test do it for the test (they were exempt as
  # RubyGems' own reads), and a test's check of a directory above a loaded
  # gem's (where gems are installed) is the test's (it was dropped as
  # leading to a gem of the bundle).
  def test_gem_helpers_and_checks_under_gem_roots_are_the_tests
    root = File.join(@tmp, "gemroot")
    install = lambda do |name, code|
      FileUtils.mkdir_p(File.join(root, "gems/#{name}-1.0/lib"))
      File.write(File.join(root, "gems/#{name}-1.0/lib/#{name}.rb"), "$#{name}_lib = 1\n")
      File.write(File.join(root, "gems/#{name}-1.0/data.txt"), "#{name}\n")
      FileUtils.mkdir_p(File.join(root, "specifications"))
      File.write(File.join(root, "specifications/#{name}-1.0.gemspec"), <<~SPEC)
        # -*- encoding: utf-8 -*-
        # stub: #{name} 1.0 ruby lib

        #{code}
        Gem::Specification.new do |s|
          s.name = #{name.inspect}
          s.version = "1.0"
          s.summary = "x"
          s.authors = ["x"]
          s.require_paths = ["lib"]
        end
      SPEC
    end
    install.call("loadedfake", "")
    install.call("otherfake", "$otherfake_spec = 1")
    gem_path = ([root] + Gem.path).join(File::PATH_SEPARATOR)
    other = File.join(root, "gems/otherfake-1.0")
    recs = collect(<<~RUBY, env: { "GEM_PATH" => gem_path })
      require "loadedfake"
      raise "lib" unless $loadedfake_lib == 1
      raise "read" unless Gem.read_binary(#{File.join(other, "data.txt").inspect}) == "otherfake\\n"
      raise "glob" unless Gem::Util.glob_files_in_dir("*", #{other.inspect}).any? { |f| f.end_with?("/data.txt") }
      Gem::Specification.load(#{File.join(other, "lib/otherfake.rb").inspect})
      raise "eval" unless $otherfake_lib == 1
      Gem::Specification.load(#{File.join(root, "specifications/otherfake-1.0.gemspec").inspect})
      raise "spec" unless $otherfake_spec == 1
      raise "dir" unless File.directory?(#{File.join(root, "gems").inspect})
    RUBY
    res = recs.find { |r| r["kind"] == "result" }
    assert_equal 0, res["exitStatus"], res.inspect
    t = taints(recs).join("\n")
    assert_includes t, "ruby:read-outside-bundle:read #{other}/data.txt "
    assert_includes t, "ruby:read-outside-bundle:readdir #{other} "
    assert_includes t, "ruby:read-outside-bundle:read #{other}/lib/otherfake.rb "
    assert_includes t, "ruby:read-outside-bundle:read #{root}/specifications/otherfake-1.0.gemspec "
    assert_includes t, "ruby:read-outside-bundle:stat #{root}/gems "
    # The loaded gem's files are its own (an external), and RubyGems' reads
    # of every installed gemspec are its bookkeeping.
    outside = t.lines.grep(/\Aruby:(read|gem)-outside-bundle:/).join
    refute_includes outside, "loadedfake"
    assert_equal 5, outside.lines.size, outside
    assert(recs.any? { |r| r["kind"] == "external" && r["name"] == "loadedfake" }, recs.inspect)
  end

  def test_libxml2_external_resources_taint
    skip "the nokogiri gem is not installed for #{RUBY_VERSION}" unless installed?("nokogiri")
    put("data/ent.txt", "e1")
    put("data/doc.xml", "<r/>")
    recs = collect(<<~RUBY)
      require "nokogiri"
      xml = %(<!DOCTYPE r [<!ENTITY e SYSTEM "#{@repo}/data/ent.txt">]><r>&e;</r>)
      Nokogiri::XML(xml) { |c| c.noent.nonet }
    RUBY
    assert(taints(recs).any? { |t| t.start_with?("native:libxml2:Document.read_memory") }, taints(recs).inspect)
    plain = collect(<<~RUBY)
      require "nokogiri"
      Nokogiri::XML("<r><a/></r>").at("a")
      Nokogiri::XML(File.open("data/doc.xml"))
      Nokogiri::HTML("<p>x</p>")
    RUBY
    refute(taints(plain).any? { |t| t.start_with?("native:") }, taints(plain).inspect)
    assert_includes paths(plain, "read"), "data/doc.xml"
    schema = collect(<<~RUBY)
      require "nokogiri"
      Nokogiri::XML::Schema(%(<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:include schemaLocation="other.xsd"/></xs:schema>)) rescue nil
      Nokogiri::XML("<r/>").do_xinclude
      Nokogiri::XML::SAX::Parser.new(Nokogiri::XML::SAX::Document.new).parse_file("data/doc.xml")
    RUBY
    t = taints(schema).join("\n")
    assert_includes t, "native:libxml2:Schema"
    assert_includes t, "native:libxml2:XInclude"
    assert_includes paths(schema, "read"), "data/doc.xml"
  end

  # Times, permission bits and owners are not kept by git.
  def test_file_metadata_reads_taint
    put("data/old", "o")
    put("data/new", "n")
    recs = collect(<<~RUBY)
      File.mtime("data/new") >= File.mtime("data/old")
    RUBY
    assert(taints(recs).any? { |t| t.start_with?("ruby:file-metadata:File.mtime of data/new") }, taints(recs).inspect)
    {
      "File.stat(\"data/old\").mtime" => "File::Stat#mtime",
      "File.open(\"data/old\") { |f| f.mtime }" => "File#mtime",
      "File.open(\"data/old\") { |f| f.stat.mode }" => "File::Stat#mode",
      "File.world_readable?(\"data/old\")" => "File.world_readable?",
      "File.stat(\"data/new\") <=> File.stat(\"data/old\")" => "File::Stat#<=>",
      "require \"pathname\"; Pathname.new(\"data/old\").ctime" => "File.ctime"
    }.each do |code, what|
      r = collect("#{code}\n")
      assert(taints(r).any? { |t| t.start_with?("ruby:file-metadata:#{what}") }, "#{code}: #{taints(r).inspect}")
    end
    fine = collect(<<~RUBY)
      require "fileutils"
      File.size("data/old")
      File.executable?("data/old")
      FileUtils.cp("data/old", File.join(ENV["TMPDIR"], "copy"))
      File.write("tmp_own.txt", "x")
      File.mtime("tmp_own.txt")
      File.mtime(ENV["TMPDIR"])
      # ActiveSupport's File.atomic_write probing a directory's permissions.
      File.open("probe", "w") {}
      st = File.stat("probe")
      File.unlink("probe")
      [st.uid, st.gid, st.mode]
    RUBY
    refute(taints(fine).any? { |t| t.start_with?("ruby:file-metadata") }, taints(fine).inspect)
    net = collect(<<~RUBY)
      require "socket"
      Socket.ip_address_list
    RUBY
    assert_includes taints(net).join("\n"), "network:Socket.ip_address_list"
  end

  # A test that replaces File.directory?, File.exist?, Dir.children or
  # File.expand_path (rspec-mocks' allow(File).to receive, Minitest's
  # File.stub) changes what the test sees, never what the collector records:
  # it uses the methods captured when it loaded.
  def test_stubbed_file_methods_do_not_hide_real_reads
    put("data/g/1.txt", "1")
    put("data/g/2.txt", "2")
    put("data/real.txt", "real")
    recs = collect(<<~RUBY)
      # Stubs as rspec-mocks makes them over methods a prepended module
      # defines (a module prepended in front, its methods removed when the
      # "example" ends).
      stubs = {
        File => { directory?: ->(*) { false }, exist?: ->(*) { false },
                  expand_path: ->(p, *) { "/nonexistent/" + p.to_s } },
        Dir => { children: ->(*) { [] } }
      }
      mods = stubs.map do |k, ms|
        m = Module.new { ms.each { |name, body| define_method(name, &body) } }
        k.singleton_class.prepend(m)
        [m, ms.keys]
      end
      begin
        raise "glob" unless Dir.glob("data/g/*.txt").size == 2
        raise "read" unless File.read("data/real.txt") == "real"
        raise "stub" if File.exist?("data/real.txt")
      ensure
        mods.each { |m, names| names.each { |n| m.send(:remove_method, n) } }
      end
    RUBY
    assert_includes paths(recs, "readdir"), "data/g"
    assert_includes paths(recs, "read"), "data/real.txt"
    refute(recs.any? { |r| r["path"].to_s.start_with?("/nonexistent/") }, "a stubbed expand_path is not used")
    assert_empty taints(recs)
  end

  # RSpec (VCI_RAILS_RUNNER=rspec): examples are counted by the reporter
  # hook, the default seed is 0, the example status file lives in vci's
  # temp dir, and a focused run that skipped examples is refused.
  def test_rspec_results_seed_and_status_file
    skip "the rspec-core gem is not installed for #{RUBY_VERSION}" unless installed?("rspec-core") && installed?("rspec-expectations")
    put(".rspec", "--require spec_helper\n")
    put("spec/spec_helper.rb", <<~RUBY)
      RSpec.configure do |c|
        c.example_status_persistence_file_path = "spec/examples.txt"
        c.filter_run_when_matching :focus
        c.order = :random
        File.write(File.join(ENV["TMPDIR"], "seed"), c.seed.to_s)
      end
    RUBY
    put("spec/a_spec.rb", <<~RUBY)
      RSpec.describe "a" do
        it("one") { expect(1).to eq(1) }
        it("two") { expect(2).to eq(2) }
      end
    RUBY
    put("spec/pending_spec.rb", <<~RUBY)
      RSpec.describe "p" do
        it("passes") { expect(1).to eq(1) }
        xit("skipped") { expect(1).to eq(1) }
      end
    RUBY
    put("spec/focus_spec.rb", <<~RUBY)
      RSpec.describe "f" do
        fit("focused") { expect(1).to eq(1) }
        it("not run") { expect(1).to eq(1) }
      end
    RUBY
    script = %(require "rspec/core"; $0 = "rspec"; RSpec::Core::Runner.invoke\n)
    run = lambda do |file|
      collect(script, env: { "VCI_RAILS_RUNNER" => "rspec" }, args: ["--options", ".rspec", file])
    end
    recs = run.call("spec/a_spec.rb")
    result = recs.find { |r| r["kind"] == "result" }
    assert_equal "passed", result["state"], result.inspect
    assert_equal 2, result["tests"]
    assert_equal "0", File.read(File.join(@tmpdir, "seed"))
    refute File.exist?(File.join(@repo, "spec/examples.txt")), "the status file is not written in the repository"
    assert File.file?(File.join(@tmpdir, "vci-rspec-example-statuses.txt"))
    assert_includes paths(recs, "read"), ".rspec"
    assert_includes paths(recs, "module"), "spec/spec_helper.rb"
    assert_empty taints(recs)
    meta = recs.find { |r| r["kind"] == "meta" }
    assert_match(/rspec-core \d/, meta["runner"])

    recs = run.call("spec/pending_spec.rb")
    result = recs.find { |r| r["kind"] == "result" }
    assert_equal ["failed", 1, 1], [result["state"], result["skipped"], result["tests"] - 1], result.inspect

    recs = run.call("spec/focus_spec.rb")
    assert(taints(recs).any? { |t| t.start_with?("rspec:filtered:1 of 2 examples did not run") }, taints(recs).inspect)
    assert_equal "filtered", recs.find { |r| r["kind"] == "result" }["state"]

    # Without --options, RSpec reads ~/.rspec and friends: refused.
    recs = collect(script, env: { "VCI_RAILS_RUNNER" => "rspec", "HOME" => @tmpdir }, args: ["spec/a_spec.rb"])
    assert(taints(recs).any? { |t| t.start_with?("rspec:option-files") }, taints(recs).inspect)
  end

  # SimpleCov in an RSpec process: its output (and the earlier results it
  # would merge) lives in vci's temp dir, and its configuration files outside
  # the repository (~/.simplecov, .simplecov above the project) look absent.
  def test_rspec_simplecov_is_kept_out_of_the_repository
    skip "simplecov and rspec-core are not installed for #{RUBY_VERSION}" unless installed?("simplecov") && installed?("rspec-core")
    put("spec/a_spec.rb", "RSpec.describe('a') { it('one') { expect(1).to eq(1) } }\n")
    home = File.join(@tmp, "home").tap { |d| FileUtils.mkdir_p(d) }
    File.write(File.join(home, ".simplecov"), "raise 'the global SimpleCov config was loaded'\n")
    File.write(File.join(@tmp, ".simplecov"), "raise 'a .simplecov above the repository was loaded'\n")
    script = %(require "simplecov"; SimpleCov.start; require "rspec/core"; $0 = "rspec"; RSpec::Core::Runner.invoke\n)
    recs = collect(script, env: { "VCI_RAILS_RUNNER" => "rspec", "HOME" => home },
                           args: ["--options", ".rspec", "spec/a_spec.rb"])
    assert_equal "passed", recs.find { |r| r["kind"] == "result" }["state"]
    refute File.exist?(File.join(@repo, "coverage")), "nothing written in the repository"
    assert File.file?(File.join(@tmpdir, "vci-coverage", ".resultset.json"))
    assert_includes paths(recs, "probe"), ".simplecov"
    outside = recs.select { |r| r["path"].to_s.end_with?("/.simplecov") && !r["path"].start_with?(@repo) }
    assert_empty outside
    assert_empty taints(recs)
  end

  # An at_exit handler that changes the exit code after RSpec reported its
  # results (SimpleCov's minimum_coverage exits 2, minitest/autorun's handler,
  # a test's own `at_exit { exit 1 }`): the recorded exit status is the
  # process's, so the file is not reported as passed.
  def test_rspec_exit_status_changed_after_the_run_is_recorded
    skip "the rspec-core gem is not installed for #{RUBY_VERSION}" unless installed?("rspec-core") && installed?("rspec-expectations")
    put("spec/exit_spec.rb", <<~RUBY)
      at_exit { exit 2 }
      RSpec.describe("a") { it("one") { expect(1).to eq(1) } }
    RUBY
    script = %(require "rspec/core"; $0 = "rspec"; RSpec::Core::Runner.invoke\n)
    recs = collect(script, env: { "VCI_RAILS_RUNNER" => "rspec" }, args: ["--options", ".rspec", "spec/exit_spec.rb"])
    result = recs.find { |r| r["kind"] == "result" }
    assert_equal ["failed", 2], [result["state"], result["exitStatus"]], result.inspect
    assert(taints(recs).any? { |t| t.start_with?("vci:process-exit:2 ") }, taints(recs).inspect)
  end

  # A test that sets ENV["TMPDIR"] does not move the collector's notion of
  # its own temp dir: reads under the new value are still recorded.
  def test_tmpdir_set_by_the_test_does_not_hide_reads
    tmp = File.realpath(@tmp)
    outside = File.join(tmp, "outside.txt")
    File.write(outside, "o")
    ["/", tmp].each do |dir|
      recs = collect(<<~RUBY)
        ENV["TMPDIR"] = #{dir.inspect}
        File.read(#{outside.inspect})
      RUBY
      assert_includes recs.select { |r| r["kind"] == "read" }.map { |r| r["path"] }, outside, "TMPDIR=#{dir}"
    end
  end

  # Prism's *_file APIs read the source in C.
  def test_prism_file_apis_are_reads
    skip "prism is not installed for #{RUBY_VERSION}" unless installed?("prism")
    %w[p1 p2 p3 p4 p5 p6 p7].each { |n| put("data/#{n}.rb", "X = 1\n") }
    recs = collect(<<~RUBY)
      require "prism"
      Prism.parse_file("data/p1.rb")
      Prism.parse_file_success?("data/p2.rb")
      Prism.parse_file_failure?("data/p3.rb")
      Prism.lex_file("data/p4.rb")
      Prism.parse_lex_file("data/p5.rb")
      Prism.parse_file_comments("data/p6.rb")
      Prism.dump_file("data/p7.rb") if Prism.respond_to?(:dump_file)
    RUBY
    reads = paths(recs, "read")
    %w[p1 p2 p3 p4 p5 p6].each { |n| assert_includes reads, "data/#{n}.rb" }
  end

  # Ruby's resolv.rb reads /etc/resolv.conf while it loads (DefaultResolver =
  # Resolv.new), which `require "net/http"` (Capybara, rspec-rails' Capybara
  # integration) does at boot. That read is not an input: the DNS settings
  # only matter for lookups, which open sockets (refused). A read the test
  # itself makes through Resolv afterwards is recorded.
  def test_resolv_conf_read_while_resolv_loads_is_not_an_input
    skip "no /etc/resolv.conf here" unless File.file?("/etc/resolv.conf")
    recs = collect(%(require "resolv"\n))
    conf = recs.select { |r| r["path"].to_s.end_with?("/resolv.conf") }
    assert_empty conf
    recs = collect(%(require "resolv"; Resolv::DNS::Config.default_config_hash\n))
    assert(recs.any? { |r| r["kind"] == "read" && r["path"].to_s.end_with?("/resolv.conf") }, recs.inspect)
  end

  # An example whose failure was cleared before it finished (a retry in an
  # around hook, a prepended Example#finish) or reported as passed by an
  # overridden reporter is refused.
  def test_rspec_cleared_or_swallowed_failures_are_refused
    skip "the rspec-core gem is not installed for #{RUBY_VERSION}" unless installed?("rspec-core") && installed?("rspec-expectations")
    put("spec/retry_spec.rb", <<~RUBY)
      $attempt = 0
      RSpec.configure do |c|
        c.around(:each) do |ex|
          3.times do
            ex.example.instance_variable_set(:@exception, nil)
            ex.run
            break unless ex.example.exception
          end
        end
      end
      RSpec.describe("r") { it("flaky") { $attempt += 1; expect($attempt).to eq(2) } }
    RUBY
    put("spec/reporter_spec.rb", <<~RUBY)
      RSpec::Core::Reporter.prepend(Module.new { def example_failed(ex) = example_passed(ex) })
      RSpec.describe("s") { it("fails") { expect(1).to eq(2) } }
    RUBY
    put("spec/finish_spec.rb", <<~RUBY)
      RSpec::Core::Example.prepend(Module.new { def finish(reporter); @exception = nil; super; end })
      RSpec.describe("f") { it("fails") { expect(1).to eq(2) } }
    RUBY
    script = %(require "rspec/core"; $0 = "rspec"; RSpec::Core::Runner.invoke\n)
    {
      "spec/retry_spec.rb" => ["rspec:failure-cleared:"],
      "spec/reporter_spec.rb" => ["rspec:failure-cleared:", "rspec:status-mismatch"],
      "spec/finish_spec.rb" => ["rspec:failure-cleared:"]
    }.each do |f, want|
      recs = collect(script, env: { "VCI_RAILS_RUNNER" => "rspec" }, args: ["--options", ".rspec", f])
      result = recs.find { |r| r["kind"] == "result" }
      want.each do |w|
        assert taints(recs).any? { |t| t.start_with?(w) }, "#{f}: #{w} in #{result.inspect} #{taints(recs).inspect}"
      end
    end
  end

  # Regression: a name starting with "~" or "|" was never recorded (expand
  # returned nil: File.expand_path("~note.txt") raises, and "|" was taken
  # for a command), while File, Dir and File::Stat open such names
  # literally, relative to the working directory.
  def test_names_starting_with_tilde_or_pipe_are_files
    put("~note.txt", "hello")
    put("|pipe.txt", "p")
    put("~dir/a.txt", "a")
    recs = collect(<<~'RUBY')
      raise "read" unless File.read("~note.txt") == "hello"
      raise "open" unless File.open("|pipe.txt", &:read) == "p"
      raise "File.read" unless File.read("|pipe.txt") == "p"
      raise "exist" unless File.exist?("~dir/a.txt")
      raise "absent" if File.exist?("~gone.txt")
      Dir.children("~dir")
      File.realpath("~note.txt")
      File.symlink("~note.txt", "tmp_link") rescue nil
    RUBY
    reads = paths(recs, "read")
    %w[~note.txt |pipe.txt].each { |p| assert_includes reads, p }
    assert_includes paths(recs, "stat"), "~dir/a.txt"
    assert_includes paths(recs, "probe"), "~gone.txt"
    assert_includes paths(recs, "readdir"), "~dir"
    assert_empty taints(recs)
    # IO.read("|cmd") runs a command: refused, as before.
    recs = collect(<<~'RUBY')
      IO.read("|echo hi")
      IO.write("|cat > /dev/null", "x")
    RUBY
    t = taints(recs).join("\n")
    assert_includes t, "process:IO.read(|cmd)"
    assert_includes t, "process:IO.write(|cmd)"
  end

  # Regression: an exemption (vci's temp dir, Ruby's own directories) was
  # decided by how a path was spelt. A directory symlink there into the
  # repository (made and removed by the test) hid the repository files read
  # through it; one to a file elsewhere hid that read too.
  def test_symlinks_in_exempt_directories_are_resolved
    put("fx/x.png", "x")
    outside = File.join(@tmp, "elsewhere").tap { |d| FileUtils.mkdir_p(d) }
    File.write(File.join(outside, "o.txt"), "o")
    fake_lib = File.join(@tmp, "fakerubylib").tap { |d| FileUtils.mkdir_p(d) }
    recs = collect(<<~RUBY)
      # Ruby's own directory, as the collector knows it (a stand-in for a
      # writable rubylibdir).
      RbConfig::CONFIG["rubyhdrdir"] = #{fake_lib.inspect}
      [ENV["TMPDIR"], #{fake_lib.inspect}].each_with_index do |dir, i|
        link = File.join(dir, "fx\#{i}")
        File.symlink(File.expand_path("fx"), link)
        File.read(File.join(link, "x.png"))
        File.unlink(link)
        out = File.join(dir, "out\#{i}")
        File.symlink(#{outside.inspect}, out)
        File.read(File.join(out, "o.txt"))
        File.unlink(out)
      end
    RUBY
    assert_includes paths(recs, "read"), "fx/x.png"
    reads = recs.select { |r| r["kind"] == "read" }.map { |r| r["path"] }
    assert_includes reads, File.realpath(File.join(outside, "o.txt"))
  end

  def test_vips_operation_names_resolve_as_libvips_resolves_them
    skip "ruby-vips with libvips is not available" unless vips_available?
    put_png("img/a.png")
    put_png("~pic.png")
    put("img/b.txt", "hello")
    # Regression: names were classified case-sensitively, but libvips finds
    # an operation by nickname or class name without regard to case.
    recs = collect(<<~RUBY)
      require "vips"
      raise "PNGLOAD" unless Vips::Operation.call("PNGLOAD", ["img/a.png"]).width == 3
      raise "PngLoad" unless Vips::Operation.call("PngLoad", ["img/a.png"]).width == 3
      raise "class" unless Vips::Operation.call("VIPSFOREIGNLOADPNGFILE", ["img/a.png"]).width == 3
      Vips::Operation.call("THUMBNAIL", ["img/a.png", 2], { size: :down })
      raise "tilde" unless Vips::Image.new_from_file("~pic.png").width == 3
    RUBY
    assert_empty taints(recs), taints(recs).join("\n")
    assert_includes paths(recs, "read"), "img/a.png"
    assert_includes paths(recs, "read"), "~pic.png", "libvips opens \"~pic.png\" literally"
    {
      <<~RUBY => "native:vips:system",
        require "vips"
        Vips::Operation.call("SYSTEM", ["cat img/b.txt"], { log: true }) rescue nil
      RUBY
      <<~RUBY => "native:vips:pngload built outside Vips::Operation.call",
        require "vips"
        op = Vips::Operation.new("PNGLOAD")
        op.set("filename", "img/a.png", nil, 0, GObject::GSTR_TYPE, false)
        op.build
      RUBY
      <<~RUBY => 'native:vips:"no_such_op"',
        require "vips"
        Vips::Operation.call("no_such_op", []) rescue nil
      RUBY
    }.each do |script, want|
      t = taints(collect(script)).join("\n")
      assert_includes t, want, script
    end
  end

  # Regression: OpenSSL reads certificate files and its default paths in C.
  def test_openssl_certificate_files
    recs = collect(<<~'RUBY')
      require "openssl"
      key = OpenSSL::PKey::EC.generate("prime256v1")
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=vci test CA")
      cert.public_key = key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = ef.issuer_certificate = cert
      cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
      cert.add_extension(ef.create_extension("keyUsage", "keyCertSign, cRLSign", true))
      cert.sign(key, OpenSSL::Digest.new("SHA256"))
      VciCollector.quiet { File.write("ca.pem", cert.to_pem) }
      st = OpenSSL::X509::Store.new
      st.add_file("ca.pem")
      raise "verify" unless st.verify(cert)
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.ca_file = "ca.pem"
      ctx.setup
      OpenSSL::Config.new("ssl.cnf") rescue nil
    RUBY
    assert_empty taints(recs), taints(recs).join("\n")
    assert_includes paths(recs, "read"), "ca.pem"
    assert_includes paths(recs, "probe"), "ssl.cnf"
    {
      <<~'RUBY' => "native:openssl:X509::Store#verify with a certificate store that loaded OpenSSL's default paths",
        require "openssl"
        st = OpenSSL::X509::Store.new
        st.set_default_paths
        st.verify(OpenSSL::X509::Certificate.new)
      RUBY
      <<~'RUBY' => "native:openssl:X509::StoreContext.new with a certificate store that loaded",
        require "openssl"
        OpenSSL::X509::StoreContext.new(OpenSSL::SSL::SSLContext::DEFAULT_CERT_STORE, OpenSSL::X509::Certificate.new)
      RUBY
      <<~'RUBY' => "native:openssl:X509::Store#verify with a certificate store that has a certificate directory",
        require "openssl"
        st = OpenSSL::X509::Store.new
        st.add_path("certs")
        st.verify(OpenSSL::X509::Certificate.new)
      RUBY
      <<~'RUBY' => "native:openssl:SSLContext#setup with ca_path",
        require "openssl"
        ctx = OpenSSL::SSL::SSLContext.new
        ctx.ca_path = "certs"
        ctx.setup rescue nil
      RUBY
    }.each do |script, want|
      t = taints(collect(script)).join("\n")
      assert_includes t, want, script
    end
  end

  # Regression: who the process runs as was never observed (a laptop's
  # user is not a root CI container's).
  def test_process_identity_reads_taint
    recs = collect(<<~'RUBY')
      require "etc"
      require "fileutils"
      d = File.join(ENV["TMPDIR"], "x")
      FileUtils.mkdir_p(d)
      FileUtils.remove_entry_secure(d)
    RUBY
    assert_empty taints(recs).grep(/process-identity/), taints(recs).join("\n")
    %w[Process.uid Process.euid Process::UID.rid Process::Sys.getuid Etc.getlogin Etc.getpwuid].each do |call|
      args = call == "Etc.getpwuid" ? "(Process::Sys.getuid)" : ""
      t = taints(collect("require 'etc'\n#{call}#{args}\n")).join("\n")
      assert_includes t, "ruby:process-identity:#{call} at", call
    end
  end

  # Regression: the check on an attached FFI function was a prepended
  # module, so `method(:f).super_method.call` called C past it.
  def test_ffi_wrapper_cannot_be_skipped
    skip "the ffi gem is not installed for #{RUBY_VERSION}" unless installed?("ffi")
    recs = collect(<<~RUBY)
      require "ffi"
      module L
        extend FFI::Library
        ffi_lib FFI::Library::LIBC
        attach_function :getpid, [], :int
      end
      raise "super_method" unless L.method(:getpid).super_method.nil?
    RUBY
    assert_empty taints(recs).grep(/FFI call/), "not called: #{taints(recs).inspect}"
    recs = collect(<<~RUBY)
      require "ffi"
      module L
        extend FFI::Library
        ffi_lib FFI::Library::LIBC
        attach_function :getpid, [], :int
      end
      m = L.method(:getpid)
      (m.super_method || m).call
    RUBY
    assert_includes taints(recs).join("\n"), "native:FFI call L.getpid"
  end

  def test_plain_mode_records_nothing
    put("script.rb", "File.read(__FILE__)\n")
    e = { "RUBYOPT" => "-r#{COLLECTOR}", "VCI_RAILS_MODE" => "plain", "VCI_OUT" => @out, "VCI_TEST_ID" => "script.rb" }
    system(e, RbConfig.ruby, "script.rb", chdir: @repo, exception: true)
    assert_empty Dir[File.join(@out, "*")]
  end

  # A stub that saves and restores a hooked method by alias (Minitest's
  # `stub`, vex-api's `Object#stub`) used to leave a copy of the hook whose
  # `super` called itself: every later `ENV[]` or `File.read` overflowed the
  # stack. The stub works, the method is restored, and reads after it are
  # still recorded.
  def test_alias_stub_of_a_hooked_method_restores_it
    put("data.txt", "data")
    recs = collect(<<~RUBY)
      def stub_by_alias(obj, name, val)
        meta = obj.singleton_class
        meta.alias_method :"__saved_\#{name}", name
        meta.define_method(name) { |*| val }
        yield
      ensure
        meta.alias_method name, :"__saved_\#{name}"
        meta.undef_method :"__saved_\#{name}"
      end
      stub_by_alias(ENV, :[], "stubbed") { raise "not stubbed" unless ENV["VCI_STUBBED"] == "stubbed" }
      stub_by_alias(File, :read, "stubbed") { raise "not stubbed" unless File.read("nope") == "stubbed" }
      raise "not restored" unless ENV["VCI_STUBBED"].nil? && File.read("data.txt") == "data"
    RUBY
    assert_includes paths(recs, "read"), "data.txt"
    assert_includes recs.select { |r| r["kind"] == "env" }.map { |r| r["key"] }, "VCI_STUBBED"
    assert_equal 0, recs.last["exitStatus"]
    assert_empty taints(recs)
  end

  # Batch mode (VCI_RAILS_BATCH): the loader (a stand-in for Rails'
  # Runner.load_tests) asks for the first file, and the process boots once
  # per helper the files require first, then forks one process per file.
  # Each file's output is what its own run writes: its own reads, the boot's,
  # never another file's; nothing one file's process defines or leaves in
  # vci's temp dir reaches the next; each result and exit status is its own;
  # the batch's own forks are not a test's ("process:fork").
  def test_batch_mode_runs_each_file_in_a_process_of_its_own
    put("test/test_helper.rb", "require \"minitest\"\nBOOT = File.read(File.expand_path(\"boot.txt\", __dir__))\n")
    put("test/boot.txt", "boot")
    put("test/data/a.txt", "a")
    put("test/data/b.txt", "b")
    put("test/a_test.rb", <<~RUBY)
      require "test_helper"

      QMARK = true
      String.class_eval { def vci_patched = true }

      class ATest < Minitest::Test
        def test_a
          assert_equal "a", File.read("test/data/a.txt")
          File.write(File.join(Dir.tmpdir, "cache.txt"), "a")
        end
      end
    RUBY
    put("test/b_test.rb", <<~RUBY)
      require_relative "test_helper"

      raise "a is loaded" if defined?(QMARK)

      class BTest < Minitest::Test
        def test_b
          assert_equal "b", File.read("test/data/b.txt")
          refute "".respond_to?(:vci_patched)
          refute File.exist?(File.join(Dir.tmpdir, "cache.txt"))
          assert false, "b fails"
        end
      end
    RUBY
    put("test/c_test.rb", <<~RUBY)
      # frozen_string_literal: true

      require "test_helper"

      class CTest < Minitest::Test
        def test_c = assert(BOOT == "boot")
      end
    RUBY
    ids = %w[test/a_test.rb test/b_test.rb test/c_test.rb]
    out = batch(ids)
    # A and C require "test_helper" first (one boot), B require_relative's
    # it (a boot of its own).
    assert_equal [{ "id" => "test/a_test.rb", "exit" => 0 }, { "id" => "test/c_test.rb", "exit" => 0 },
                  { "id" => "test/b_test.rb", "exit" => 1 }, { "done" => true }], out[:status], out[:said]
    a, b, c = out.values_at(*ids)
    assert_equal %w[test/boot.txt test/data/a.txt], paths(a, "read").sort
    assert_equal %w[test/boot.txt test/data/b.txt], paths(b, "read").sort
    assert_equal %w[test/boot.txt], paths(c, "read")
    assert_includes paths(a, "module"), "test/a_test.rb"
    refute_includes paths(b, "module"), "test/a_test.rb"
    assert_includes paths(b, "module"), "test/test_helper.rb"
    assert_equal({ "state" => "passed", "tests" => 1, "failed" => 0 }, a.last.slice("state", "tests", "failed"))
    assert_equal({ "state" => "failed", "tests" => 1, "failed" => 1 }, b.last.slice("state", "tests", "failed"))
    assert_equal "passed", c.last["state"]
    [a, b, c].each { |r| assert_empty taints(r) }
    assert_empty Dir.children(@tmpdir)

    # A's output is what a run of A on its own writes.
    alone = collect(<<~'RUBY', env: { "VCI_TEST_ID" => "script.rb" }, args: ["test/a_test.rb", "--seed", "0"])
      require "minitest/autorun"
      $LOAD_PATH << "test"
      require_relative "loader/rails/test_unit/runner"
      FakeRunner.load_tests(ARGV.grep(/_test\.rb\z/))
    RUBY
    norm = ->(recs) { recs.reject { |r| %w[meta result].include?(r["kind"]) }.sort_by(&:to_s) }
    assert_equal norm.call(alone), norm.call(a)
  end

  # Batch mode whose files the loader never asks for (they are required
  # some other way): every file goes back to run on its own. A boot that
  # fails sends its group's files back.
  def test_batch_mode_sends_back_what_it_cannot_run_per_file
    put("test/test_helper.rb", "require \"minitest\"\n")
    put("test/a_test.rb", "require \"test_helper\"\nclass ATest < Minitest::Test\n  def test_a = assert(true)\nend\n")
    put("test/b_test.rb", "require \"test_helper\"\nclass BTest < Minitest::Test\n  def test_b = assert(true)\nend\n")
    ids = %w[test/a_test.rb test/b_test.rb]
    out = batch(ids, script: "require \"minitest/autorun\"\n$LOAD_PATH << \"test\"\nrequire_relative \"test/a_test\"\nrequire_relative \"test/b_test\"\n")
    assert_equal ids, out[:status].filter_map { |l| l["id"] if l["why"]&.include?("own loader") }, out[:said]
    assert_equal({ "done" => true }, out[:status].last)
    ids.each { |id| assert_nil out[id] }

    put("test/test_helper.rb", "require \"minitest\"\nraise \"no database\"\n")
    out = batch(ids)
    assert_equal ids, out[:status].filter_map { |l| l["id"] if l["why"]&.include?("RuntimeError: no database") }, out[:said]
    ids.each { |id| assert_nil out[id] }

    # The boot's process dies: its files go back.
    put("test/test_helper.rb", "require \"minitest\"\nProcess.kill(:KILL, Process.pid)\n")
    out = batch(ids)
    assert_equal ids, out[:status].filter_map { |l| l["id"] if l["why"]&.include?("ended (signal 9)") }, out[:said]

    # A's process changes a file the boot left in vci's temp dir, which B's
    # process would see: B goes back (A's own run stands).
    put("test/test_helper.rb", "require \"minitest\"\nrequire \"tmpdir\"\nFile.write(File.join(Dir.tmpdir, \"boot.txt\"), \"boot\")\n")
    put("test/a_test.rb", "require \"test_helper\"\nclass ATest < Minitest::Test\n  def test_a = File.write(File.join(Dir.tmpdir, \"boot.txt\"), \"a was here\")\nend\n")
    out = batch(ids)
    assert_equal({ "id" => "test/a_test.rb", "exit" => 0 }, out[:status][0], out[:said])
    assert_match(/process of test\/a_test.rb changed .*boot.txt in vci's temp directory/, out[:status][1]["why"])
    assert_equal "test/b_test.rb", out[:status][1]["id"]
    assert_equal "no-assertions", out["test/a_test.rb"].last["state"]
  end

  # Run the files `ids` with the collector in batch mode, the loader asking
  # for each (or `script`): each id's records, the lines of files.jsonl
  # (:status) and what the process said (:said).
  def batch(ids, script: nil)
    put("loader/rails/test_unit/runner.rb",
        "module FakeRunner\n  def self.load_tests(files) = files.each { |f| require File.expand_path(f) }\nend\n")
    script ||= "require \"minitest/autorun\"\n$LOAD_PATH << \"test\"\nrequire_relative \"loader/rails/test_unit/runner\"\n" \
               "FakeRunner.load_tests(ARGV.grep(/_test\\.rb\\z/))\n"
    put("script.rb", script)
    list = File.join(@tmp, "batch-files.txt")
    File.write(list, ids.join("\n"))
    FileUtils.rm_rf(Dir[File.join(@out, "*")])
    e = {
      "RUBYOPT" => "-r#{COLLECTOR}", "VCI_RAILS_MODE" => "collect", "VCI_OUT" => @out, "VCI_RAILS_BATCH" => list,
      "VCI_ROOT" => @repo, "VCI_REPO" => @repo, "TMPDIR" => @tmpdir, "RUBYLIB" => nil, "BUNDLE_GEMFILE" => nil
    }
    said = IO.popen(e, [RbConfig.ruby, "script.rb", *ids, "--seed", "0"], chdir: @repo, err: %i[child out], &:read)
    status_file = File.join(@out, "batch", "files.jsonl")
    assert File.file?(status_file), "no batch status; process said:\n#{said}"
    out = { said: said, status: File.readlines(status_file).map { |l| JSON.parse(l) } }
    ids.each do |id|
      f = File.join(@out, "#{Digest::SHA256.hexdigest(id)}.jsonl")
      out[id] = File.readlines(f).map { |l| JSON.parse(l) } if File.file?(f)
    end
    out
  end
end
