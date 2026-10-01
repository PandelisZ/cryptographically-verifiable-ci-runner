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
    assert_includes recs.select { |r| r["kind"] == "read" }.map { |r| r["path"] }, outside
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

  def test_sqlite_files_vci_did_not_prepare_taint
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
        attach_function :getpid, [], :int
      end
      L.getpid
    RUBY
    assert_includes taints(recs).join("\n"), "native:FFI attach_function"
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

  def test_plain_mode_records_nothing
    put("script.rb", "File.read(__FILE__)\n")
    e = { "RUBYOPT" => "-r#{COLLECTOR}", "VCI_RAILS_MODE" => "plain", "VCI_OUT" => @out, "VCI_TEST_ID" => "script.rb" }
    system(e, RbConfig.ruby, "script.rb", chdir: @repo, exception: true)
    assert_empty Dir[File.join(@out, "*")]
  end
end
