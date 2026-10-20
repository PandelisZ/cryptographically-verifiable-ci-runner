# frozen_string_literal: true

# vci_collector: records what one Rails test file (one Ruby process) reads,
# for `vci run` (crates/vci-adapter/src/rails.rs); in batch mode
# (VCI_RAILS_BATCH, see Batch) one process boots once for several files and
# forks one such process per file. Findings behind it: docs/spike-rails.md.
#
# Loaded with RUBYOPT=-r<abs>/vci_collector.rb, so it runs before bin/rails,
# Bundler, Rails and the test file. Pure Ruby; it requires no gem while the
# tests run (a default gem required early could clash with the version the
# bundle activates later).
#
# Modes (VCI_RAILS_MODE):
#   collect  record everything, write $VCI_OUT/<sha256(VCI_TEST_ID)>.jsonl at exit
#            (batch mode: each file's process writes its own, and
#            $VCI_OUT/batch/files.jsonl says how each one ended)
#   plain    no recording, only the run conditions `vci run` uses (a fresh
#            local secret, RSpec's seed and status file); used by `vci ci`
#   probe    print one "VCI-PROBE <json>" line with the toolchain at exit
#   engine   nothing at all: a child process Active Record's own schema
#            maintenance starts (`bin/rails db:test:prepare`, see
#            VciCollector.engine_child?), which only sets up the test database
#
# The test database is the test engine's business: vci neither redirects,
# prepares, purges nor loads it. Rails' maintain_test_schema!, transactional
# tests and fixtures give each test its starting state, as in a plain
# `bin/rails test` or `rspec`. Its contents are not an input (see DB).
#
# VCI_RAILS_RUNNER=rspec: the process runs RSpec (`rspec <file>`) instead of
# `bin/rails test`; see RSpecSupport for what is neutralised (option files
# outside the repository, the example status file, a random seed, SimpleCov's
# output directory) and refused.
#
# Ruby has no audit hook: file access is observed by wrapping the Ruby entry
# points (File, FileTest, IO, Dir, File::Stat, Kernel#open/require/load,
# ENV). C extensions that open files themselves are not seen. Anything the
# collector cannot attribute becomes a taint (the file is not attested).

# A child process of Active Record's schema maintenance (VCI_RAILS_MODE=engine,
# set by the collector of its parent): not the test's, nothing to record.
return if ENV["VCI_RAILS_MODE"] == "engine"
# A process a test started (`ruby -e`, `bin/rails runner`) in batch mode: it
# inherits RUBYOPT and VCI_OUT but no test id (the batch gives a file's
# process its id, not its environment), and it is not the batch's own
# process (VciCollector::BATCH). Its parent's hooks recorded it as a taint
# ("process:spawn", "process:system", ...); here it is not the test's
# process, so the collector does nothing at all: no hooks, no output, and
# nothing on stderr (vex-api's batch_interaction_test.rb asserts that a
# child `ruby -e` prints nothing). Without VCI_OUT (the collector loaded by
# hand) it still says at exit that it wrote nothing.
if ENV.fetch("VCI_RAILS_MODE", "collect") == "collect" && ENV["VCI_OUT"] && !ENV["VCI_TEST_ID"] &&
   !(ENV["VCI_RAILS_BATCH"] && [nil, Process.pid.to_s].include?(ENV["VCI_RAILS_BATCH_PID"]))
  return
end

module VciCollector
  # When the collector was loaded (the Ruby process's start, near enough):
  # a batch reports its boot time from here.
  LOADED_AT = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  # Part of the toolchain (Probe.libs): bumped whenever what the collector
  # records or refuses changes, so an attestation made by an older collector
  # (which may have missed an input) is not accepted where a newer one runs.
  VERSION = "0.5.0"
  MODE = ENV.fetch("VCI_RAILS_MODE", "collect")
  # The test framework vci started this process for: "minitest" (default,
  # `bin/rails test <file>`) or "rspec" (`rspec <file>`, see RSpecSupport).
  RUNNER = ENV["VCI_RAILS_RUNNER"] == "rspec" ? "rspec" : "minitest"
  OUT = ENV["VCI_OUT"]
  TEST_ID = ENV["VCI_TEST_ID"]
  # Batch mode (collect mode with VCI_RAILS_BATCH): one process for several
  # test files (`bin/rails test <files>`, `rspec <files>`); the variable names
  # a file listing their test ids, one per line. Read here, before any hook
  # is installed. See Batch.
  # The batch is the process vci started (or what it execs: the same
  # process id, as a binstub or wrapper that execs Ruby again), never a
  # child process a test starts (`ruby bin/rails runner`, `ruby -e`): it
  # inherits RUBYOPT and VCI_RAILS_BATCH, and would otherwise take itself
  # for the batch's driver: at its exit it said that every file of the
  # batch must run again on its own, and a child `bin/rails test` of a file
  # of the batch drove the whole batch again (vex-api's
  # solid_queue_shutdown_test.rb runs `bin/rails runner`). The first process
  # to load the collector names itself in VCI_RAILS_BATCH_PID; a process
  # with another id is a process without a test id, which writes nothing.
  # (Removing VCI_RAILS_BATCH instead lost the batch in a runner that execs
  # Ruby again.)
  ENV["VCI_RAILS_BATCH_PID"] ||= Process.pid.to_s if ENV["VCI_RAILS_BATCH"]
  BATCH = (ENV["VCI_RAILS_BATCH"] if ENV["VCI_RAILS_BATCH_PID"] == Process.pid.to_s)
  BATCH_IDS = if BATCH && !BATCH.empty? && MODE == "collect"
                begin
                  File.read(BATCH).split("\n").reject(&:empty?).freeze
                rescue StandardError
                  [].freeze
                end
              end
  # Batch mode: how many slots run a group's files at once (VCI_RAILS_SLOTS,
  # set by vci: VCI_RAILS_JOBS, else PARALLEL_WORKERS above 1, else
  # VCI_JOBS, else the processor count; 1 when vci's PARALLEL_WORKERS is 1),
  # and what decided that number (VCI_RAILS_SLOTS_ASKED): "1", VCI_RAILS_JOBS
  # (any project); "workers", PARALLEL_WORKERS (as in Rails, it overrides
  # the project's `parallelize(workers:)`). See Batch.slots_for.
  SLOTS = [ENV["VCI_RAILS_SLOTS"].to_i, 1].max
  SLOTS_ASKED = ENV["VCI_RAILS_SLOTS_ASKED"] == "1"
  SLOTS_WORKERS = ENV["VCI_RAILS_SLOTS_ASKED"] == "workers"
  # Batch mode: whether the lines every file of a boot (or slot) shares are
  # written once for them all (Batch.share!; VCI_RAILS_SHARED_OUTPUT=0:
  # each file's process writes all of its output, as a one-file run does).
  SHARED_OUTPUT = ENV["VCI_RAILS_SHARED_OUTPUT"] != "0"
  # The fresh temp dir vci gave this process (TMPDIR), read once here: a test
  # that later sets ENV["TMPDIR"] (to "/tmp", HOME, "/") changes where its
  # own temp files go, never which reads the collector treats as vci's
  # scratch space (it would otherwise hide every read under that directory).
  TMP = ENV["TMPDIR"]
  # vci's temp dir itself: TMP, unless a group running beside others
  # (Batch#drive_together!) points TMP at a directory of its own inside it.
  # Reads anywhere under it are vci's scratch space, never inputs.
  TMP_ROOT = TMP
  DLEXTS = %w[.so .bundle].freeze
  RBEXTS = %w[.rb .so .bundle].freeze
  # Code of RubyGems and Bundler. What they look up decides which gems are
  # loaded and from where; that outcome is recorded (the resolved bundle,
  # every loaded gem's version), so their own bookkeeping is not an input:
  # their reads of TOOLING_ENV variables, their existence and type checks
  # and listings outside the repository (~/.gem, ~/.bundle, HOME), and under
  # a gem root what Gems.bookkeeping? lists (never anything else they read,
  # list or check there for a caller).
  RUBYLIBDIR = RbConfig::CONFIG["rubylibdir"].to_s
  TOOLING_FILES = [
    "#{RUBYLIBDIR}/rubygems.rb", "#{RUBYLIBDIR}/bundled_gems.rb", "#{RUBYLIBDIR}/bundler.rb"
  ].freeze
  TOOLING_DIRS = ["#{RUBYLIBDIR}/rubygems/", "#{RUBYLIBDIR}/bundler/"].freeze
  TOOLING_GEM = %r{/gems/bundler-\d[^/]*/(lib|exe)/}
  TOOLING_ENV = /\A(HOME|PATH|USER|LOGNAME|SHELL|TMPDIR|TMP|TEMP|MANPATH|RB_USER_INSTALL|SOURCE_DATE_EPOCH|DEBUG|NO_COLOR|TERM|GEM_[A-Z0-9_]*|BUNDLE_[A-Z0-9_]*|BUNDLER_[A-Z0-9_]*|RUBYOPT|RUBYLIB|RUBYGEMS_[A-Z0-9_]*|THOR_[A-Z0-9_]*|XDG_[A-Z0-9_]*)\z/
  # Globs whose result reaches no test, made at boot by: rspec-rails 8's
  # "rspec_rails.code_statistics" initializer, which globs
  # spec/**/*_spec.rb to register `bin/rails stats` directories
  # (Rails::CodeStatistics). Recorded, its listings would make every new spec
  # file anywhere in spec/ run every spec that boots Rails. A test that reads
  # Rails::CodeStatistics' directories is refused instead (install_code_stats).
  GLOB_NOT_INPUT = %r{/rspec-rails-[^/]+/lib/rspec-rails\.rb\z}
  # See VciCollector.resolv_loading?.
  RESOLV_CONF = %w[/etc/resolv.conf /private/etc/resolv.conf].freeze

  # The file system primitives the collector itself uses, captured before
  # anything (its own hooks, a test's stubs) can replace them: a test that
  # stubs File.exist?, File.directory?, Dir.children or File.expand_path
  # (rspec-mocks' `allow(File).to receive(...)`, Minitest's `File.stub`)
  # changes what the test sees, never what the collector records about the
  # real file system (a stubbed File.directory? would otherwise hide the
  # listings of a real Dir.glob).
  module Real
    FS = ::File.singleton_class
    DS = ::Dir.singleton_class
    FILE = %i[exist? directory? symlink? file? expand_path realpath stat lstat join dirname basename extname
              fnmatch binread].to_h { |m| [m, FS.instance_method(m)] }.freeze
    DIR = %i[children pwd].to_h { |m| [m, DS.instance_method(m)] }.freeze
    # IO.popen, for the collector's own `git check-ignore` at exit
    # (Output.ignored_children).
    POPEN = ::IO.singleton_class.instance_method(:popen)

    class << self
      def popen(*args, **kw, &blk)
        POPEN.bind_call(::IO, *args, **kw, &blk)
      end

      FILE.each_key do |m|
        define_method(m) { |*args| FILE[m].bind_call(::File, *args) }
      end
      DIR.each_key do |m|
        define_method(:"dir_#{m}") { |*args| DIR[m].bind_call(::Dir, *args) }
      end
    end
  end

  # Only the process vci started writes output (a forked child inherits the
  # collector, and its "process:fork" taint), or in batch mode the process
  # Batch forked for a file (it sets @pid and @test_id).
  @pid = Process.pid
  @test_id = TEST_ID
  @busy_key = :__vci_collector_busy
  @records = {}      # [kind, abs] => true, insertion ordered
  @env_keys = {}     # key => {where => true}
  @taints = []
  @written = {}      # abs => true: written, created, deleted or renamed by this process
  # abs => true: what the path holds now is this process's own output (it
  # created it, truncated it, or renamed its own file onto it). Reads and
  # checks of it from then on are not inputs; earlier ones are.
  @produced = {}
  @inodes = {}       # [dev, ino] => abs of files opened through File
  # abs => real path, for paths outside the repository that led elsewhere
  # (through a symlink) when they were used: the link may be gone by exit.
  @reals = {}
  @enumerations = [] # [where, method]
  @lp_memo = {}
  @hooks_done = {}

  class << self
    attr_reader :records, :taints, :written, :produced, :env_keys, :enumerations, :reals, :pid, :test_id

    def collect?
      MODE == "collect"
    end

    def busy?
      Thread.current[@busy_key]
    end

    # Run a block without recording (the collector's own file system calls).
    def quiet
      was = Thread.current[@busy_key]
      Thread.current[@busy_key] = true
      yield
    ensure
      Thread.current[@busy_key] = was
    end

    def root
      @root ||= quiet { Real.realpath(ENV["VCI_ROOT"] || Real.dir_pwd) }
    end

    def repo
      @repo ||= quiet { Real.realpath(ENV["VCI_REPO"] || root) }
    end

    def taint(reason)
      return unless collect?
      r = reason.to_s
      @taints << r unless @taints.include?(r)
    end

    # A path argument as a String, or nil (an IO, an fd, anything else).
    def pathify(x)
      case x
      when String then x
      when Integer, IO then nil
      else
        if x.respond_to?(:to_path)
          x.to_path
        elsif x.respond_to?(:to_str)
          x.to_str
        end
      end
    rescue StandardError
      nil
    end

    # The absolute path a File, IO, Dir or File::Stat entry point opens for
    # `p`. They take every name literally, relative to the working
    # directory: "~note.txt" and "~/x" are not expanded (only
    # File.expand_path and require do that), and "|x" is a file named "|x"
    # (only Kernel#open and IO.read/readlines/foreach/write run a command for
    # it, and those taint). A name the collector cannot resolve when the
    # operation it was given to succeeded would be a read vci did not
    # record: it refuses the file (fail closed). A name with a NUL byte is
    # rejected by Ruby before it reaches the file system.
    def expand(p)
      return nil unless p.is_a?(String) && !p.empty?
      return nil if p.include?("\0")
      quiet { literal_path(p) }
    rescue StandardError => e
      taint("vci:unresolvable-path:#{p.inspect} (#{e.class}: vci could not tell which file this names)")
      nil
    end

    # File.expand_path without its "~" expansion: what the file system entry
    # points open for `p` (relative to `dir`, default the working directory).
    def literal_path(p, dir = nil)
      p = "./#{p}" if p.start_with?("~")
      dir ? Real.expand_path(p, dir) : Real.expand_path(p)
    end

    def inside?(abs, dir)
      abs == dir || abs.start_with?(dir.end_with?("/") ? dir : "#{dir}/")
    end

    def frame
      me = __FILE__
      loc = caller_locations(3, 60)&.find { |l| (l.absolute_path || l.path) != me }
      loc ? (loc.absolute_path || loc.path).to_s : "?"
    end

    def tooling?(where)
      return false if inside?(where, repo)
      TOOLING_FILES.include?(where) || TOOLING_DIRS.any? { |d| where.start_with?(d) } || TOOLING_GEM.match?(where)
    end

    # Record an observation. RubyGems' and Bundler's own reads, existence
    # and type checks and listings (see TOOLING_FILES) are marked as theirs
    # (:tooling), inside the repository as outside it: whether a path is
    # part of a bundle installed in the repository (BUNDLE_PATH=vendor/bundle,
    # as ruby/setup-ruby's bundler-cache sets it) is only known once Bundler
    # has set the bundle up, so Output.write_records decides at exit. Under
    # a gem root only their bookkeeping (Gems.bookkeeping?) is not an input;
    # anywhere else outside the repository their checks and listings are
    # not, and their reads are; anywhere else in the repository (Gemfile, a
    # path gem's gemspec) all of it is. A read of a .gemspec that
    # Gem::Specification.load evaluates for code that is not theirs (a test)
    # is marked :gemspec_load, which replaces an earlier :tooling (their
    # read of the stub line at the top of the same file, made at boot):
    # evaluating one is running its code (Output.bundle_bookkeeping?).
    # realpath's checks of each component of a path (walk: the path) are
    # marked with the path and who asked (walked, Output.bundle_bookkeeping?).
    # A read or check of a path whose content is this process's own output
    # is not an input (one made before the process replaced it is).
    def add(kind, abs, walk: nil)
      return unless abs
      abs = resolve(abs)
      return if %i[read stat readdir].include?(kind) && @produced[abs]
      return if !inside?(abs, repo) && RESOLV_CONF.include?(abs) && resolv_loading?
      if %i[stat probe readdir read].include?(kind)
        where = quiet { frame }
        if quiet { tooling?(where) }
          if kind == :read && abs.end_with?(".gemspec") && quiet { gemspec_load? }
            @records[[kind, abs]] = :gemspec_load unless @records[[kind, abs]] == true
          else
            @records[[kind, abs]] ||= :tooling
          end
          return
        end
        if walk
          walked(kind, abs, walk, where)
          return
        end
        Batch.loader_check(kind, abs, where) if Batch.on?
      end
      @records[[kind, abs]] = true
    end

    # A check realpath made of a component of `walk`, for code at `where`:
    # kept with every other path and caller (one per file of code) that
    # made the same check, unless the check is already an input (true).
    # It replaces RubyGems' own (:tooling), which a check of a path's type
    # under a gem root is not an input for.
    def walked(kind, abs, walk, where)
      cur = @records[[kind, abs]]
      if cur.is_a?(Array) && cur[0] == :realpath
        cur[1] << [walk, where] unless cur[1].size >= 64 || cur[1].any? { |_, w| w == where }
      elsif cur.nil? || cur == :tooling
        @records[[kind, abs]] = [:realpath, [[walk, where]]]
      end
    end

    # Gem::Specification.load (which evaluates the file) is on the stack,
    # called by code that is not RubyGems' or Bundler's (a test, a gem): not
    # their own stub lookups (Gem::StubSpecification#to_spec, which
    # Gem::Specification.find_all_by_name and Bundler's setup use).
    def gemspec_load?
      locs = caller_locations(3, 40).to_a
      i = locs.index do |l|
        l.base_label == "load" && (l.absolute_path || l.path).to_s.end_with?("/rubygems/specification.rb")
      end
      return false unless i
      by = locs[(i + 1)..].find { |l| (l.absolute_path || l.path) != __FILE__ }
      !by || !tooling?((by.absolute_path || by.path).to_s)
    end

    # The real path of `abs`, or of its nearest existing ancestor joined
    # with the rest (an absent path).
    def real_of(abs)
      rest = []
      cur = abs
      quiet do
        until cur == "/" || cur.empty?
          begin
            return File.join(Real.realpath(cur), *rest.reverse)
          rescue SystemCallError
            rest << Real.basename(cur)
            cur = Real.dirname(cur)
          end
        end
      end
      abs
    end

    # A path outside the repository is resolved when it is used: through a
    # symlink (in a temp dir, Ruby's own or a gem's directory, the
    # collector's), it can name a repository file, which is then what is
    # recorded. The link may be gone by the time the records are written
    # (a test that makes one and removes it), so this cannot wait until
    # then. Where it led otherwise is kept for Output.classify.
    def resolve(abs)
      return abs if inside?(abs, repo)
      real = real_of(abs)
      return abs if real == abs
      return real if inside?(real, repo)
      @reals[abs] ||= real
      abs
    rescue StandardError
      abs
    end

    # resolve for the directory holding `abs`, not `abs` itself.
    def resolve_parent(abs)
      return abs if inside?(abs, repo)
      dir = quiet { Real.dirname(abs) }
      r = resolve(dir)
      r == dir ? abs : File.join(r, quiet { Real.basename(abs) })
    end

    # Ruby's resolv.rb (Ruby's own library or the resolv gem) creating its
    # DefaultResolver while it loads (`DefaultResolver = self.new` in the
    # body of class Resolv), which reads /etc/resolv.conf: `require
    # "net/http"` does this at boot (Capybara, which rspec-rails loads
    # whenever it is in the bundle). Not an input: those DNS settings are
    # only used by lookups, which open sockets (refused). Any other read of
    # the file (Resolv::DNS::Config called by a test) is recorded.
    def resolv_loading?
      quiet do
        caller_locations(2, 40).to_a.any? do |l|
          p = (l.absolute_path || l.path).to_s
          l.label == "<class:Resolv>" && p.end_with?("/resolv.rb") && !inside?(p, repo)
        end
      end
    rescue StandardError
      false
    end

    def rec(kind, path)
      return unless collect? && !busy?
      add(kind, expand(pathify(path)))
    end

    # A file that is an input whoever reads it (DB.schema_files): its
    # content, or that it is absent.
    def schema_input(abs)
      abs = resolve(abs)
      return if @produced[abs]
      @records[[exists_quietly?(abs) ? :read : :probe, abs]] = true
    end

    # Type (and, for a file, content) observed: absent -> probe, else stat.
    def observe_stat(path, walk: nil)
      return unless collect? && !busy?
      abs = expand(pathify(path))
      return unless abs
      exists = quiet { Real.exist?(abs) || Real.symlink?(abs) }
      add(exists ? :stat : :probe, abs, walk: walk)
    end

    def env_read(key)
      return unless collect? && !busy?
      k = key.to_s
      return if k.empty?
      where = quiet { frame }
      return if TOOLING_ENV.match?(k) && tooling?(where)
      (@env_keys[k] ||= {})[where] = true
    rescue StandardError
      nil
    end

    def env_enumerated(meth)
      return unless collect? && !busy?
      @enumerations << [quiet { frame }, meth.to_s]
    end

    # A write to `path`. produced: its content is now wholly this
    # process's output; gone: it no longer exists.
    # follow: false for an operation on the path itself (unlink, rename,
    # lchmod, creating a link): a symlink there is not followed.
    def wrote(path, produced: false, gone: false, follow: true)
      return unless collect? && !busy?
      abs = expand(pathify(path))
      return unless abs
      abs = follow ? resolve(abs) : resolve_parent(abs)
      @records[[:write, abs]] = true
      @written[abs] = true
      Batch.slot_wrote(abs) if Batch.slot
      if produced
        @produced[abs] = true
      elsif gone
        @produced.delete(abs)
      end
    end

    def self_produced?(abs)
      @produced.key?(abs)
    end

    # Before an operation that fails unless `path` exists (delete, rename,
    # chmod, ...): its existence is observed, unless it is the process's own.
    def before_change(path)
      return unless collect? && !busy?
      observe_stat(path)
    end

    # A file was created or opened for writing: its directory had to exist.
    def parent_observed(abs)
      dir = quiet { Real.dirname(abs) }
      add(:stat, dir) if inside?(dir, repo) && dir != abs
    end

    # File-open mode -> [reads, writes, truncates, creates]
    def mode_info(mode, flags)
      reads = true
      writes = false
      trunc = false
      creat = false
      case mode
      when nil
        nil
      when Integer
        acc = mode & 3
        reads = acc != File::WRONLY
        writes = acc != File::RDONLY
        trunc = (mode & File::TRUNC) != 0
        creat = (mode & File::CREAT) != 0
      else
        m = mode.to_s.split(":").first.to_s.delete("bt")
        case m
        when "r", "" then nil
        when "r+" then writes = true
        when "w" then reads = false; writes = true; trunc = true; creat = true
        when "w+" then writes = true; trunc = true; creat = true
        when "a" then reads = false; writes = true; creat = true
        when "a+" then writes = true; creat = true
        when "wx", "x" then reads = false; writes = true; creat = true
        else writes = true
        end
      end
      if flags.is_a?(Integer)
        writes ||= (flags & 3) != File::RDONLY
        trunc ||= (flags & File::TRUNC) != 0
        creat ||= (flags & File::CREAT) != 0
      end
      [reads, writes, trunc, creat]
    end

    # A path was opened (ok) or failed to open (ENOENT/ENOTDIR).
    def opened(path, mode, flags, existed, ok)
      return unless collect? && !busy?
      abs = expand(pathify(path))
      return unless abs
      abs = resolve(abs)
      reads, writes, trunc, creat = mode_info(mode, flags)
      unless ok
        add(:probe, abs) if reads || !creat
        return
      end
      remember_inode(abs)
      if writes
        @records[[:write, abs]] = true
        @written[abs] = true
        Batch.slot_wrote(abs) if Batch.slot
        parent_observed(abs)
        # Truncated or created: what it holds from now on is the process's
        # own. A read before this point (recorded then) stays an input.
        @produced[abs] = true if trunc || !existed
      end
      add(:read, abs) if reads
    end

    def remember_inode(abs)
      st = quiet { Real.stat(abs) }
      @inodes[[st.dev, st.ino]] = abs
    rescue StandardError
      nil
    end

    # An IO built from a file descriptor (File.new(fd), IO.for_fd(fd)): fine
    # when it is a file vci saw opened (by dev/ino), a pipe, a socket pair or
    # a terminal; otherwise the file was opened where vci cannot see it.
    def fd_reopened(io)
      return unless collect? && !busy?
      st = quiet { io.stat }
      return if st.nil? || !st.file?
      return if @inodes.key?([st.dev, st.ino])
      taint("ruby:fd-open:#{io.fileno} at #{quiet { frame }} (a file opened where vci cannot see it)")
    rescue StandardError => e
      taint("ruby:fd-open:#{e.class}")
    end

    def exists_quietly?(p)
      quiet { Real.exist?(p) }
    rescue StandardError
      false
    end

    # --- require / load ------------------------------------------------

    def relative_feature?(f)
      !(f.start_with?("/") || f.start_with?("./") || f.start_with?("../") || f.start_with?("~"))
    end

    # The files Ruby tries for `feature` in one load path entry, in order.
    def candidates(base, feature)
      ext = Real.extname(feature)
      case ext
      when ".rb" then [Real.join(base, feature)]
      when ".so", ".bundle", ".o", ".dll"
        stem = feature.delete_suffix(ext)
        ([Real.join(base, feature)] + DLEXTS.map { |x| Real.join(base, stem + x) }).uniq
      else RBEXTS.map { |x| Real.join(base, feature + x) }
      end
    end

    def expanded_load_path
      $LOAD_PATH.map do |e|
        s = e.respond_to?(:to_path) ? e.to_path : e.to_s
        @lp_memo[s] ||= quiet { Real.expand_path(s) }
      end
    rescue StandardError
      []
    end

    # A load path entry of the repository's own code: inside the
    # repository, and not an installed gem's directory under a gem root
    # there (a bundle installed in the repository, BUNDLE_PATH=vendor/bundle:
    # its gems are externals, identified by version, as when the bundle is
    # installed outside the repository, and probing every one of their
    # directories for every require costs seconds per file). Gem.path holds
    # the bundle's directory once Bundler has set it up; a path gem inside
    # the repository is not under it and stays repository code.
    def repo_entry?(e)
      return false unless inside?(e, repo)
      !(defined?(::Gem) && ::Gem.respond_to?(:path) && ::Gem.path.any? { |r| inside?(e, r.to_s) })
    rescue StandardError
      true
    end

    # A relative feature was required and found at `hit` (nil: unknown).
    # Every repository load path entry Ruby searched before the one holding
    # it gets a probe per candidate, so a file created there later (which
    # Ruby would load instead) invalidates.
    def lookup(feature, hit, lp)
      return unless collect?
      quiet do
        lp.each do |e|
          cands = candidates(e, feature)
          if hit && cands.include?(hit)
            cands.each do |c|
              break if c == hit
              @records[[:probe, c]] = true if repo_entry?(e)
            end
            return
          end
          next unless repo_entry?(e)
          cands.each { |c| @records[[exists_quietly?(c) ? :read : :probe, c]] = true }
        end
      end
    end

    # A failed require / require_relative / load / autoload.
    def missing_feature(path)
      return unless collect? && path.is_a?(String) && !path.empty?
      if relative_feature?(path)
        expanded_load_path.each do |e|
          next unless repo_entry?(e)
          candidates(e, path).each { |c| @records[[:probe, c]] = true unless exists_quietly?(c) }
        end
        # `load "x"` falls back to the working directory.
        c = Real.expand_path(path)
        @records[[:probe, c]] = true if inside?(c, repo) && !exists_quietly?(c)
      else
        abs = Real.expand_path(path)
        candidates(Real.dirname(abs), Real.basename(abs)).each do |c|
          add(:probe, c) unless exists_quietly?(c)
        end
      end
    end

    # --- glob ---------------------------------------------------------

    def expand_braces(pat)
      i = pat.index("{")
      return [pat] unless i
      depth = 0
      j = i
      parts = []
      start = i + 1
      while j < pat.length
        c = pat[j]
        if c == "\\"
          j += 2
          next
        end
        if c == "{"
          depth += 1
        elsif c == "}"
          depth -= 1
          if depth.zero?
            parts << pat[start...j]
            break
          end
        elsif c == "," && depth == 1
          parts << pat[start...j]
          start = j + 1
        end
        j += 1
      end
      return [pat] unless depth.zero?
      pre = pat[0...i]
      post = pat[(j + 1)..].to_s
      parts.flat_map { |p| expand_braces(pre + p + post) }
    end

    def wild?(c)
      c.match?(/[*?\[]/)
    end

    # Record what `Dir.glob(pattern)` depends on: the listing of every
    # directory it reads, and every literal path it checks.
    def glob_record(patterns, base, flags)
      return unless collect? && !busy?
      return if GLOB_NOT_INPUT.match?(quiet { frame })
      quiet do
        start_base = base ? literal_path(pathify(base) || base.to_s) : Real.dir_pwd
        Array(patterns).each do |raw|
          pat = pathify(raw)
          next unless pat
          expand_braces(pat).each do |p|
            start = p.start_with?("/") ? "/" : start_base
            comps = p.split("/").reject(&:empty?).drop_while { |c| c == "." }
            glob_walk(start, comps, flags.is_a?(Integer) ? flags : 0, 0)
          end
        end
      end
    rescue StandardError => e
      taint("ruby:glob:#{e.class}: #{e.message}")
    end

    def glob_walk(dir, comps, flags, depth)
      return if comps.empty? || depth > 64
      c = comps[0]
      rest = comps[1..]
      dotmatch = (flags & File::FNM_DOTMATCH) != 0
      if c == "**"
        return unless Real.directory?(dir)
        add(:readdir, dir)
        glob_walk(dir, rest, flags, depth + 1)
        children(dir).each do |n|
          next if n.start_with?(".") && !dotmatch
          p = Real.join(dir, n)
          next if Real.symlink?(p) || !Real.directory?(p)
          glob_walk(p, comps, flags, depth + 1)
        end
      elsif wild?(c)
        unless Real.directory?(dir)
          add(:probe, dir) unless Real.exist?(dir)
          return
        end
        add(:readdir, dir)
        return if rest.empty?
        fl = File::FNM_PATHNAME | File::FNM_EXTGLOB | (dotmatch ? File::FNM_DOTMATCH : 0)
        children(dir).each do |n|
          next unless Real.fnmatch(c, n, fl)
          p = Real.join(dir, n)
          glob_walk(p, rest, flags, depth + 1) if Real.directory?(p)
        end
      else
        p = Real.join(dir, c.gsub(/\\(.)/, '\1'))
        if rest.empty?
          add(Real.exist?(p) || Real.symlink?(p) ? :stat : :probe, p)
        elsif Real.directory?(p)
          glob_walk(p, rest, flags, depth + 1)
        else
          add(:probe, p) unless Real.exist?(p)
        end
      end
    end

    def children(dir)
      Real.dir_children(dir)
    rescue StandardError
      []
    end

    # realpath() reveals the type of every component: record each one inside
    # the repository (a symlink with its target).
    def realpath_walk(path, dir)
      return unless collect? && !busy?
      p = pathify(path)
      return unless p
      abs = quiet { literal_path(p, dir && (pathify(dir) || dir.to_s)) }
      cur = ""
      abs.split("/").reject(&:empty?).each do |c|
        cur = "#{cur}/#{c}"
        observe_stat(cur, walk: abs) if inside?(cur, repo)
      end
    end

    # The exit status the process is leaving with, from `$!` as this (the
    # last) at_exit handler starts: every handler registered after the
    # collector (RSpec's, minitest/autorun's, SimpleCov's minimum_coverage
    # check, a test's own `at_exit { exit 1 }`) has run and set it. Read it
    # first thing: Ruby resets `$!` inside some of the collector's own calls
    # (`defined?` on a constant, rescued exceptions), so a later read would
    # see nil and report 0. `vci run` also checks the exit code it gets.
    def exit_status(e = $!)
      if e.is_a?(SystemExit)
        e.status
      elsif e
        1
      else
        0
      end
    end
  end
end

# ---------------------------------------------------------------------------
# Batch mode: several test files, one boot (BATCH_IDS).
# ---------------------------------------------------------------------------
module VciCollector
  # `vci run` of several files of one runner starts one process
  # (`bin/rails test <files>`, `rspec <files>`) with VCI_RAILS_BATCH naming
  # their test ids. When the runner's loader asks for the first of them
  # (Rails' Runner.load_tests requires each file, RSpec's load_spec_files
  # loads each), that process (the driver) loads none of them: for each
  # group of files whose first statement requires the same helper
  # (test_helper, rails_helper: the boot), it forks a process that requires
  # that helper, which then forks one process per file of the group, one at
  # a time (they share the test database, as one-file runs do). From the
  # fork on, a file's process is a one-file run of that file: the loader's
  # requests for the other files of the batch are skipped, its own file
  # loads (and whatever it requires, other test files included), its tests
  # run, and at exit it writes its output as a one-file run does
  # (VciCollector.test_id: its file), holding what the boot observed before
  # the fork, which a one-file run observes too. Nothing one file's process
  # does reaches another's: classes, monkey patches, constants, shared
  # examples, memoized data, loaded code, threads, native libraries,
  # results. What they share is what one process per file shares: the file
  # system and the database, plus vci's temp dir, from which what a file's
  # process left is removed before the next one starts (see tmp_cleanup).
  #
  # The boot is the file's own first statement, so a file's process has
  # run exactly what its one-file run runs, in the same order. A file whose
  # first statement is not a plain require of a helper (`require "x"`,
  # `require_relative "x"`, `require File.expand_path("x", __dir__)`) has
  # no boot in common with others: its process requires everything itself.
  #
  # Slots: when the project runs its tests in Rails' parallel worker
  # processes (`parallelize`, with: :processes), or VCI_RAILS_JOBS asks for
  # it, a group of several files runs in W slots at once (SLOTS, at most one
  # per file). After the boot, the group's process runs Rails' before-fork
  # hooks and forks one long-lived process per slot, which does what a Rails
  # parallel worker does after its fork: `parallel_worker_id = i` and every
  # after-fork hook with its index (Rails' own creates and loads the
  # database `<db>_<i>` and reconnects to it; `parallelize_setup` blocks,
  # Oaken's `load_seed`). Then the slot forks one process per file, one at a
  # time: slot i's first file is the group's i-th, the rest come from a
  # queue the slots share, in the group's order. A file's process is the
  # same one-file run as above, against its slot's database, which it does
  # not seed again: Minitest's executor says the run is parallel
  # (`should_parallelize?`, which Oaken's first `before_setup` asks), as in
  # a Rails worker. Each slot has a temp dir of its own (TMPDIR), cleaned
  # after each file's process as above; at its end the slot runs the
  # cleanup hooks (`parallelize_teardown`). What the files of different
  # slots share is what Rails' workers share: the file system, the database
  # server, and vci's temp dir outside the slots' own (any change there
  # sends every file of the group back to run on its own).
  #
  # $VCI_OUT/batch/files.jsonl gets a line per file: {id, exit} (its
  # process's exit status; null: a signal killed it; with `slot`: the slot
  # that ran it), or {id, why}: vci must run it again on its own (a later
  # {id, why} overrides an earlier {id, exit}). A slot that could not set up
  # or stopped says so in a line {slot, why} with no id. The driver ends
  # with {done: true}.
  module Batch
    # The loaders of the test runners (the frame that asks for a test file).
    LOADERS = %r{/(rails/test_unit/runner|rspec/core/configuration)\.rb\z}
    # Frames between a loader and the collector's hook: require wrappers
    # (Zeitwerk's Kernel#require, Ruby's bundled_gems replace_require,
    # RSpec's __send__).
    WRAPPERS = /require|load|\A(__send__|send|public_send)\z/
    LEADING = [
      [/\Arequire\s*\(?\s*(["'])([^"'\\#]+)\1\s*\)?\s*(?:#.*)?\z/, :require],
      [/\Arequire_relative\s*\(?\s*(["'])([^"'\\#]+)\1\s*\)?\s*(?:#.*)?\z/, :relative],
      [/\Arequire\s*\(?\s*File\.expand_path\(\s*(["'])([^"'\\#]+)\1\s*,\s*(__dir__|__FILE__|File\.dirname\(__FILE__\))\s*\)\s*\)?\s*(?:#.*)?\z/,
       :expand]
    ].freeze

    # Extends Minitest's executor in a slot (Batch.parallel_executor!):
    # `should_parallelize?` is true, except to the executor's own `start`
    # (Rails' ParallelizeExecutor forks its workers when it says so).
    module SlotExecutor
      def start(*args, **kw, &blk)
        @vci_own_start = true
        super if defined?(super)
      ensure
        @vci_own_start = false
      end

      def should_parallelize?
        return super if @vci_own_start && defined?(super)
        true
      end
    end

    # Records what ActiveSupport::TestCase.parallelize was asked for
    # (Batch.install_parallelize).
    module ParallelizeCall
      def parallelize(*args, **kw, &blk)
        VciCollector::Batch.parallelize_called(kw.fetch(:workers, :number_of_processors))
        super
      end
    end

    @target = nil
    @own_fork = false
    @slot = nil
    @slot_tmp = nil

    class << self
      # The test id this process runs (a file's process), or nil.
      attr_reader :target
      # The index of the slot this process belongs to (a slot's process or
      # a file's process forked from it), or nil; its temp dir, or nil.
      attr_reader :slot, :slot_tmp

      # Whether this process is a slot running Rails' after-fork hooks
      # (creating and loading its database).
      def slot_setup?
        @slot_setup == true
      end

      def on?
        !BATCH_IDS.nil?
      end

      # Whether the running fork is the batch's own (not a test's).
      def own_fork?
        @own_fork
      end

      # Absolute path (as given and real) => test id.
      def ids
        @ids ||= VciCollector.quiet do
          h = {}
          BATCH_IDS.each do |id|
            abs = Real.expand_path(id, VciCollector.root)
            h[abs] ||= id
            h[VciCollector.real_of(abs)] ||= id
          end
          h
        end
      end

      # The base names (without .rb) of the batch's files: most requires are
      # none of them.
      def names
        @names ||= VciCollector.quiet { BATCH_IDS.to_h { |id| [Real.basename(id, ".rb"), true] } }
      end

      # The test id of a file (absolute, or relative to the project), or nil.
      def id_of(path)
        p = VciCollector.pathify(path)
        return nil unless p.is_a?(String) && !p.empty?
        VciCollector.quiet do
          abs = Real.expand_path(p, VciCollector.root)
          ids[abs] || ids[abs.end_with?(".rb") ? abs : "#{abs}.rb"] || ids[VciCollector.real_of(abs)]
        end
      rescue StandardError
        nil
      end

      # Whether the runner's loader makes the require or load being hooked.
      def loader_call?
        me = __FILE__
        (caller_locations(2, 40) || []).each do |l|
          p = (l.absolute_path || l.path).to_s
          return true if LOADERS.match?(p)
          next if p == me || WRAPPERS.match?(l.base_label.to_s)
          return false
        end
        false
      end

      # A require or load of `path`: :skip when, in a file's process, the
      # loader asks for another file of the batch; else :load. The first
      # request of the loader for a file of the batch forks the run (drive!,
      # which returns only in a file's process).
      def gate(path)
        p = VciCollector.pathify(path)
        return :load unless p.is_a?(String) && names.key?(VciCollector.quiet { Real.basename(p, ".rb") })
        id = id_of(p)
        return :load if @preloading || !(id && loader_call?)
        drive! if @target.nil?
        id == @target ? :load : :skip
      end

      # --- the driver ---------------------------------------------------------

      def drive!
        status_dir = File.join(OUT.to_s, "batch")
        VciCollector.quiet { Dir.mkdir(status_dir) unless Real.directory?(status_dir) }
        groups = BATCH_IDS.uniq.group_by { |f| boot_of(f) }
        code = 0
        why = nil
        # Several groups run at once (2.2.12), each with a temp directory of
        # its own (so no group sees another's files): on
        # vex one file with a boot of its own ran 94 s after the main
        # group's 255 s. VCI_RAILS_GROUPS_IN_TURN=1 runs them one after the
        # other, as before.
        if groups.size > 1 && VciCollector.quiet { ENV["VCI_RAILS_GROUPS_IN_TURN"] }.to_s != "1"
          return drive_together!(groups)
        end
        groups.each_with_index do |(boot, files), gi|
          last = gi == groups.size - 1
          if why
            files.each { |f| status(id: f, why: why) }
            next
          end
          # What a group's processes leave in vci's temp dir (its boot's
          # files, its slots' dirs and what their hooks wrote there) is
          # removed before the next group boots, as each one-file run gets
          # a fresh temp dir; a change to what was there before it (the
          # runner's own files) would be seen by the next groups: they run
          # on their own.
          before = tmp_entries
          group_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          pid = fork_own
          return become(run_group(boot, files)) if pid.nil?
          _, st = Process.wait2(pid)
          status(group: { boot: boot.nil? ? "" : Array(boot).last.to_s, files: files.size,
                          ms: ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - group_started) * 1000).round })
          c = st.exitstatus || 1
          code = c if code.zero?
          unsaid(files, st)
          # The last group's leftovers need no removal here: no group runs
          # after it, and vci removes the whole temp directory when the batch
          # ends (2.2.10: walking and unlinking a full vex job's leftovers
          # one entry at a time took about 80 s).
          next if last
          t = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          changed = tmp_cleanup(before)
          status(group_cleanup_ms: ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t) * 1000).round)
          unless changed.empty?
            why = "the group of #{files.first} changed #{changed.first(3).join(", ")} in vci's temp directory, " \
                  "which the files of the groups after it would see: they run on their own"
          end
        end
        status(done: true)
        flush
        Process.exit!(code)
      rescue Exception => e # rubocop:disable Lint/RescueException
        raise if @target
        $stderr.puts "vci_collector: batch driver: #{e.class}: #{e.message}"
        Process.exit!(1)
      end

      # drive! with every group running at once, each in a temp directory of
      # its own under vci's (TMPDIR and the collector's own view of it, in
      # that group's processes only): groups share only an empty parent.
      def drive_together!(groups)
        running = []
        groups.each_with_index do |(boot, files), gi|
          own = File.join(TMP, "vci-group-#{gi}")
          VciCollector.quiet { Dir.mkdir(own) unless Real.directory?(own) }
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          pid = fork_own
          if pid.nil?
            VciCollector.quiet { ENV["TMPDIR"] = own }
            VciCollector.send(:remove_const, :TMP)
            VciCollector.const_set(:TMP, own)
            # RSpec's example status file, configured before the fork in
            # vci's temp dir, moves to the group's: the groups' processes
            # would otherwise read what the others wrote there.
            RSpecSupport.slot_moved!
            return become(run_group(boot, files))
          end
          running << [pid, boot, files, started]
        end
        code = 0
        # Each group as it ends (its own time, not the slowest's).
        until running.empty?
          pid, st = Process.wait2(-1)
          i = running.index { |r| r[0] == pid }
          next if i.nil?
          _, boot, files, started = running.delete_at(i)
          status(group: { boot: boot.nil? ? "" : Array(boot).last.to_s, files: files.size, at_once: true,
                          ms: ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round })
          c = st.exitstatus || 1
          code = c if code.zero?
          unsaid(files, st)
        end
        status(done: true)
        flush
        Process.exit!(code)
      end

      # In a group's process: the boot, then one process per file (returns
      # the file in that file's process; exits in the group's).
      def run_group(boot, files)
        why = nil
        if boot
          begin
            preload(boot)
          rescue ScriptError, StandardError, SystemExit => e
            why = "its first statement failed in the batch's boot (#{e.class}: #{e.message.to_s.lines.first.to_s.strip}): " \
                  "it runs on its own"
          end
        end
        if why.nil? && (w = slots_for(files, boot)) > 1
          return run_slots(files, w)
        end
        share!(write: true) if why.nil? && files.size > 1
        first = 0
        files.each do |f|
          if why
            status(id: f, why: why)
            next
          end
          before = tmp_entries
          disconnect
          pid = fork_own
          return f if pid.nil?
          _, st = Process.wait2(pid)
          status(id: f, exit: st.exitstatus)
          first = st.exitstatus || 1 if first.zero? && !st.success?
          changed = tmp_cleanup(before)
          unless changed.empty?
            why = "the process of #{f} changed #{changed.first(3).join(", ")} in vci's temp directory, which the " \
                  "files after it in the batch would see: they run on their own"
          end
        end
        flush
        Process.exit!(first)
      rescue Exception => e # rubocop:disable Lint/RescueException
        raise if @target
        $stderr.puts "vci_collector: batch boot: #{e.class}: #{e.message}"
        Process.exit!(1)
      end

      # --- slots --------------------------------------------------------------

      # How many slots run the group's `files` (1: one file at a time, as
      # above): SLOTS, at most one per file, when the project runs its tests
      # in Rails' parallel worker processes (at most as many as its
      # `parallelize(workers:)` asks for, unless vci's PARALLEL_WORKERS says
      # how many: `workers: 1` is a project whose tests must not run at
      # once) or VCI_RAILS_JOBS asked for it. Never for a group without a
      # boot (`boot` nil): nothing is loaded when the slots fork, so no
      # after-fork hook gives a slot its database (the files' own
      # `require "test_helper"` registers Rails' only after the fork), and
      # its files would run at once on one database.
      def slots_for(files, boot)
        w = [SLOTS, files.size].min
        return 1 if w < 2 || boot.nil?
        return w if SLOTS_ASKED
        return 1 unless rails_parallel?
        return w if SLOTS_WORKERS
        n = workers_asked
        n.nil? ? w : [w, n].min.clamp(1, w)
      end

      # The number of workers the boot's `parallelize(workers:)` asked for
      # (an Integer), or nil (`:number_of_processors`, the default, or not
      # seen). Recorded by ParallelizeCall: under vci's PARALLEL_WORKERS=1,
      # Rails' executor always has size 1.
      def workers_asked
        v = @workers
        return nil if v.nil? || v == :number_of_processors
        Integer(v.is_a?(String) ? v.strip : v)
      rescue ArgumentError, TypeError
        nil
      end

      # ActiveSupport::TestCase.parallelize was called with `workers`.
      def parallelize_called(workers)
        @workers = workers
      end

      # Hook ActiveSupport::TestCase.parallelize (VciCollector::HOOKS), in
      # batch mode only: what it was asked for decides the slots
      # (workers_asked).
      def install_parallelize
        return true unless on?
        return false unless defined?(::ActiveSupport::TestCase)
        return false if ::ActiveSupport.respond_to?(:autoload?) && !::ActiveSupport.autoload?(:TestCase).nil?
        return false unless ::ActiveSupport::TestCase.respond_to?(:parallelize)
        ::ActiveSupport::TestCase.singleton_class.prepend(ParallelizeCall)
        true
      end

      # Whether the boot called Rails' `parallelize` with processes (its
      # executor is Rails' and forks workers): the project's test setup is
      # made for processes with a database each.
      def rails_parallel?
        return false unless defined?(::Minitest) && ::Minitest.respond_to?(:parallel_executor)
        return false unless defined?(::ActiveSupport::Testing::ParallelizeExecutor)
        ex = ::Minitest.parallel_executor
        ex.is_a?(::ActiveSupport::Testing::ParallelizeExecutor) && ex.parallelize_with == :processes
      rescue StandardError
        false
      end

      # Rails' parallelization hooks of `kind` (:before_fork_hooks,
      # :after_fork_hooks, :run_cleanup_hooks), or none.
      def rails_hooks(kind)
        return [] unless defined?(::ActiveSupport::Testing::Parallelization)
        p = ::ActiveSupport::Testing::Parallelization
        p.respond_to?(kind) ? Array(p.public_send(kind)) : []
      rescue StandardError
        []
      end

      # The directory holding the slots' temp dirs, in vci's temp dir.
      def slots_root
        TMP.nil? || TMP.empty? ? nil : File.join(TMP, "vci-slots")
      end

      # In a group's process after the boot: `w` slots run the files (returns
      # the file in that file's process; exits in the group's). The group's
      # process waits for every slot, then says why of each file no slot ran,
      # and sends every file back when something changed in vci's temp dir
      # outside the slots' own (a file the boot opened there, a cache another
      # file's process could have read: who changed it, and who saw it, is
      # unknown).
      def run_slots(files, w)
        root = slots_root
        VciCollector.quiet do
          Dir.mkdir(root) unless Real.directory?(root)
          w.times { |i| Dir.mkdir(File.join(root, i.to_s)) unless Real.directory?(File.join(root, i.to_s)) }
        end if root
        queue = File.join(OUT.to_s, "batch", "queue-#{Process.pid}")
        VciCollector.quiet { File.write(queue, w.to_s) }
        # Every slot's lines say when they were written, from here (ms).
        @batch_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        status(boot_ms: ((@batch_started - VciCollector::LOADED_AT) * 1000).round)
        spawned = VciCollector.quiet { ENV["VCI_BATCH_SPAWNED_MS"] }.to_s
        if spawned.match?(/\A\d+\z/)
          status(spawn_to_slots_ms: [(Time.now.to_f * 1000).round - spawned.to_i, 0].max)
        end
        if root
          @tmp_mark = File.join(OUT.to_s, "batch", "tmp-shared-#{Process.pid}")
          @shared_dirs = VciCollector.quiet { Output.both(TMP) }
        end
        begin
          rails_hooks(:before_fork_hooks).each(&:call)
        rescue Exception => e # rubocop:disable Lint/RescueException
          why = "Rails' before-fork hooks failed in the batch's boot (#{e.class}: " \
                "#{e.message.to_s.lines.first.to_s.strip}): it runs on its own"
          files.each { |f| status(id: f, why: why) }
          flush
          Process.exit!(0)
        end
        # What the boot recorded, classified once for every slot (each
        # slot's own shared output then only classifies what its setup
        # recorded).
        share!(write: false)
        disconnect
        shared = shared_tmp_entries
        pids = []
        w.times do |i|
          pid = fork_own
          return run_slot(i, files, queue, shared) if pid.nil?
          pids << pid
        end
        first = 0
        died = []
        pids.each_with_index do |pid, i|
          _, st = Process.wait2(pid)
          first = st.exitstatus || 1 if first.zero? && !st.success?
          died << "slot #{i} ended (signal #{st.termsig})" if st.signaled?
        end
        waited_at = batch_at
        t = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        said, stopped = said_lines
        said_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t) * 1000).round
        stopped += died
        # A change there that is gone by now (written and removed while
        # other slots ran) was seen by a slot after a file, or noted when a
        # process of a slot wrote there (slot_wrote).
        t = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        changed = (shared_tmp_changes(shared) | tmp_marked).sort
        status(after_slots: { waited_at: waited_at, said_ms: said_ms,
                              tmp_ms: ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t) * 1000).round })
        files.each do |f|
          if !changed.empty?
            status(id: f, why: "a process of the batch changed #{changed.first(3).join(", ")} in vci's temp " \
                               "directory, outside its slot's, which any file of its group could have read: " \
                               "it runs on its own")
          elsif !said.include?(Json.str(f)[1..-2])
            how = stopped.empty? ? "every slot stopped" : stopped.uniq.first(2).join("; ")
            status(id: f, why: "no slot of the batch ran it (#{how}): it runs on its own")
          end
        end
        flush
        Process.exit!(first)
      rescue Exception => e # rubocop:disable Lint/RescueException
        raise if @target
        $stderr.puts "vci_collector: batch slots: #{e.class}: #{e.message}"
        Process.exit!(1)
      end

      # A slot's process: set up as a Rails parallel worker `i` is, then one
      # process per file (returns the file in that file's process; exits in
      # the slot's).
      def run_slot(i, files, queue, shared)
        @slot = i
        if (root = slots_root)
          @slot_tmp = File.join(root, i.to_s)
          VciCollector.quiet { ENV["TMPDIR"] = @slot_tmp }
          @own_dirs = VciCollector.quiet { Output.both(@slot_tmp) }
          RSpecSupport.slot_moved!
        end
        begin
          if defined?(::ActiveSupport::TestCase) && ::ActiveSupport::TestCase.respond_to?(:parallel_worker_id=)
            ::ActiveSupport::TestCase.parallel_worker_id = i
          end
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          @slot_setup = true
          rails_hooks(:after_fork_hooks).each { |cb| cb.call(i) }
          @slot_setup = false
          status(slot: i, setup_ms: ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round,
                 at: batch_at)
        rescue Exception => e # rubocop:disable Lint/RescueException
          status(slot: i, why: "slot #{i}'s setup (Rails' after-fork hooks: its database, parallelize_setup) " \
                               "failed: #{e.class}: #{e.message.to_s.lines.first.to_s.strip}")
          take(queue, files.size, back: i)
          cleanup_slot(i)
          flush
          Process.exit!(0)
        end
        parallel_executor!
        share!(write: true)
        first = 0
        nxt = i
        while nxt && nxt < files.size
          f = files[nxt]
          before = tmp_entries(@slot_tmp)
          disconnect
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          pid = fork_own
          return f if pid.nil?
          _, st = Process.wait2(pid)
          status(id: f, exit: st.exitstatus, slot: i,
                 ms: ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round, at: batch_at)
          first = st.exitstatus || 1 if first.zero? && !st.success?
          changed = @slot_tmp ? tmp_cleanup(before, @slot_tmp) : []
          unless changed.empty?
            status(slot: i, why: "the process of #{f} changed #{changed.first(3).join(", ")} in slot #{i}'s temp " \
                                 "directory: the slot takes no more files")
            break
          end
          seen = shared_tmp_changes(shared)
          unless seen.empty? && tmp_marked.empty?
            # The group's process sends every file back for this, even when
            # the change is gone by the time the slots end.
            seen.each { |p| mark_tmp(p) }
            status(slot: i, why: "vci's temp directory changed outside the slots' own: slot #{i} takes no more files")
            break
          end
          nxt = take(queue, files.size)
        end
        cleanup_slot(i)
        flush
        Process.exit!(first)
      rescue Exception => e # rubocop:disable Lint/RescueException
        raise if @target
        $stderr.puts "vci_collector: batch slot #{i}: #{e.class}: #{e.message}"
        Process.exit!(1)
      end

      # Milliseconds since the slots were started (`run_slots`).
      def batch_at
        ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - (@batch_started || 0)) * 1000).round
      end

      # Rails' cleanup hooks (parallelize_teardown), as a worker runs them
      # before it exits.
      def cleanup_slot(i)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        rails_hooks(:run_cleanup_hooks).each { |cb| cb.call(i) }
        status(slot: i, cleanup_ms: ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round,
               cleanup_end_at: batch_at)
      rescue Exception => e # rubocop:disable Lint/RescueException
        $stderr.puts "vci_collector: slot #{i}'s cleanup hooks (parallelize_teardown): #{e.class}: #{e.message}"
      end

      # The slots' shared queue (a file: the index of the next file, then
      # those given back): the next file's index, or nil. With `back`:
      # gives that index back instead (a slot that cannot run its first
      # file), for the next slot that asks.
      def take(queue, n, back: nil)
        VciCollector.quiet do
          File.open(queue, File::RDWR) do |q|
            q.flock(File::LOCK_EX)
            nxt, *given = q.read.split(",").map(&:to_i)
            nxt ||= n
            i = nil
            if back
              given << back
            elsif !given.empty?
              i = given.shift
            elsif nxt < n
              i = nxt
              nxt += 1
            end
            q.rewind
            q.truncate(0)
            q.write([nxt, *given].join(","))
            q.flush
            i
          end
        end
      rescue StandardError
        nil
      end

      # Minitest's executor in a slot says the run is parallel (Oaken's
      # TestSetup asks `should_parallelize?` in the first `before_setup` of a
      # process and reseeds the database unless it is: the slot seeded it
      # once, as a Rails worker does). The executor is left as it is
      # otherwise: Rails' own (`is_a?` as before; under vci's
      # PARALLEL_WORKERS=1 it forks no worker, and its own `start` still gets
      # its own answer) or Minitest's.
      def parallel_executor!
        return unless defined?(::Minitest) && ::Minitest.respond_to?(:parallel_executor)
        ex = ::Minitest.parallel_executor or return
        ex.extend(SlotExecutor)
      rescue StandardError
        nil
      end

      # In a slot's process, or a file's process forked from it: the process
      # wrote `abs` (VciCollector.wrote, .opened). In vci's temp dir outside
      # its slot's own (a path computed before the slots forked, as
      # `BOOT_TMP = Dir.tmpdir` in a helper), a process of another slot
      # running at the same time could have read it, which nothing records
      # (reads in vci's temp dir are not inputs): noted for the group's
      # process, which sends every file of the group back, even when the
      # write is undone before any snapshot of the temp dir sees it. Writes
      # vci cannot see (a C extension's) are caught only by the snapshots.
      def slot_wrote(abs)
        return if @slot.nil? || @tmp_mark.nil? || @shared_dirs.nil?
        return unless @shared_dirs.any? { |d| VciCollector.inside?(abs, d) }
        return if (@own_dirs || []).any? { |d| VciCollector.inside?(abs, d) }
        mark_tmp(abs)
      end

      # Note `path` (a change in vci's temp dir outside the slots' own) for
      # the group's process.
      def mark_tmp(path)
        return if @tmp_mark.nil? || (@marked ||= {}).key?(path)
        @marked[path] = true
        VciCollector.quiet { File.open(@tmp_mark, "a") { |f| f.write("#{path}\n") } }
      rescue StandardError
        nil
      end

      # What the slots' processes noted (mark_tmp) so far.
      def tmp_marked
        return [] if @tmp_mark.nil?
        VciCollector.quiet { Real.exist?(@tmp_mark) ? File.read(@tmp_mark).split("\n").reject(&:empty?).uniq : [] }
      rescue StandardError
        []
      end

      # Every entry of vci's temp dir outside the slots' temp dirs.
      def shared_tmp_entries
        root = slots_root
        tmp_entries.reject { |p, _| root && (p == root || p.start_with?("#{root}/")) }
      end

      # The entries of vci's temp dir outside the slots' that are not what
      # they were in `before` (a directory's mtime aside).
      def shared_tmp_changes(before)
        after = shared_tmp_entries
        (before.keys | after.keys).select do |p|
          b = before[p]
          a = after[p]
          b.nil? || a.nil? || (b[0] != "directory" && a != b)
        end.sort
      end

      # What files.jsonl says so far: the ids it has a line of (as Json.str
      # spells them, without the quotes) and the slots' {slot, why} lines.
      def said_lines
        ids = []
        stops = []
        VciCollector.quiet do
          File.readlines(File.join(OUT.to_s, "batch", "files.jsonl")).each do |l|
            if (id = l[/"id":"((?:[^"\\]|\\.)*)"/, 1])
              ids << id
            elsif l.include?("\"slot\":") && (why = l[/"why":"((?:[^"\\]|\\.)*)"/, 1])
              stops << why
            end
          end
        end
        [ids, stops]
      rescue StandardError
        [ids || [], stops || []]
      end

      # The runner's handling of its arguments (Rails' extract_filters,
      # RSpec's files_to_run) checks each file of the batch before the run
      # forks; a one-file run checks its own file only (become).
      def loader_check(kind, abs, where)
        return unless @target.nil? && LOADERS.match?(where) && ids.key?(abs)
        (@loader_checks ||= {})[[kind, abs]] = true
      end

      # After a group's process: a line for each of its files it said
      # nothing of (it died: a signal, a crash in the boot).
      def unsaid(files, st)
        said = VciCollector.quiet do
          File.readlines(File.join(OUT.to_s, "batch", "files.jsonl")).map { |l| l[/"id":"((?:[^"\\]|\\.)*)"/, 1] }
        rescue StandardError
          []
        end
        how = st.signaled? ? "signal #{st.termsig}" : "exit #{st.exitstatus}"
        files.each do |f|
          next if said.include?(Json.str(f)[1..-2])
          status(id: f, why: "the process that booted its group ended (#{how}) before it ran it")
        end
      end

      # A file's process: from now on a one-file run of `id`.
      def become(id)
        @target = id
        (@loader_checks || {}).each_key { |k| VciCollector.records.delete(k) unless ids[k[1]] == id }
        VciCollector.instance_variable_set(:@pid, Process.pid)
        VciCollector.instance_variable_set(:@test_id, id)
        # Minitest's at_exit (registered by the driver) sets the exit status
        # only in the process that registered it, unless forks may.
        ::Minitest.allow_fork = true if defined?(::Minitest) && ::Minitest.respond_to?(:allow_fork=)
        id
      end

      # Close the boot's database connections before a file's process forks,
      # as Rails' `parallelize` does before it forks its workers: a forked
      # process that used them, and closed them at exit, would leave the
      # next one a dead socket ("Lost connection to MySQL server during
      # query" on vex-api). Each file's process connects anew, as its
      # one-file run connected at boot.
      def disconnect
        return unless defined?(::ActiveRecord::Base) && ::ActiveRecord::Base.respond_to?(:connection_handler)
        VciCollector.quiet { ::ActiveRecord::Base.connection_handler.clear_all_connections! }
      rescue StandardError
        nil
      end

      def flush
        [$stdout, $stderr].each { |io| io.flush rescue nil }
      end

      def fork_own
        flush
        @own_fork = true
        Process.fork
      ensure
        @own_fork = false
      end

      # A line of $VCI_OUT/batch/files.jsonl.
      def status(line)
        VciCollector.quiet do
          # One write of the whole line: the slots' processes append to the
          # same file.
          File.open(File.join(OUT.to_s, "batch", "files.jsonl"), "a") { |f| f.write("#{Json.dump(line)}\n") }
        end
      end

      # The driver's process ran the tests itself: the loader never asked
      # for a file of the batch (a runner vci does not know). Every file
      # runs again on its own.
      def undriven!
        return unless OUT
        VciCollector.quiet { Dir.mkdir(File.join(OUT, "batch")) unless Real.directory?(File.join(OUT, "batch")) }
        why = "the test runner did not load the batch's files through its own loader (Rails' Runner.load_tests, " \
              "RSpec's load_spec_files)"
        BATCH_IDS.uniq.each { |f| status(id: f, why: why) }
        status(done: true)
      end

      # --- the boot -----------------------------------------------------------

      # What the first statement of file `id` requires ([kind, name]), or
      # nil (comments, blank lines and magic comments before it).
      def boot_of(id)
        abs = VciCollector.quiet { Real.expand_path(id, VciCollector.root) }
        text = VciCollector.quiet { Real.binread(abs) }.dup.force_encoding(Encoding::UTF_8).scrub
        in_doc = false
        text.each_line do |raw|
          line = raw.strip
          if in_doc
            in_doc = false if raw.start_with?("=end")
            next
          end
          if raw.start_with?("=begin")
            in_doc = true
            next
          end
          next if line.empty? || line.start_with?("#")
          LEADING.each do |re, kind|
            m = re.match(line) or next
            return [:require, m[2]] if kind == :require
            dir = VciCollector.quiet { Real.dirname(VciCollector.real_of(abs)) }
            return [:path, VciCollector.quiet { Real.expand_path(m[2], dir) }] if kind == :relative
            base = m[3] == "__FILE__" ? abs : VciCollector.quiet { Real.dirname(abs) }
            base = VciCollector.quiet { Real.dirname(VciCollector.real_of(abs)) } if m[3] == "__dir__"
            return [:path, VciCollector.quiet { Real.expand_path(m[2], base) }]
          end
          return nil
        end
        nil
      rescue StandardError
        nil
      end

      # Run a boot as the file's first statement does (recorded as anything
      # else the process loads). A boot may be another test file of the
      # batch (`require_relative "queue_result_reuse_test"`, vex-api's
      # ci/batch_queue_result_reuse_test.rb): it loads as the first
      # statement loads it in a one-file run (its tests with it), and is not
      # the runner's request for a file of the batch, which the boot runs
      # inside of (gate: before this, the group's process drove the whole
      # batch again from there).
      def preload(boot)
        @preloading = true
        require boot[1]
      ensure
        @preloading = false
      end

      # --- the output its files share ---------------------------------------

      # The shared output this process's files' processes refer to (see
      # share!), or nil: {name:, sha256:, index: {line => its index}}.
      attr_reader :shared

      # In a group's or slot's process, before it forks its files'
      # processes: everything recorded so far is in each of them, and most
      # of what each writes at exit is the same (on vex-api ~14,000 lines a
      # file, 2 to 4 s of classifying them, checking the gems' files against
      # their archives and writing them). A child process writes those lines
      # once (`write`), as Output.lines_of makes them in a process that ends
      # now (`shared: true`), to $VCI_OUT/batch/shared-<pid>.jsonl, and gives
      # this process back how it classified each path and what it found in
      # the gems' archives (inherited by every file's process, so its own
      # output costs only what it observed itself) and the lines (this
      # process keeps their index, see split). The child does all of it:
      # what Output and GemVerify load or remember (the zone data source,
      # Active Record's database tasks, rubygems/package) must not be in
      # the processes of the files, whose own runs load it themselves, or
      # not.
      #
      # Sound by construction: the shared lines hold only what this process
      # recorded before any file's process forked from it, which every one
      # of them inherits; each file's process still makes all of its lines
      # at exit and writes those that are not shared, and the shared lines
      # that are not its own (split), so the two together are its lines
      # whatever happened after the fork. Anything that fails here leaves
      # each file's process writing all of its output.
      def share!(write:)
        @shared = nil
        return unless SHARED_OUTPUT && OUT
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        name = "shared-#{Process.pid}.jsonl"
        r, w = VciCollector.quiet { IO.pipe }
        disconnect
        pid = fork_own
        if pid.nil?
          code = 1
          begin
            r.close
            w.binmode
            w.write(Marshal.dump(VciCollector.quiet { shared_output(write ? name : nil) }))
            w.close
            code = 0
          rescue Exception => e # rubocop:disable Lint/RescueException
            $stderr.puts "vci_collector: batch: the files' shared output: #{e.class}: #{e.message}"
          ensure
            Process.exit!(code)
          end
        end
        w.close
        r.binmode
        blob = r.read
        r.close
        _, st = Process.wait2(pid)
        raise "its process ended (#{st.signaled? ? "signal #{st.termsig}" : "exit #{st.exitstatus}"})" unless st.success?
        data = Marshal.load(blob) # rubocop:disable Security/MarshalLoad
        Output.learn(data[:classified])
        Output.learn_ignored(data[:ignored])
        GemVerify.learn(data[:gems])
        return unless write
        index = {}
        data[:lines].each_with_index { |l, i| index[l] = i }
        @shared = { name: name, sha256: data[:sha256], index: index, size: data[:lines].size }
        output_line(shared: name, lines: index.size,
                    ms: ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round)
      rescue StandardError => e
        @shared = nil
        $stderr.puts "vci_collector: batch: the lines its files share were not written once (#{e.class}: " \
                     "#{e.message}); each file's process writes all of its output"
      end

      # In share!'s child: the shared lines (written to `name` in
      # $VCI_OUT/batch, if given), with what the child learnt making them.
      # The runner's checks of the batch's files (loader_check) are left
      # out: each file's process keeps its own file's only.
      def shared_output(name)
        vc = VciCollector
        (@loader_checks || {}).each_key { |k| vc.records.delete(k) }
        DB.schema_files.each { |f| vc.schema_input(f) }
        lines = Output.lines_of(0, shared: true)
        out = { classified: Output.classified, gems: GemVerify.done, ignored: Output.ignore_memo }
        return out unless name
        require "digest/sha2"
        text = lines.map { |l| "#{Json.dump(l)}\n" }.join
        path = File.join(OUT, "batch", name)
        File.write("#{path}.tmp", text)
        File.rename("#{path}.tmp", path)
        out.merge(lines: lines, sha256: Digest::SHA256.hexdigest(text))
      end

      # A file's process at exit, its output's `lines` (Output.lines_of):
      # when its boot or slot wrote the shared lines, the lines to write
      # instead: meta, {kind: "shared", base: <its name>, sha256: <of its
      # content>, drop: [the indexes of its lines that are not this file's]},
      # then every line of `lines` that is not one of the shared lines (a
      # line twice: once more). vci reads the shared lines but those
      # dropped, and these (read_batch). nil: write `lines` as they are.
      def split(lines)
        sh = @shared
        return nil unless sh && @target
        index = sh[:index]
        used = Array.new(sh[:size], false)
        own = []
        lines.each do |l|
          i = index[l]
          if i.nil? || used[i]
            own << l
          else
            used[i] = true
          end
        end
        meta = own.shift
        raise "no meta line first" unless meta.is_a?(Hash) && meta[:kind] == "meta"
        drop = []
        used.each_with_index { |u, i| drop << i unless u }
        [meta, { kind: "shared", base: sh[:name], sha256: sh[:sha256], drop: drop }, *own]
      rescue StandardError => e
        $stderr.puts "vci_collector: batch: #{e.class}: #{e.message}; the file's process writes all of its output"
        nil
      end

      # A file's process wrote its output: how long that took (from the
      # start of Output.write!), and how much of it was its own.
      def wrote_output(lines, split, started)
        return unless on? && @target
        line = { file: @target, ms: ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round,
                 lines: lines }
        if split
          line[:own] = split.size - 2
          line[:drop] = split[1][:drop].size
        end
        output_line(line)
      end

      # A line of $VCI_OUT/batch/output.jsonl (timings of the files'
      # output; read by vci for its log only).
      def output_line(line)
        VciCollector.quiet do
          File.open(File.join(OUT.to_s, "batch", "output.jsonl"), "a") { |f| f.write("#{Json.dump(line)}\n") }
        end
      rescue StandardError
        nil
      end

      # --- vci's temp dir -----------------------------------------------------

      # Everything under vci's temp dir (or `dir` in it): path => [type,
      # size, mtime].
      def tmp_entries(dir = TMP)
        out = {}
        return out if dir.nil? || dir.empty?
        VciCollector.quiet do
          walk = lambda do |d|
            (Real.dir_children(d) rescue []).each do |c|
              p = Real.join(d, c)
              st = (Real.lstat(p) rescue nil) or next
              out[p] = [st.ftype, st.size, st.mtime.to_r]
              walk.call(p) if st.directory?
            end
          end
          walk.call(dir)
        end
        out
      end

      # Remove what a file's process added to vci's temp dir (a fresh temp
      # dir per process, as one-file runs get). Returns the files it found
      # there before and changed or removed (the next file's process would
      # see that).
      def tmp_cleanup(before, dir = TMP)
        after = tmp_entries(dir)
        VciCollector.quiet do
          (after.keys - before.keys).sort_by { |p| -p.length }.each do |p|
            after[p][0] == "directory" ? (Dir.rmdir(p) rescue nil) : (File.unlink(p) rescue nil)
          end
        end
        before.filter_map do |p, (type, size, mtime)|
          next if type == "directory"
          a = after[p]
          p if a.nil? || a != [type, size, mtime]
        end
      end
    end
  end
end

module VciCollector
    # `require` of a feature: record the lookup (see VciCollector.lookup),
    # then hook libraries that appeared. The block does the require. In
    # batch mode the test runner's request for a test file is where the run
    # forks (Batch.gate).
    def self.around_require(path)
      return yield if busy?
      return false if Batch.on? && Batch.gate(path) == :skip
      f = pathify(path)
      lp = f && relative_feature?(f) ? expanded_load_path : nil
      n = $LOADED_FEATURES.size
      r = yield
      if r && lp
        hit = $LOADED_FEATURES.size > n ? $LOADED_FEATURES.last : nil
        lookup(f, hit, lp)
      end
      after_require
      r
    end

    # `load` of a relative path also searches the load path.
    def self.around_load(path)
      return true if !busy? && Batch.on? && Batch.gate(path) == :skip
      unless busy?
        f = pathify(path)
        if f && relative_feature?(f)
          expanded_load_path.each do |e|
            next unless inside?(e, repo)
            c = File.join(e, f)
            rec(exists_quietly?(c) ? :read : :probe, c)
          end
        end
      end
      r = yield
      after_require
      r
    end

    # Active Record's own schema maintenance, which `rails/test_help` (and
    # rspec-rails' `maintain_test_schema!` in rails_helper) runs before the
    # tests: when the test database's schema is not the current one
    # (`schema_up_to_date?`: a fresh checkout has no database yet, or
    # db/schema.rb changed), ActiveRecord::Migration.load_schema! shells out
    # to `bin/rails db:test:prepare`. That child is the engine's, not the
    # test's: it only sets up the test database, whose contents are not an
    # input. Only the `system("bin/rails db:test:prepare")` call made
    # directly by that method of the activerecord gem the bundle loaded, in
    # the project directory (where it changes to, Rails.root), is this child:
    # a test's own child processes stay refused, and so does that command
    # run anywhere else (a stubbed Rails.root would run another bin/rails).
    ENGINE_LABELS = %w[load_schema! load_schema_if_pending!].freeze
    ENGINE_COMMAND = ["bin/rails db:test:prepare"].freeze

    def self.engine_child?(args = ENGINE_COMMAND, kw = {})
      return false if busy?
      return false unless args == ENGINE_COMMAND && kw.empty?
      quiet do
        next false unless Real.realpath(Real.dir_pwd) == root
        me = __FILE__
        loc = caller_locations(2, 12)&.find { |l| (l.absolute_path || l.path) != me }
        path = loc && (loc.absolute_path || loc.path).to_s
        next false unless path&.end_with?("/lib/active_record/migration.rb")
        next false unless ENGINE_LABELS.include?(loc.base_label.to_s)
        spec = defined?(::Gem) && ::Gem.respond_to?(:loaded_specs) ? ::Gem.loaded_specs["activerecord"] : nil
        next false if spec.nil?
        # Either spelling: a frame's path is the real one, a gem's directory
        # may be spelt through a symlink (/var -> /private/var).
        dir = Real.expand_path(spec.full_gem_path)
        inside?(path, dir) || inside?(real_of(path), real_of(dir))
      end
    rescue StandardError
      false
    end

    # The arguments of that child's `system` call with VCI_RAILS_MODE=engine
    # in its environment: the collector its RUBYOPT loads does nothing there
    # (no recording, no output file that would replace the parent's).
    def self.engine_args(args)
      if args[0].is_a?(Hash)
        [args[0].merge("VCI_RAILS_MODE" => "engine"), *args[1..]]
      else
        [{ "VCI_RAILS_MODE" => "engine" }, *args]
      end
    end

    # Kernel is patched the way RubyGems, bundled_gems.rb and Zeitwerk patch
    # it (alias + redefine), not with prepend: they alias Kernel#require into
    # Kernel's singleton class, where a prepended method's `super` finds
    # nothing. Both copies are patched: Kernel#require and Kernel.require
    # (a module function). Under Bundler on Ruby 3.4, bundled_gems.rb
    # redefines Kernel#require to call Kernel.no_warning_require, an alias
    # of Kernel.require, so every plain `require` goes through the
    # singleton copy.
    def self.install_kernel_hooks
      ::Kernel.module_eval do
        alias_method :__vci_require, :require
        alias_method :__vci_load, :load
        alias_method :__vci_open, :open
        alias_method :__vci_system, :system
        alias_method :__vci_spawn, :spawn
        alias_method :__vci_exec, :exec
        alias_method :__vci_backtick, :`

        def require(path)
          VciCollector.around_require(path) { __vci_require(path) }
        end

        def load(path, *rest)
          VciCollector.around_load(path) { __vci_load(path, *rest) }
        end

        def open(*args, **kw, &blk)
          p = args[0].is_a?(String) ? args[0] : nil
          VciCollector.taint("process:Kernel#open(|cmd)") if p&.start_with?("|") && !VciCollector.busy?
          __vci_open(*args, **kw, &blk)
        end

        def system(*args, **kw)
          return __vci_system(*VciCollector.engine_args(args), **kw) if VciCollector.engine_child?(args, kw)
          VciCollector.taint("process:system") unless VciCollector.busy?
          __vci_system(*args, **kw)
        end

        def spawn(*args, **kw)
          VciCollector.taint("process:spawn") unless VciCollector.busy?
          __vci_spawn(*args, **kw)
        end

        def exec(*args, **kw)
          VciCollector.taint("process:exec") unless VciCollector.busy?
          __vci_exec(*args, **kw)
        end

        def `(cmd)
          VciCollector.taint("process:backtick") unless VciCollector.busy?
          __vci_backtick(cmd)
        end

        # Kernel#test(?e, path) and friends check files in C.
        alias_method :__vci_test, :test

        def test(cmd, *paths)
          paths.each { |p| VciCollector.observe_stat(p) } unless VciCollector.busy?
          __vci_test(cmd, *paths)
        end

        private :require, :load, :open, :system, :spawn, :exec, :`, :test,
                :__vci_require, :__vci_load, :__vci_open, :__vci_system, :__vci_spawn, :__vci_exec,
                :__vci_backtick, :__vci_test
      end
      ::Kernel.singleton_class.class_eval do
        alias_method :__vci_s_require, :require
        alias_method :__vci_s_load, :load

        def require(path)
          VciCollector.around_require(path) { __vci_s_require(path) }
        end

        def load(path, *rest)
          VciCollector.around_load(path) { __vci_s_load(path, *rest) }
        end
      end
      # Kernel.system, Kernel.spawn, ... (module functions: separate copies).
      ::Kernel.singleton_class.class_eval do
        %i[system spawn exec ` open].each do |m|
          next unless ::Kernel.respond_to?(m, true)
          orig = :"__vci_s_#{m == :` ? "backtick" : m}"
          alias_method orig, m
          define_method(m) do |*args, **kw, &blk|
            return send(orig, *VciCollector.engine_args(args), **kw, &blk) if m == :system && VciCollector.engine_child?(args, kw)
            p = args[0].is_a?(String) ? args[0] : nil
            if m != :open || p&.start_with?("|")
              VciCollector.taint("process:Kernel.#{m}") unless VciCollector.busy?
            end
            send(orig, *args, **kw, &blk)
          end
        end
      end
    end

end

# ---------------------------------------------------------------------------
# A hooked method a test redefines in the class the hook is prepended to
# (every mode).
# ---------------------------------------------------------------------------
module VciCollector
  # A test that captures a hooked method as an object and then redefines the
  # method calls the object for what its redefinition does not fake:
  #
  #   original_env = ENV.method(:[])
  #   ENV.stub(:[], ->(key) { key == "X" ? "x" : original_env.call(key) })
  #
  # (vex-api's manual_image_deploy_service_test.rb; also a lasting
  # `define_singleton_method`; rspec-mocks puts its stubs in a module
  # prepended in front of the hook, which does not loop). Without the
  # collector the object is Ruby's own method. Under it, it is the collector's hook (a module prepended to
  # the class that defines the method, so what `ENV.method(:[])` finds),
  # whose `super` is whatever the class defines now: the redefinition, which
  # called the object, which called the hook again, until SystemStackError.
  #
  # So a redefinition of a hooked name in the hooked class itself (seen by
  # method_added / singleton_method_added) is wrapped: the wrapper runs the
  # redefinition, and when the hook is re-entered from inside it on the same
  # thread through a captured object (Method#call, Method#[], Method#===,
  # UnboundMethod#bind_call: the frame that called the hook), it calls the
  # method the class defined before the collector hooked it instead. The
  # hook still records that call (the captured object is the hook). A direct
  # call from inside the redefinition (`ENV[k]` in the stub, or in a block a
  # stubbed `File.open` yields) runs the redefinition again, as it does
  # without the collector. A captured object called some other way
  # (`&original`, `original.to_proc`, `curry`) is not told apart from a
  # direct call: after MAX_DEPTH nested runs of the redefinition on one
  # thread the original is called (the recursion ends, where it would
  # otherwise overflow the stack). Restoring the original (Minitest's
  # `alias_method` back, AliasGuard) is not wrapped. Anything unexpected
  # leaves the redefinition as the test made it.
  module Redefined
    # target => {name => the method the target itself defined before it was
    # hooked (UnboundMethod), or nil (inherited, or none)}
    WATCH = {}.compare_by_identity
    ACTIVE = :__vci_collector_redefined
    WRAPPING = :__vci_collector_wrapping
    CAPTURED = /\A(Method#(call|\[\]|===)|UnboundMethod#bind_call)\z/
    MAX_DEPTH = 16
    HERE = __FILE__

    # Prepended to the class whose method_added (instance methods of a
    # hooked class) or singleton_method_added (a hooked singleton class: its
    # object's) Ruby calls.
    module Watch
      private

      def method_added(name)
        VciCollector::Redefined.added(self, name)
        super
      end

      def singleton_method_added(name)
        VciCollector::Redefined.added(singleton_class, name)
        super
      end
    end

    class << self
      # Watch the methods `mod` (a hook prepended to `target`) defines.
      def watch(target, mod)
        names = WATCH[target] ||= {}
        (mod.instance_methods(false) + mod.private_instance_methods(false)).each do |m|
          names[m] = own(target, m) unless names.key?(m)
        end
        (target.singleton_class? ? target : target.singleton_class).prepend(Watch)
      rescue StandardError
        nil
      end

      # The method `t` itself defines for `name` (behind what is prepended
      # to it), or nil.
      def own(t, name)
        um = t.instance_method(name)
        pre = t.ancestors.take_while { |a| !a.equal?(t) }
        um = um.super_method while um && !um.owner.equal?(t) && pre.any? { |a| a.equal?(um.owner) }
        um if um&.owner.equal?(t)
      rescue NameError
        nil
      end

      def added(t, name)
        names = WATCH[t]
        return unless names&.key?(name) && !Thread.current[WRAPPING]
        user = own(t, name)
        return if user.nil? || user == names[name]
        wrap(t, name, user, names[name])
      rescue StandardError
        nil
      end

      def wrap(t, name, user, orig)
        key = [t, name].freeze
        vis = if t.private_instance_methods(false).include?(name) then :private
              elsif t.protected_instance_methods(false).include?(name) then :protected
              else :public
              end
        Thread.current[WRAPPING] = true
        t.send(:define_method, name) do |*args, **kw, &blk|
          VciCollector::Redefined.run(key, orig, user, self, args, kw, blk)
        end
        t.send(vis, name)
      ensure
        Thread.current[WRAPPING] = false
      end

      def run(key, orig, user, recv, args, kw, blk)
        active = (Thread.current[ACTIVE] ||= {}.compare_by_identity)
        depth = active[key] || 0
        if depth.positive? && (depth >= MAX_DEPTH || captured?)
          target = orig || inherited(*key)
          return target.bind_call(recv, *args, **kw, &blk) if target
        end
        active[key] = depth + 1
        begin
          user.bind_call(recv, *args, **kw, &blk)
        ensure
          depth.zero? ? active.delete(key) : active[key] = depth
        end
      end

      # Whether the hook that led here was called through a captured method
      # object: the first frame outside the collector.
      def captured?
        caller_locations(2).each do |l|
          next if l.path == HERE
          return CAPTURED.match?(l.label)
        end
        false
      end

      def inherited(t, name)
        t.superclass&.instance_method(name)
      rescue NameError
        nil
      end
    end
  end
end

# ---------------------------------------------------------------------------
# File system, process and ENV hooks (collect mode only).
# ---------------------------------------------------------------------------
if VciCollector.collect?
  module VciCollector
    # Process methods answering who the process runs as.
    IDENTITY_METHODS = %i[uid gid euid egid groups].freeze

    STAT_METHODS = %i[
      exist? file? directory? readable? readable_real? world_readable? writable? writable_real?
      world_writable? executable? executable_real? size? size zero? empty? symlink? pipe? socket?
      blockdev? chardev? setuid? setgid? sticky? owned? grpowned? ftype atime mtime ctime birthtime
      stat lstat readlink
    ].freeze

    # Metadata git does not keep: a checkout's file times are when it was
    # checked out, and its permission bits are 644 or 755 (umask aside) and
    # its owner the runner's user. Reading them refuses the file (see
    # VciCollector.metadata_read).
    TIME_METHODS = %i[atime mtime ctime birthtime].freeze
    PERM_METHODS = %i[
      world_readable? world_writable? readable? readable_real? writable? writable_real? setuid? setgid? sticky?
      owned? grpowned?
    ].freeze

    module FileStatHooks
      STAT_METHODS.each do |m|
        define_method(m) do |*args, **kw, &blk|
          return super(*args, **kw, &blk) if VciCollector.busy?
          begin
            r = super(*args, **kw, &blk)
          rescue SystemCallError
            VciCollector.observe_stat(args[0])
            raise
          end
          VciCollector.observe_stat(args[0])
          if TIME_METHODS.include?(m)
            VciCollector.metadata_read(args[0], "File.#{m}", :time)
          elsif PERM_METHODS.include?(m)
            VciCollector.metadata_read(args[0], "File.#{m}", :perm)
          elsif (m == :stat || m == :lstat) && r.is_a?(File::Stat)
            VciCollector.tag_stat(r, args[0])
          end
          r
        end
      end

      def identical?(a, b)
        unless VciCollector.busy?
          VciCollector.observe_stat(a)
          VciCollector.observe_stat(b)
        end
        super
      end

      def realpath(path, *rest)
        return super if VciCollector.busy?
        begin
          r = super
        rescue SystemCallError
          VciCollector.realpath_walk(path, rest[0])
          raise
        end
        VciCollector.realpath_walk(path, rest[0])
        r
      end

      def realdirpath(path, *rest)
        return super if VciCollector.busy?
        r = super
        VciCollector.realpath_walk(path, rest[0])
        r
      end

      def expand_path(path, *rest)
        unless VciCollector.busy?
          p = VciCollector.pathify(path)
          VciCollector.env_read("HOME") if p&.start_with?("~")
        end
        super
      end
    end

    # Each of these fails unless its path exists (mkfifo: unless it does
    # not): the path's existence is observed first (see before_change).
    module FileWriteHooks
      %i[delete unlink].each do |m|
        define_method(m) do |*paths|
          return super(*paths) if VciCollector.busy?
          paths.each { |p| VciCollector.before_change(p) }
          r = super(*paths)
          paths.each { |p| VciCollector.wrote(p, gone: true, follow: false) }
          r
        end
      end

      %i[chmod lchmod].each do |m|
        define_method(m) do |mode, *paths|
          return super(mode, *paths) if VciCollector.busy?
          paths.each { |p| VciCollector.before_change(p) }
          r = super(mode, *paths)
          paths.each { |p| VciCollector.wrote(p, follow: m == :chmod) }
          r
        end
      end

      %i[chown lchown utime lutime].each do |m|
        define_method(m) do |a, b, *paths|
          return super(a, b, *paths) if VciCollector.busy?
          paths.each { |p| VciCollector.before_change(p) }
          r = super(a, b, *paths)
          paths.each { |p| VciCollector.wrote(p, follow: !m.start_with?("l")) }
          r
        end
      end

      %i[truncate mkfifo].each do |m|
        define_method(m) do |path, *rest|
          return super(path, *rest) if VciCollector.busy?
          VciCollector.before_change(path)
          r = super(path, *rest)
          VciCollector.wrote(path, follow: m == :truncate)
          r
        end
      end

      # The destination holds the source's content afterwards: the
      # process's own only if the source was (File.atomic_write).
      def rename(from, to)
        return super if VciCollector.busy?
        f = VciCollector.expand(VciCollector.pathify(from))
        produced = f && VciCollector.self_produced?(VciCollector.resolve(f))
        VciCollector.before_change(from)
        r = super
        VciCollector.wrote(from, gone: true, follow: false)
        VciCollector.wrote(to, produced: produced, gone: !produced, follow: false)
        t = VciCollector.expand(VciCollector.pathify(to))
        VciCollector.parent_observed(VciCollector.resolve(t)) if t
        r
      end

      def symlink(target, link)
        unless VciCollector.busy?
          # Reading through the link reads the target.
          t = VciCollector.pathify(target)
          l = VciCollector.expand(VciCollector.pathify(link))
          VciCollector.rec(:read, VciCollector.quiet { VciCollector.literal_path(t, Real.dirname(l)) }) if t && l
          VciCollector.wrote(link, follow: false)
        end
        super
      end

      def link(src, dst)
        unless VciCollector.busy?
          VciCollector.rec(:read, src)
          VciCollector.wrote(dst, follow: false)
        end
        super
      end
    end

    # IO.read/binread/readlines/foreach/write/binwrite("|cmd") run a command
    # when called on IO itself (not on File or another subclass, which open
    # a file named "|cmd" like every other entry point).
    module IOHooks
      def self.command?(klass, p)
        p&.start_with?("|") && klass.equal?(::IO)
      end

      %i[read binread readlines].each do |m|
        define_method(m) do |*args, **kw, &blk|
          return super(*args, **kw, &blk) if VciCollector.busy?
          p = VciCollector.pathify(args[0])
          if IOHooks.command?(self, p)
            VciCollector.taint("process:IO.#{m}(|cmd)")
            return super(*args, **kw, &blk)
          end
          begin
            r = super(*args, **kw, &blk)
          rescue Errno::ENOENT, Errno::ENOTDIR
            VciCollector.rec(:probe, p) if p
            raise
          end
          VciCollector.read_path(p) if p
          r
        end
      end

      def foreach(*args, **kw, &blk)
        unless VciCollector.busy?
          p = VciCollector.pathify(args[0])
          if IOHooks.command?(self, p)
            VciCollector.taint("process:IO.foreach(|cmd)")
          elsif p
            VciCollector.exists_quietly?(p) ? VciCollector.read_path(p) : VciCollector.rec(:probe, p)
          end
        end
        super
      end

      %i[write binwrite].each do |m|
        define_method(m) do |*args, **kw, &blk|
          return super(*args, **kw, &blk) if VciCollector.busy?
          p = VciCollector.pathify(args[0])
          if IOHooks.command?(self, p)
            VciCollector.taint("process:IO.#{m}(|cmd)")
            return super(*args, **kw, &blk)
          end
          existed = p && VciCollector.exists_quietly?(p)
          r = super(*args, **kw, &blk)
          if p
            # IO.write truncates unless given an offset or a mode.
            if kw[:mode].nil? && args[2].nil?
              VciCollector.opened(p, "w", nil, existed, true)
            else
              VciCollector.opened(p, kw[:mode] || "r+", kw[:flags], existed, true)
            end
          end
          r
        end
      end

      def copy_stream(src, dst, *rest)
        return super if VciCollector.busy?
        s = VciCollector.pathify(src)
        VciCollector.read_path(s) if s
        d = VciCollector.pathify(dst)
        existed = d && VciCollector.exists_quietly?(d)
        r = super
        VciCollector.opened(d, "w", nil, existed, true) if d
        r
      end

      def sysopen(path, *rest)
        return super if VciCollector.busy?
        p = VciCollector.pathify(path)
        _, writes, = VciCollector.mode_info(rest[0], nil)
        existed = p && writes ? VciCollector.exists_quietly?(p) : true
        begin
          r = super
        rescue Errno::ENOENT, Errno::ENOTDIR
          VciCollector.opened(p, rest[0], nil, existed, false) if p
          raise
        end
        VciCollector.opened(p, rest[0], nil, existed, true) if p
        r
      end

      def popen(*args, **kw, &blk)
        VciCollector.taint("process:IO.popen") unless VciCollector.busy?
        super
      end

      def for_fd(*args, **kw, &blk)
        io = super
        VciCollector.fd_reopened(io) unless VciCollector.busy?
        io
      end
    end

    module FileInitHook
      def initialize(*args, **kw, &blk)
        return super if VciCollector.busy?
        target = args[0]
        if target.is_a?(Integer)
          super
          VciCollector.fd_reopened(self)
          return
        end
        p = VciCollector.pathify(target)
        return super unless p
        mode = args[1] || kw[:mode]
        flags = kw[:flags]
        _, writes, = VciCollector.mode_info(mode, flags)
        existed = writes ? VciCollector.exists_quietly?(p) : true
        begin
          super
        rescue Errno::ENOENT, Errno::ENOTDIR
          VciCollector.opened(p, mode, flags, existed, false)
          raise
        end
        VciCollector.opened(p, mode, flags, existed, true)
      end

      %i[truncate chmod chown].each do |m|
        define_method(m) do |*args|
          VciCollector.wrote(path) if !VciCollector.busy? && path
          super(*args)
        end
      end
    end

    module IOInitHook
      def initialize(*args, **kw, &blk)
        super
        VciCollector.fd_reopened(self) if instance_of?(IO) && args[0].is_a?(Integer) && !VciCollector.busy?
      end

      # IO#reopen(path) opens the file in C.
      def reopen(*args, **kw)
        p = args[0].is_a?(IO) ? nil : VciCollector.pathify(args[0])
        return super unless p && !VciCollector.busy?
        _, writes, = VciCollector.mode_info(args[1] || kw[:mode], kw[:flags])
        existed = writes ? VciCollector.exists_quietly?(p) : true
        begin
          r = super
        rescue Errno::ENOENT, Errno::ENOTDIR
          VciCollector.opened(p, args[1] || kw[:mode], kw[:flags], existed, false)
          raise
        end
        VciCollector.opened(p, args[1] || kw[:mode], kw[:flags], existed, true)
        r
      end
    end

    # Compiling a file without loading it reads its source in C.
    module ISeqHooks
      %i[compile_file compile_file_prism].each do |m|
        define_method(m) do |path, *rest, **kw|
          VciCollector.read_path(VciCollector.pathify(path)) unless VciCollector.busy?
          super(path, *rest, **kw)
        end
      end
    end

    # ARGF (Kernel#gets/readline/readlines and ARGF.read) reads the files
    # named in ARGV, in C.
    module ArgfHooks
      %i[read readlines readline gets each_line each_char each_byte getc getbyte readchar readbyte
         file filename lineno skip binmode].each do |m|
        define_method(m) do |*args, **kw, &blk|
          VciCollector.taint("ruby:ARGF.#{m} (reads the files named in ARGV)") unless VciCollector.busy? || ARGV.empty?
          super(*args, **kw, &blk)
        end
      end
    end

    module FileStatInit
      def initialize(path)
        VciCollector.observe_stat(path) unless VciCollector.busy?
        super
        VciCollector.tag_stat(self, path) unless VciCollector.busy?
      end

      # A File::Stat of a repository path (File.stat, File#stat, ...): its
      # times, mode and owner are metadata git does not keep.
      TIME_METHODS.each do |m|
        define_method(m) do
          VciCollector.stat_metadata_read(self, "File::Stat##{m}", :time) unless VciCollector.busy?
          super()
        end
      end

      def <=>(other)
        VciCollector.stat_metadata_read(self, "File::Stat#<=> (compares mtimes)", :time) unless VciCollector.busy?
        super
      end

      (PERM_METHODS + %i[mode uid gid]).each do |m|
        define_method(m) do
          VciCollector.stat_metadata_read(self, "File::Stat##{m}", :perm) unless VciCollector.busy?
          super()
        end
      end
    end

    # File#mtime, File#stat, ... on an open file.
    module FileMetaHooks
      TIME_METHODS.each do |m|
        define_method(m) do
          VciCollector.metadata_read(path, "File##{m}", :time) unless VciCollector.busy?
          super()
        end
      end

      def lstat
        r = super
        VciCollector.tag_stat(r, path) unless VciCollector.busy?
        r
      end
    end

    module IOStatHook
      def stat
        r = super
        VciCollector.tag_stat(r, path) if !VciCollector.busy? && is_a?(File)
        r
      end
    end

    module DirHooks
      %i[children entries each_child foreach].each do |m|
        define_method(m) do |*args, **kw, &blk|
          return super(*args, **kw, &blk) if VciCollector.busy?
          p = VciCollector.pathify(args[0])
          begin
            r = super(*args, **kw, &blk)
          rescue Errno::ENOENT, Errno::ENOTDIR
            VciCollector.rec(:probe, p) if p
            raise
          end
          VciCollector.rec(:readdir, p) if p
          r
        end
      end

      # Dir.open builds the Dir in C without Dir#initialize (Ruby 3.4's
      # <internal:dir>): its listing, or the absent path, is recorded here.
      # The block is run here so an error raised inside it is not taken for
      # a failed open.
      def open(path, *rest, **kw, &blk)
        return super if VciCollector.busy?
        p = VciCollector.pathify(path)
        begin
          d = super(path, *rest, **kw, &nil)
        rescue Errno::ENOENT, Errno::ENOTDIR
          VciCollector.rec(:probe, p) if p
          raise
        end
        VciCollector.rec(:readdir, p) if p
        return d unless blk
        begin
          yield d
        ensure
          d.close
        end
      end

      def for_fd(*args, **kw, &blk)
        VciCollector.taint("ruby:Dir.for_fd (a directory opened where vci cannot see it)") unless VciCollector.busy?
        super
      end

      def glob(pattern, *rest, **kw, &blk)
        VciCollector.glob_record(pattern, kw[:base], rest[0]) unless VciCollector.busy?
        super
      end

      def [](*patterns, **kw)
        VciCollector.glob_record(patterns, kw[:base], 0) unless VciCollector.busy?
        super
      end

      def exist?(path)
        r = super
        VciCollector.observe_stat(path) unless VciCollector.busy?
        r
      end

      def empty?(path)
        r = super
        unless VciCollector.busy?
          p = VciCollector.pathify(path)
          if p && VciCollector.quiet { Real.directory?(p) }
            VciCollector.rec(:readdir, p)
          else
            VciCollector.observe_stat(path)
          end
        end
        r
      end

      # Fails if the path exists (EEXIST, observed by its stat) or its
      # parent does not.
      def mkdir(path, *rest)
        return super if VciCollector.busy?
        begin
          r = super
        rescue SystemCallError
          VciCollector.observe_stat(path)
          raise
        end
        VciCollector.wrote(path, produced: true)
        a = VciCollector.expand(VciCollector.pathify(path))
        VciCollector.parent_observed(VciCollector.resolve(a)) if a
        r
      end

      %i[rmdir delete unlink].each do |m|
        define_method(m) do |path|
          return super(path) if VciCollector.busy?
          VciCollector.before_change(path)
          r = super(path)
          VciCollector.wrote(path, gone: true, follow: false)
          r
        end
      end

      def chdir(*args, **kw, &blk)
        VciCollector.env_read("HOME") if args.empty? && !VciCollector.busy?
        super
      end

      def home(*args)
        VciCollector.env_read("HOME") if args.empty? && !VciCollector.busy?
        super
      end
    end

    module DirInitHook
      def initialize(path, *rest, **kw)
        return super if VciCollector.busy?
        p = VciCollector.pathify(path)
        begin
          super
        rescue Errno::ENOENT, Errno::ENOTDIR
          VciCollector.rec(:probe, p) if p
          raise
        end
        VciCollector.rec(:readdir, p) if p
      end
    end

    module ProcessHooks
      def spawn(*args, **kw)
        VciCollector.taint("process:Process.spawn") unless VciCollector.busy?
        super
      end

      def exec(*args, **kw)
        VciCollector.taint("process:Process.exec") unless VciCollector.busy?
        super
      end

      # Every fork (Kernel#fork, Process.fork, IO.popen("-")) goes through
      # Process._fork (Ruby 3.1+), including Rails' parallel test workers.
      def _fork
        VciCollector.taint("process:fork") unless VciCollector::Batch.own_fork?
        super
      end

      def daemon(*args)
        VciCollector.taint("process:daemon")
        super
      end

      IDENTITY_METHODS.each do |m|
        define_method(m) do |*args, **kw, &blk|
          VciCollector.identity_read("Process.#{m}") unless VciCollector.busy?
          super(*args, **kw, &blk)
        end
      end
    end

    # Who the process runs as: Process::UID/GID and Process::Sys, and Etc
    # (install_etc). See VciCollector.identity_read.
    def self.identity_hook(prefix, methods)
      Module.new do
        methods.each do |m|
          define_method(m) do |*args, **kw, &blk|
            VciCollector.identity_read("#{prefix}.#{m}") unless VciCollector.busy?
            super(*args, **kw, &blk)
          end
        end
      end
    end

    # ENV: reads by key are recorded; anything that walks the environment is
    # an enumeration (see Env.allowed_enumeration?).
    module EnvHooks
      %i[[] fetch key? has_key? include? member? assoc].each do |m|
        define_method(m) do |key, *rest, &blk|
          VciCollector.env_read(key) unless VciCollector.busy?
          super(key, *rest, &blk)
        end
      end

      %i[values_at slice].each do |m|
        define_method(m) do |*keys|
          keys.each { |k| VciCollector.env_read(k) } unless VciCollector.busy?
          super(*keys)
        end
      end

      %i[
        each each_pair each_key each_value keys values to_h to_hash to_a inspect size length empty?
        select filter reject filter_map key rassoc value? has_value? invert except any? find detect
        count sort sort_by min max sum find_all group_by partition each_with_object inject reduce
        map flat_map collect delete_if keep_if select! filter! reject! clear replace update merge!
        dup clone to_s
      ].each do |m|
        next unless ENV.respond_to?(m, true)
        define_method(m) do |*args, **kw, &blk|
          VciCollector.env_enumerated(m) unless VciCollector.busy? || m == :to_s
          super(*args, **kw, &blk)
        end
      end
    end

    # Frames whose metadata reads are not inputs: ActiveSupport's file
    # watchers compare mtimes only to decide whether to reload code, routes
    # and locales (which vci's runs never do: one process per file).
    METADATA_ALLOWED = %r{/active_support/(evented_)?file_update_checker\.rb\z}
    # Ruby's standard library reads permission bits for its own purposes
    # (FileUtils copies a file's mode, Dir.tmpdir checks writability).
    # So does ActiveSupport's File.atomic_write (it gives the new file the
    # old one's owner and mode).
    STDLIB_PERM = %r{/(fileutils|tmpdir|tempfile|pathname)(-[\d.]+)?/lib/|/active_support/core_ext/file/atomic\.rb\z}

    class << self
      def read_path(p)
        abs = expand(p)
        add(:read, abs) if abs
      end

      # Remember which repository file a File::Stat describes, unless the
      # process produced that file (its metadata is then the process's own,
      # even if the file is deleted before the Stat is read).
      def tag_stat(st, path)
        return unless collect?
        abs = expand(pathify(path))
        abs = resolve(abs) if abs
        st.instance_variable_set(:@__vci_path, abs) if abs && !@produced[abs]
      rescue StandardError
        nil
      end

      def stat_metadata_read(st, what, kind)
        abs = st.instance_variable_get(:@__vci_path)
        metadata_read(abs, what, kind) if abs
      end

      # The user or group the process runs as (Process.uid, Etc.getpwuid,
      # Etc.getlogin, ...): a laptop's user is not CI's (a root container
      # job, a runner's uid 1001), and nothing records it, so a test reading
      # it is refused. Not refused: RubyGems and Bundler, and Ruby's standard
      # library asking for itself (FileUtils.remove_entry_secure's owner
      # check, pp printing a File::Stat), like permission bits.
      def identity_read(what)
        return unless collect? && !busy?
        where = quiet { frame }
        return if tooling?(where) || where.start_with?("#{RUBYLIBDIR}/") || STDLIB_PERM.match?(where)
        taint("ruby:process-identity:#{what} at #{where} (the user and groups the tests run as differ between machines; vci does not record them)")
      end

      def metadata_read(path, what, kind)
        return unless collect? && !busy?
        abs = expand(pathify(path))
        abs = resolve(abs) if abs
        return unless abs && inside?(abs, repo) && !@produced[abs]
        where = quiet { frame }
        return if METADATA_ALLOWED.match?(where) || tooling?(where)
        return if kind == :perm && (where.start_with?("#{RUBYLIBDIR}/") || STDLIB_PERM.match?(where))
        rel = abs.delete_prefix("#{repo}/")
        taint("ruby:file-metadata:#{what} of #{rel} at #{where} (git does not keep file times, permission bits other than the executable bit, or owners: a checkout's differ)")
      end
    end
  end

  module VciCollector
    # The modules the collector prepends to Ruby's file, process and ENV
    # entry points (AliasGuard).
    HOOK_MODULES = {}.compare_by_identity

    def self.hook(target, mod)
      HOOK_MODULES[mod] = true
      Redefined.watch(target, mod)
      target.prepend(mod)
    end

    # A test's stub that saves a method by alias and restores it the same way
    # (Minitest's `stub`, an `alias_method` + `define_method` helper such as
    # `ENV.stub(:[], ...)`) would save the collector's hook, which is what
    # the name resolves to, instead of the method; restoring it put a copy of
    # the hook in the class, whose `super` called itself: every later call
    # of the method recursed until the stack overflowed (vex-api's
    # `Object#stub` of `ENV[]`: the process wrote no output). Aliasing a hooked method aliases the method the hook
    # wraps, so the stub replaces and restores that one, and the hook keeps
    # recording around it.
    # Only for a hook prepended to this very class: an alias in a subclass
    # (`File.read`, hooked on IO's singleton class) is a copy whose `super`
    # goes on to the superclass, as it should.
    module AliasGuard
      def alias_method(new_name, old_name)
        um = (instance_method(old_name) rescue nil)
        return super unless um && VciCollector::HOOK_MODULES.key?(um.owner)
        mine = ancestors.take_while { |a| !a.equal?(self) }
        return super unless mine.any? { |a| a.equal?(um.owner) }
        um = um.super_method while um && VciCollector::HOOK_MODULES.key?(um.owner)
        return super unless um
        define_method(new_name, um)
        new_name.to_sym
      end
    end
  end
  Module.prepend(VciCollector::AliasGuard)

  VciCollector.hook(File.singleton_class, VciCollector::FileStatHooks)
  VciCollector.hook(File.singleton_class, VciCollector::FileWriteHooks)
  VciCollector.hook(FileTest.singleton_class, VciCollector::FileStatHooks)
  VciCollector.hook(IO.singleton_class, VciCollector::IOHooks)
  VciCollector.hook(File, VciCollector::FileInitHook)
  VciCollector.hook(File, VciCollector::FileMetaHooks)
  VciCollector.hook(IO, VciCollector::IOInitHook)
  VciCollector.hook(IO, VciCollector::IOStatHook)
  VciCollector.hook(File::Stat, VciCollector::FileStatInit)
  VciCollector.hook(Dir.singleton_class, VciCollector::DirHooks)
  VciCollector.hook(Dir, VciCollector::DirInitHook)
  VciCollector.hook(Process.singleton_class, VciCollector::ProcessHooks)
  VciCollector.hook(Process::UID.singleton_class, VciCollector.identity_hook("Process::UID", %i[rid eid]))
  VciCollector.hook(Process::GID.singleton_class, VciCollector.identity_hook("Process::GID", %i[rid eid]))
  VciCollector.hook(Process::Sys.singleton_class, VciCollector.identity_hook("Process::Sys", %i[getuid geteuid getgid getegid]))
  VciCollector.hook(ENV.singleton_class, VciCollector::EnvHooks)
  VciCollector.hook(RubyVM::InstructionSequence.singleton_class, VciCollector::ISeqHooks)
  VciCollector.hook(ARGF.singleton_class, VciCollector::ArgfHooks)

  # Every Ruby source compiled from a file (require, require_relative, load,
  # autoload, Zeitwerk) is a module input.
  VciCollector::TP_COMPILED = TracePoint.new(:script_compiled) do |tp|
    next if VciCollector.busy? || tp.eval_script
    iseq = tp.instruction_sequence
    path = iseq.absolute_path || iseq.path
    VciCollector.records[[:module, path]] = true if path.is_a?(String) && path.start_with?("/")
    VciCollector.after_require
  end
  VciCollector::TP_COMPILED.enable

  # A failed require/require_relative/load/autoload: every candidate it
  # tried is a probe (creating one would change what loads).
  VciCollector::TP_RAISE = TracePoint.new(:raise) do |tp|
    e = tp.raised_exception
    next unless e.is_a?(LoadError) && !VciCollector.busy?
    VciCollector.quiet { VciCollector.missing_feature(e.path) }
  end
  VciCollector::TP_RAISE.enable
end

# require/load are hooked in every mode: they install the Rails and Minitest
# integration as those libraries load (recording only in collect mode).
VciCollector.install_kernel_hooks

# ---------------------------------------------------------------------------
# Rails / Minitest integration (every mode).
# ---------------------------------------------------------------------------
module VciCollector
  # Libraries whose entry points are hooked when they appear (after
  # every require/load, every compiled file, and whenever one of the
  # constants they define is set, which also catches a library loaded
  # where no require hook sees it, such as from C).
  HOOKS = {
    minitest: -> { defined?(::Minitest) && ::Minitest.respond_to?(:register_plugin) && install_minitest },
    rspec: lambda {
      defined?(::RSpec::Core::Runner) && defined?(::RSpec::Core::Reporter) &&
        defined?(::RSpec::Core::ConfigurationOptions) && defined?(::RSpec::Core::Configuration) &&
        defined?(::RSpec::Core::Ordering::ConfigurationManager) && defined?(::RSpec::Core::World) &&
        defined?(::RSpec::Core::Example) && RSpecSupport.install
    },
    simplecov: -> { defined?(::SimpleCov) && ::SimpleCov.respond_to?(:coverage_path) && RSpecSupport.install_simplecov },
    code_stats: -> { defined?(::Rails::CodeStatistics) && ::Rails::CodeStatistics.respond_to?(:directories) && install_code_stats },
    rails_config: -> { defined?(::Rails::Application::Configuration) && install_rails_config },
    parallelize: -> { Batch.install_parallelize },
    socket: -> { defined?(::BasicSocket) && install_socket },
    pty: -> { defined?(::PTY) && install_pty },
    fiddle: -> { defined?(::Fiddle::Function) && defined?(::Fiddle::Handle) && install_fiddle },
    ffi: -> { defined?(::FFI::Library) && defined?(::FFI::DynamicLibrary) && install_ffi },
    ffi_variadic: -> { defined?(::FFI::VariadicInvoker) && install_ffi_variadic },
    vips: lambda {
      defined?(::Vips::Operation) && ::Vips::Operation.respond_to?(:call) && defined?(::Vips::Image) && install_vips
    },
    zlib: -> { defined?(::Zlib::GzipReader) && install_zlib },
    etc: -> { defined?(::Etc) && ::Etc.respond_to?(:getpwuid) && ::Etc.respond_to?(:getlogin) && install_etc },
    openssl: lambda {
      defined?(::OpenSSL::X509::Store) && defined?(::OpenSSL::X509::StoreContext) &&
        defined?(::OpenSSL::SSL::SSLContext) && defined?(::OpenSSL::SSL::SSLSocket) && defined?(::OpenSSL::Config) &&
        ::OpenSSL::X509::Store.method_defined?(:add_file) && install_openssl
    },
    openssl_provider: -> { defined?(::OpenSSL::Provider) && ::OpenSSL::Provider.respond_to?(:load) && install_openssl_modules(::OpenSSL::Provider) },
    openssl_engine: -> { defined?(::OpenSSL::Engine) && ::OpenSSL::Engine.respond_to?(:by_id) && install_openssl_modules(::OpenSSL::Engine) },
    prism: -> { defined?(::Prism) && ::Prism.respond_to?(:parse_file) && install_prism },
    sqlite3: -> { defined?(::SQLite3::Database) && install_sqlite3 },
    nokogiri: lambda {
      defined?(::Nokogiri::XML::Document) && defined?(::Nokogiri::XML::Node) && defined?(::Nokogiri::XML::Reader) &&
        defined?(::Nokogiri::XML::Schema) && defined?(::Nokogiri::XML::RelaxNG) &&
        defined?(::Nokogiri::XML::SAX::ParserContext) && defined?(::Nokogiri::XSLT::Stylesheet) &&
        defined?(::Nokogiri::XML::ParseOptions) && install_nokogiri
    }
  }.freeze

  # Present once the library is loaded, whether or not it was hooked.
  LOADED = {
    socket: -> { defined?(::BasicSocket) },
    pty: -> { defined?(::PTY) },
    fiddle: -> { defined?(::Fiddle) },
    ffi: -> { defined?(::FFI::Library) },
    ffi_variadic: -> { defined?(::FFI::VariadicInvoker) },
    vips: -> { defined?(::Vips::Operation) && ::Vips::Operation.respond_to?(:call) },
    zlib: -> { defined?(::Zlib::GzipReader) },
    etc: -> { defined?(::Etc) && ::Etc.respond_to?(:getpwuid) },
    openssl: -> { defined?(::OpenSSL::X509::Store) && ::OpenSSL::X509::Store.method_defined?(:add_file) },
    prism: -> { defined?(::Prism) && ::Prism.respond_to?(:parse_file) },
    sqlite3: -> { defined?(::SQLite3::Database) },
    nokogiri: -> { defined?(::Nokogiri::XML::Document) }
  }.freeze

  # Database clients: [constant path, name]. Every way to open a
  # connection is wrapped as it appears (aliases may be defined later).
  DB_CLIENTS = [[%w[PG Connection], "postgresql"], [%w[Mysql2 Client], "mysql2"], [%w[Trilogy], "trilogy"]].freeze
  DB_OPENERS = %i[new connect open connect_start async_connect sync_connect setdb setdblogin].freeze
  DB_OPENING = :__vci_db_opening

  # Constant names whose definition triggers after_require.
  WATCHED_CONSTANTS = %i[
    Minitest Configuration ActiveSupport BasicSocket Socket PTY Fiddle Function Handle FFI Library DynamicLibrary
    Zlib GzipReader SQLite3 Database PG Connection Mysql2 Client Trilogy Nokogiri XML Document Node Reader Schema
    RelaxNG SAX ParserContext XSLT Stylesheet ParseOptions
    RSpec Runner Reporter ConfigurationOptions ConfigurationManager World SimpleCov CodeStatistics Prism Example
    VariadicInvoker Vips Operation Image Etc OpenSSL X509 Store StoreContext SSL SSLContext SSLSocket Config
    Provider Engine
  ].each_with_object({}) { |n, h| h[n] = true }.freeze

  class << self
    # Called after every require/load: hook libraries as they appear.
    def after_require
      return if @in_after_require
      @in_after_require = true
      quiet do
        HOOKS.each { |name, cond| hook_once(name, &cond) }
        install_db_clients
      end
    ensure
      @in_after_require = false
    end

    def hook_once(name, &cond)
      return if @hooks_done[name]
      @hooks_done[name] = true if instance_exec(&cond)
    rescue StandardError => e
      @hooks_done[name] = true
      taint("vci:hook-failed:#{name}:#{e.class}: #{e.message}")
    end

    def const_path(names)
      names.inject(::Object) do |m, n|
        return nil unless m.is_a?(Module) && m.const_defined?(n, false)
        m.const_get(n, false)
      end
    end

    def install_db_clients
      return unless collect?
      @db_wrapped ||= {}
      DB_CLIENTS.each do |path, name|
        klass = const_path(path)
        next unless klass.is_a?(Class)
        DB_OPENERS.each do |m|
          next if @db_wrapped[[klass, m]] || !klass.respond_to?(m)
          @db_wrapped[[klass, m]] = true
          klass.singleton_class.prepend(Module.new do
            define_method(m) do |*args, **kw, &blk|
              # Only the outermost opener is checked: PG::Connection.new
              # calls connect_start itself, with the options it resolved.
              key = VciCollector::DB_OPENING
              return super(*args, **kw, &blk) if VciCollector.busy? || Thread.current[key]
              VciCollector.db_client_opened(name, args, kw)
              # A block (PG::Connection.new { |conn| ... }) is the caller's
              # code again: what it opens is checked.
              inner = blk && proc do |*a|
                Thread.current[key] = false
                blk.call(*a)
              ensure
                Thread.current[key] = true
              end
              begin
                Thread.current[key] = true
                super(*args, **kw, &inner)
              ensure
                Thread.current[key] = false
              end
            end
          end)
        end
      end
    rescue StandardError => e
      taint("vci:hook-failed:db-client:#{e.class}: #{e.message}")
    end

    # At exit, before anything else is hooked: a library that is loaded but
    # whose hooks were never installed (or a database client with a way to
    # connect that was never wrapped) may have been used unseen.
    def unhooked
      out = []
      LOADED.each do |name, cond|
        out << "vci:not-hooked:#{name} (loaded where vci could not hook it)" if !@hooks_done[name] && cond.call
      end
      out.concat(prism_unhooked) if collect?
      if collect?
        DB_CLIENTS.each do |path, name|
          klass = const_path(path)
          next unless klass.is_a?(Class)
          DB_OPENERS.each do |m|
            next if (@db_wrapped || {})[[klass, m]] || !klass.respond_to?(m)
            out << "vci:not-hooked:#{name}.#{m} (a way to connect vci did not wrap)"
          end
        end
      end
      out
    rescue StandardError => e
      ["vci:not-hooked:#{e.class}: #{e.message}"]
    end

    def install_minitest
      ::Minitest.register_plugin(MinitestPlugin)
      true
    end

    def install_rails_config
      ::Rails::Application::Configuration.prepend(RailsConfigHooks)
      true
    end

    # Rails::CodeStatistics' directory list includes what rspec-rails found
    # with a glob vci does not record (GLOB_NOT_INPUT): reading it anywhere
    # but in Rails::CodeStatistics itself refuses the file.
    def install_code_stats
      return true unless collect?
      ::Rails::CodeStatistics.singleton_class.prepend(Module.new do
        %i[directories test_types].each do |m|
          define_method(m) do |*args, **kw, &blk|
            unless VciCollector.busy?
              where = VciCollector.quiet { VciCollector.frame }
              unless where.end_with?("/lib/rails/code_statistics.rb")
                VciCollector.taint("rails:code-statistics:#{m} at #{where} (its directories come from a listing of spec/ vci does not record)")
              end
            end
            super(*args, **kw, &blk)
          end
        end
      end)
      true
    end

    def install_socket
      return true unless collect?
      [::TCPSocket, ::TCPServer, ::UDPSocket, ::UNIXSocket, ::UNIXServer, ::Socket].each do |k|
        k.prepend(SocketInit)
      end
      ::Socket.singleton_class.prepend(SocketClassHooks)
      ::Addrinfo.singleton_class.prepend(AddrinfoHooks) if defined?(::Addrinfo)
      true
    rescue NameError
      false
    end

    def install_pty
      return true unless collect?
      hook = Module.new do
        %i[spawn getpty].each do |m|
          define_method(m) do |*args, **kw, &blk|
            VciCollector.taint("process:PTY.spawn")
            super(*args, **kw, &blk)
          end
        end
      end
      ::PTY.singleton_class.prepend(hook)
      ::PTY.prepend(hook)
      true
    end

    # Calling C through Fiddle (any Fiddle::Function, which is how a
    # library's or libc's functions are called) or opening a library with it
    # (Fiddle.dlopen, also of nil: the process's own symbols, libc's fopen).
    def install_fiddle
      return true unless collect?
      ::Fiddle::Function.prepend(Module.new do
        def initialize(*args, **kw, &blk)
          VciCollector.taint("native:Fiddle::Function (C code called through Fiddle)")
          super
        end
      end)
      ::Fiddle::Handle.prepend(Module.new do
        def initialize(*args, **kw, &blk)
          VciCollector.taint("native:Fiddle::Handle(#{args[0].inspect}) (Fiddle.dlopen)")
          super
        end
      end)
      true
    end

    # FFI. Opening a library (ffi_lib, DynamicLibrary.open) is not a read of
    # test inputs: the library is recorded (Native.loaded) as an external
    # "native:<file name>" whose version is the sha256 of the file it
    # resolved to, in every mode (the probe reports what the application
    # loads at boot). A failed open records nothing. Calling into a library
    # is what can read files vci cannot see: every function attached with
    # attach_function (and attach_variable's accessors, an FFI::Function or
    # VariadicInvoker called directly) refuses the file when it is called,
    # unless the library has a policy that sees its file inputs at the Ruby
    # level (Native::Vips, for ruby-vips).
    def install_ffi
      return true if MODE == "plain"
      ::FFI::DynamicLibrary.singleton_class.prepend(Native::OpenHook)
      return true unless collect?
      ::FFI::Library.prepend(Native::LibraryHook)
      ::FFI::Function.prepend(Native::FunctionHook) if defined?(::FFI::Function)
      true
    end

    def install_ffi_variadic
      return true unless collect?
      ::FFI::VariadicInvoker.prepend(Native::VariadicHook)
      true
    end

    # ruby-vips' Ruby entry point to libvips operations (Image.new_from_file,
    # #write_to_file, .thumbnail, .new_from_buffer, every image method):
    # see Native::Vips.
    def install_vips
      return true unless collect?
      ::Vips::Operation.singleton_class.prepend(Native::VipsOperationCall)
      true
    end

    # libxml2 (Nokogiri) reads files in C: external entities and DTDs
    # (parse options NOENT, DTDLOAD, DTDATTR), XInclude, schema and RelaxNG
    # includes and imports, XSLT includes, imports and document(), and a SAX
    # parse of a file by name. Each of these refuses the file, except a SAX
    # parse of a named file without entity substitution, which records it.
    def install_nokogiri
      return true unless collect?
      # ParseOptions' constants are set after the class (when this runs).
      opts = lambda do |where, o|
        po = ::Nokogiri::XML::ParseOptions
        ext = po::NOENT | po::DTDLOAD | po::DTDATTR | po::XINCLUDE
        n = o.respond_to?(:to_i) ? o.to_i : 0
        VciCollector.taint("native:libxml2:#{where} with options #{n} (external entities, DTDs or XInclude are read in C)") if (n & ext) != 0
      end
      ::Nokogiri::XML::Document.singleton_class.prepend(Module.new do
        %i[read_memory read_io].each do |m|
          define_method(m) do |*args, **kw, &blk|
            opts.call("Document.#{m}", args[3]) unless VciCollector.busy?
            super(*args, **kw, &blk)
          end
        end
      end)
      ::Nokogiri::XML::Reader.singleton_class.prepend(Module.new do
        %i[from_memory from_io].each do |m|
          define_method(m) do |*args, **kw, &blk|
            opts.call("Reader.#{m}", args[3]) unless VciCollector.busy?
            super(*args, **kw, &blk)
          end
        end
      end)
      ::Nokogiri::XML::Node.prepend(Module.new do
        define_method(:do_xinclude) do |*args, **kw, &blk|
          VciCollector.taint("native:libxml2:XInclude (included files are read in C)") unless VciCollector.busy?
          super(*args, **kw, &blk)
        end

        define_method(:in_context) do |str, o|
          opts.call("Node#parse", o) unless VciCollector.busy?
          super(str, o)
        end
        private :in_context
      end)
      refs = /schemaLocation|include|import|redefine|override|externalRef|href/
      [::Nokogiri::XML::Schema, ::Nokogiri::XML::RelaxNG].each do |k|
        k.singleton_class.prepend(Module.new do
          define_method(:from_document) do |doc, *rest, **kw, &blk|
            unless VciCollector.busy?
              text = VciCollector.quiet { doc.respond_to?(:to_xml) ? doc.to_xml : doc.to_s }
              VciCollector.taint("native:libxml2:#{k.name.split("::").last} with includes or imports (read in C)") if refs.match?(text)
            end
            super(doc, *rest, **kw, &blk)
          end
        end)
        k.prepend(Module.new do
          define_method(:validate_file) do |path, *rest|
            VciCollector.taint("native:libxml2:#{k.name.split("::").last}#validate of a file by name (read in C)") unless VciCollector.busy?
            super(path, *rest)
          end
          private :validate_file
        end)
      end
      ::Nokogiri::XSLT::Stylesheet.singleton_class.prepend(Module.new do
        def parse_stylesheet_doc(*args, **kw, &blk)
          VciCollector.taint("native:libxml2:XSLT (xsl:include, xsl:import and document() read files in C)") unless VciCollector.busy?
          super
        end
      end)
      ::Nokogiri::XML::SAX::ParserContext.singleton_class.prepend(Module.new do
        def file(path, *rest, **kw, &blk)
          VciCollector.read_path(VciCollector.pathify(path)) unless VciCollector.busy?
          super
        end
      end)
      ::Nokogiri::XML::SAX::ParserContext.prepend(Module.new do
        def replace_entities=(v)
          VciCollector.taint("native:libxml2:SAX replace_entities (external entities are read in C)") if v && !VciCollector.busy?
          super
        end
      end)
      true
    end

    # SQLite opens, writes and attaches database files in C. A database
    # other than the test environment's (config/database.yml) or one in
    # vci's temp dir is not attestable (DB.taints, at exit), and so is ATTACH
    # (an authorizer refuses it) and loading an extension.
    def install_sqlite3
      return true unless collect?
      ::SQLite3::Database.prepend(Module.new do
        def initialize(file, *rest, **kw, &blk)
          super
          VciCollector::DB.sqlite_opened(file, self) unless VciCollector.busy?
        end

        def enable_load_extension(*args)
          VciCollector.taint("rails:sqlite-load-extension")
          super
        end

        def load_extension(*args)
          VciCollector.taint("rails:sqlite-load-extension")
          super
        end
      end)
      true
    end

    # A database server connection (PG::Connection, Mysql2::Client,
    # Trilogy). Accepted only when Active Record's own adapter code (in the
    # activerecord gem the bundle loaded) opens it to one of the test
    # environment's databases in config/database.yml (DB.configured_server?):
    # what that server holds is not an input (see DB). Refused like any
    # other socket: a client a test opens itself (PG.connect,
    # Mysql2::Client.new, Trilogy.new), and an Active Record connection to
    # any other server or database (establish_connection with another host,
    # port or database, another environment's configuration).
    def db_client_opened(name, args = [], kw = {})
      unless quiet { active_record_adapter_frame? }
        taint("network:#{name} client (a database connection the test opened itself)")
        return
      end
      why = quiet { DB.configured_server?(name, args, kw) }
      return if why == true
      taint("network:#{name} (an Active Record connection to #{why}, not one of the test environment's " \
            "databases in config/database.yml)")
    rescue StandardError => e
      taint("network:#{name} (vci could not tell which server this connects to: #{e.class})")
    end

    # A frame of the 30 callers is in lib/active_record/connection_adapters/
    # of the activerecord gem the bundle loaded (not a file of the
    # repository or of another gem that happens to have such a path).
    def active_record_adapter_frame?
      spec = defined?(::Gem) && ::Gem.respond_to?(:loaded_specs) ? ::Gem.loaded_specs["activerecord"] : nil
      return false if spec.nil?
      dir = Real.expand_path(File.join(spec.full_gem_path, "lib/active_record/connection_adapters"))
      rdir = real_of(dir)
      me = __FILE__
      caller_locations(1, 60).to_a.reject { |l| (l.absolute_path || l.path) == me }.first(30).any? do |l|
        path = (l.absolute_path || l.path).to_s
        path.start_with?("/") && (inside?(path, dir) || inside?(real_of(path), rdir))
      end
    end

    # Prism's file entry points (parse_file, parse_file_success?,
    # parse_file_failure?, parse_file_comments, lex_file, parse_lex_file,
    # dump_file, profile_file, and any other `*_file*` method) read the
    # source in C, like RubyVM::InstructionSequence.compile_file (ISeqHooks).
    # The first argument is the path.
    def install_prism
      return true unless collect?
      names = ::Prism.singleton_methods.select { |m| m.to_s.include?("_file") }
      ::Prism.singleton_class.prepend(Module.new do
        names.each do |m|
          define_method(m) do |path, *rest, **kw, &blk|
            VciCollector.read_path(VciCollector.pathify(path)) unless VciCollector.busy?
            super(path, *rest, **kw, &blk)
          end
        end
      end)
      @prism_hooked = names
      true
    end

    # A Prism `*_file*` method defined after the hook was installed (another
    # Prism backend loaded later) is not hooked.
    def prism_unhooked
      return [] unless defined?(::Prism) && ::Prism.respond_to?(:parse_file) && @prism_hooked
      (::Prism.singleton_methods.select { |m| m.to_s.include?("_file") } - @prism_hooked).map do |m|
        "vci:not-hooked:Prism.#{m} (reads a file in C)"
      end
    end

    # Etc answers who the process runs as (see VciCollector.identity_read).
    def install_etc
      return true unless collect?
      ms = %i[getlogin getpwuid getpwnam getgrgid getgrnam passwd group getpwent getgrent].select { |m| ::Etc.respond_to?(m) }
      ::Etc.singleton_class.prepend(VciCollector.identity_hook("Etc", ms))
      true
    end

    # OpenSSL (Ruby's openssl extension) reads certificates and its
    # configuration in C:
    # - X509::Store#add_file reads the file it names: recorded;
    # - X509::Store#set_default_paths (which openssl/ssl.rb calls for
    #   DEFAULT_CERT_STORE when it loads) and #add_path make the store read
    #   the system CA bundle, SSL_CERT_FILE and SSL_CERT_DIR, the directory
    #   lazily by certificate hash: the store is marked, and verifying with
    #   it (Store#verify, StoreContext.new, a TLS handshake) refuses the file;
    # - SSLContext's ca_file (read when the context is set up: recorded) and
    #   ca_path (a hashed directory, refused);
    # - Config.new/load of a file (recorded; refused when it has .include
    #   directives), Random.load_random_file (recorded) and
    #   write_random_file (a write).
    # OPENSSL_* variables (OPENSSL_CONF, read when the library loads) are
    # hashed whenever present (RAILS_HASHED_ENV).
    def install_openssl
      return true unless collect?
      ::OpenSSL::X509::Store.prepend(OpenSSLHooks::Store)
      ::OpenSSL::X509::StoreContext.prepend(OpenSSLHooks::StoreContext)
      ::OpenSSL::SSL::SSLContext.prepend(OpenSSLHooks::SSLContext)
      ::OpenSSL::SSL::SSLSocket.prepend(OpenSSLHooks::SSLSocket)
      ::OpenSSL::Config.prepend(OpenSSLHooks::Config)
      ::OpenSSL::Random.singleton_class.prepend(OpenSSLHooks::Random) if defined?(::OpenSSL::Random)
      true
    end

    # Loading an OpenSSL provider or engine loads a module (native code)
    # from OpenSSL's directories.
    def install_openssl_modules(mod)
      return true unless collect?
      name = mod.name
      ms = %i[load by_id load_private_key load_public_key].select { |m| mod.respond_to?(m) }
      mod.singleton_class.prepend(Module.new do
        ms.each do |m|
          define_method(m) do |*args, **kw, &blk|
            VciCollector.taint("native:#{name}.#{m} (loads OpenSSL module code vci does not see)") unless VciCollector.busy?
            super(*args, **kw, &blk)
          end
        end
      end)
      true
    end

    # Zlib::GzipReader.open/GzipWriter.open open their file in C.
    def install_zlib
      return true unless collect?
      ::Zlib::GzipReader.singleton_class.prepend(Module.new do
        def open(path, *rest, **kw, &blk)
          VciCollector.read_path(VciCollector.pathify(path)) unless VciCollector.busy?
          super
        end
      end)
      ::Zlib::GzipWriter.singleton_class.prepend(Module.new do
        def open(path, *rest, **kw, &blk)
          VciCollector.wrote(path, produced: true) unless VciCollector.busy?
          super
        end
      end)
      true
    end
  end

  # Native libraries reached through FFI (see install_ffi).
  module Native
    @libs = {}     # "native:<file name>" => real path, or nil when unresolved
    # FFI::Function objects attach_function returned => [policy, owner,
    # C name, library names]: ruby-vips keeps g_free's as a free function
    # (FFI::AutoPointer.new(ptr, GLib::G_FREE)) and calls it directly.
    @functions = {}.compare_by_identity
    FFI_OK = :__vci_ffi_variadic_ok

    class << self
      attr_reader :libs

      # A library FFI opened: recorded by the file it resolved to (hashed
      # when the records are written, so no gem is required now).
      def loaded(lib, requested)
        name = (lib.name rescue nil) || requested
        # nil: the process's own symbols (Ruby and what it links), which
        # the Ruby version identifies.
        return if name.nil?
        VciCollector.quiet do
          n = name.to_s
          real = n.start_with?("/") ? (Real.realpath(n) rescue nil) : nil
          key = "native:#{Real.basename(real || n)}"
          if real && @libs[key] && @libs[key] != real
            VciCollector.taint("native:FFI two libraries named #{Real.basename(real)} (#{@libs[key]}, #{real})")
          end
          @libs[key] = real if real || !@libs.key?(key)
        end
      rescue StandardError => e
        VciCollector.taint("vci:hook-failed:ffi-open:#{e.class}: #{e.message}")
      end

      # "sha256:<hex>" of each recorded library file ("unresolved" when FFI
      # gave no path, such as a system library in the dyld shared cache).
      def versions
        require "digest/sha2"
        @libs.to_h do |key, real|
          v = real && Real.file?(real) ? "sha256:#{Digest::SHA256.file(real).hexdigest}" : "unresolved"
          [key, v]
        end
      end

      def lib_names(mod)
        (mod.ffi_libraries.map { |l| Real.basename(l.name.to_s) } rescue [])
      end

      # The policy for functions `mod` attaches, called from `where`: Vips
      # for the modules ruby-vips defines (Vips, GLib, GObject) in its own
      # files, over libvips (or GLib and GObject); nil (every call refuses
      # the file) for everything else.
      def policy_for(mod, where)
        n = (mod.name rescue nil).to_s
        return nil unless %w[Vips GLib GObject].include?(n) || n.start_with?("Vips::")
        spec = ::Gem.loaded_specs["ruby-vips"]
        return nil unless spec&.full_gem_path
        dirs = [Real.expand_path(spec.full_gem_path)]
        dirs << (Real.realpath(dirs[0]) rescue dirs[0])
        return nil unless dirs.any? { |d| VciCollector.inside?(where, File.join(d, "lib")) }
        return nil if VciCollector.inside?(where, VciCollector.repo)
        libs = lib_names(mod)
        return nil if libs.empty?
        return nil unless libs.all? { |b| b.match?(/\A(lib)?(vips|glib-2\.0|gobject-2\.0)[.-]/) }
        Vips
      rescue StandardError
        nil
      end

      def remember(invoker, mod, cname, policy)
        return unless defined?(::FFI::Function) && invoker.is_a?(::FFI::Function)
        @functions[invoker] = [policy, ((mod.name rescue nil) || mod.inspect), cname, lib_names(mod)]
      rescue StandardError => e
        VciCollector.taint("vci:hook-failed:ffi-remember:#{cname}:#{e.class}: #{e.message}")
      end

      def function(fn)
        @functions[fn]
      end

      # Wrap the methods FFI defined for an attached function or variable
      # (on the module and its singleton class) so that a call is checked.
      # A variadic function's method calls VariadicInvoker#call (and so
      # #invoke), which is then not a direct call. The wrapper replaces
      # FFI's method in place (with its visibility) rather than being
      # prepended: FFI's method is then reachable only from inside the
      # wrapper, so `method(:f).super_method.call` (or an alias made after
      # attach_function) cannot call the C function past the check.
      def wrap(mod, mname, cname, policy, names = [mname], variadic: false)
        owner = (mod.name rescue nil) || mod.inspect
        libs = lib_names(mod)
        [mod.singleton_class, mod].each do |target|
          names.each do |n|
            vis = if target.private_method_defined?(n) then :private
                  elsif target.protected_method_defined?(n) then :protected
                  elsif target.method_defined?(n) then :public
                  end
            next unless vis
            orig = target.instance_method(n)
            target.send(:remove_method, n) if orig.owner == target
            target.send(:define_method, n) do |*a, &b|
              VciCollector::Native.called(policy, owner, cname, libs, a, variadic) { orig.bind_call(self, *a, &b) }
            end
            target.send(vis, n)
          end
        end
      rescue StandardError => e
        VciCollector.taint("vci:hook-failed:ffi-wrap:#{mname}:#{e.class}: #{e.message}")
      end

      def called(policy, owner, cname, libs, args, variadic = false)
        if !VciCollector.collect? || VciCollector.busy?
          Thread.current[FFI_OK] = variadic
          return yield
        end
        why = begin
          policy ? policy.check(cname, args) : :refuse
        rescue StandardError => e
          "vci:hook-failed:ffi-policy:#{cname}:#{e.class}: #{e.message}"
        end
        if why == :refuse
          VciCollector.taint("native:FFI call #{owner}.#{cname} (C code of #{libs.join(", ")}: vci cannot see what it reads)")
        elsif why
          VciCollector.taint(why)
        end
        Thread.current[FFI_OK] = variadic
        r = yield
        begin
          policy&.after(cname, args, r)
        rescue StandardError => e
          VciCollector.taint("vci:hook-failed:ffi-policy:#{cname}:#{e.class}: #{e.message}")
        end
        r
      ensure
        Thread.current[FFI_OK] = false
      end

      # A C function called without going through an attached method.
      def direct_call(what)
        if Thread.current[FFI_OK]
          Thread.current[FFI_OK] = false
          return
        end
        return if !VciCollector.collect? || VciCollector.busy?
        VciCollector.taint("native:FFI #{what} (a C function called directly: vci cannot see what it reads)")
      end
    end

    module OpenHook
      def open(*args, **kw, &blk)
        lib = super
        VciCollector::Native.loaded(lib, args[0])
        lib
      end
    end

    module LibraryHook
      def attach_function(*args, **kw, &blk)
        mname = args[0].to_s
        cname = args[3] && (args[1].is_a?(String) || args[1].is_a?(Symbol)) ? args[1].to_s : mname
        policy = VciCollector::Native.policy_for(self, VciCollector.quiet { VciCollector.frame })
        was = Thread.current[:__vci_ffi_attaching]
        Thread.current[:__vci_ffi_attaching] = true
        begin
          invoker = super
        ensure
          Thread.current[:__vci_ffi_attaching] = was
        end
        VciCollector::Native.wrap(self, mname, cname, policy,
                                  variadic: defined?(::FFI::VariadicInvoker) && invoker.is_a?(::FFI::VariadicInvoker))
        VciCollector::Native.remember(invoker, self, cname, policy)
        invoker
      end

      # Finding the library (FFI's search of LD_LIBRARY_PATH, its library
      # directories, ...) is not an input: the file it found is recorded.
      def ffi_lib(*args, **kw, &blk)
        VciCollector.quiet { super }
      end

      def attach_variable(*args, **kw, &blk)
        r = super
        mname = args[0].to_s
        VciCollector::Native.wrap(self, mname, "variable #{mname}", nil, [mname, "#{mname}="])
        r
      end
    end

    module FunctionHook
      # Function#attach outside attach_function (a Function made from a
      # pointer and attached by hand) is wrapped like attach_function's.
      def attach(mod, name)
        r = super
        unless Thread.current[:__vci_ffi_attaching]
          VciCollector::Native.wrap(mod, name.to_s, "#{name} (FFI::Function#attach)", nil)
        end
        r
      end

      def call(*args, &blk)
        f = VciCollector::Native.function(self)
        if f
          policy, owner, cname, libs = f
          return VciCollector::Native.called(policy, owner, cname, libs, args) { super }
        end
        VciCollector::Native.direct_call("FFI::Function#call")
        super
      end
    end

    # VariadicInvoker#invoke is the C entry point (#call, and the methods
    # VariadicInvoker#attach defines, go through it).
    module VariadicHook
      def invoke(*args, &blk)
        VciCollector::Native.direct_call("VariadicInvoker#invoke")
        super
      end
    end

    # ruby-vips over libvips. libvips reads and writes files in C, but only
    # through a few entry points whose file names the Ruby side passes: the
    # file loaders and savers, thumbnail, file sources and targets, and the
    # format sniffer. Those are recorded (a read of the file named, a write
    # of the file saved); everything else ruby-vips calls works on memory
    # (images, buffers, GObject properties). What is refused: a loader or
    # saver vci does not know reads only the file it is given (PDF, SVG,
    # ImageMagick, OpenSlide, ...), `system`, `text` (fonts), ICC profiles
    # that are files, descriptor sources and targets, a file operation built
    # anywhere but through Vips::Operation.call (where its file name is
    # seen), and any libvips function this list does not name.
    module Vips
      FMT = "(?:jpeg|png|webp|gif|tiff|heif|jp2k|jxl|rad|ppm|csv|matrix)"
      FILE_OPS = /\A#{FMT}(?:load|save)\z/
      STREAM_OPS = /\A#{FMT}(?:load_(?:buffer|source)|save_(?:buffer|target|mime))\z/
      THUMBNAIL_STREAM = %w[thumbnail_buffer thumbnail_source thumbnail_image].freeze
      ICC_OPS = %w[icc_import icc_export icc_transform profile_load].freeze
      DENY_OPS = %w[system text].freeze
      # ICC profiles compiled into libvips.
      BUILTIN_PROFILES = %w[srgb cmyk p3 none].freeze
      # Option names whose value is a file: always refused (FILE_OPTION), or
      # an ICC profile, a built-in name or a file (PROFILE_OPTION).
      FILE_OPTION = /\A(?:filename|fontfile|font)\z/
      PROFILE_OPTION = /\A(?:profile|input_profile|output_profile|import_profile|export_profile)\z/
      # libvips/GLib functions that never touch a file.
      SAFE = %w[
        g_free g_log_remove_handler g_log_set_handler g_malloc g_object_get_property g_object_ref
        g_object_set_property g_object_unref g_param_spec_get_blurb g_signal_connect_data g_type_from_name
        g_type_fundamental g_type_init g_type_name g_value_get_boolean g_value_get_double g_value_get_enum
        g_value_get_flags g_value_get_int g_value_get_object g_value_get_string g_value_get_uint64 g_value_init
        g_value_set_boolean g_value_set_double g_value_set_enum g_value_set_flags g_value_set_int
        g_value_set_object g_value_set_string g_value_set_uint64 g_value_unset
        vips_addalpha vips_argument_map vips_band_format_get_type vips_band_format_iscomplex
        vips_band_format_isfloat vips_blend_mode_get_type vips_block_untrusted_set vips_cache_drop_all
        vips_cache_get_max vips_cache_get_max_files vips_cache_get_max_mem vips_cache_print vips_cache_set_max
        vips_cache_set_max_files vips_cache_set_max_mem vips_coding_get_type vips_concurrency_get
        vips_concurrency_set vips_connection_filename vips_connection_nick vips_enum_from_nick vips_enum_nick
        vips_error_buffer vips_error_clear vips_error_freeze vips_error_thaw vips_filename_get_filename
        vips_filename_get_options vips_flags_from_nick vips_foreign_find_load_buffer
        vips_foreign_find_load_source vips_foreign_find_save vips_foreign_find_save_buffer
        vips_foreign_find_save_target vips_foreign_get_suffixes vips_image_copy_memory vips_image_get
        vips_image_get_bands vips_image_get_fields vips_image_get_gainmap vips_image_get_height
        vips_image_get_typeof vips_image_get_width vips_image_hasalpha vips_image_new_from_memory
        vips_image_new_from_memory_copy vips_image_new_matrix_from_array vips_image_remove vips_image_set
        vips_image_set_kill vips_image_set_progress vips_image_write_to_memory vips_init vips_interpolate_new
        vips_interpretation_get_type vips_leak_set vips_nickname_find vips_object_get_argument
        vips_object_get_description vips_object_print_all vips_object_unref_outputs vips_operation_block_set
        vips_operation_get_flags vips_operation_new vips_region_fetch vips_region_height vips_region_new
        vips_region_width vips_source_custom_new vips_source_new_from_memory vips_target_custom_new
        vips_target_new_to_memory vips_tracked_get_allocs vips_tracked_get_files vips_tracked_get_mem
        vips_tracked_get_mem_highwater vips_type_find vips_type_map vips_value_get_array_double
        vips_value_get_array_image vips_value_get_array_int vips_value_get_blob vips_value_get_ref_string
        vips_value_set_array_double vips_value_set_array_image vips_value_set_array_int vips_value_set_blob
        vips_value_set_ref_string vips_vector_isenabled vips_vector_set_enabled vips_version
        vips_version_string
      ].to_h { |n| [n, true] }.freeze
      PERMITS = :__vci_vips_permits

      @ops = {} # operation pointer address => nickname (vips_operation_new)

      class << self
        # :file (reads or writes the file it names: recorded), :stream
        # (buffers, sources, targets), :icc (a profile may be a file),
        # :deny, :memory.
        def classify(name)
          return :deny unless name.is_a?(String)
          return :file if FILE_OPS.match?(name) || name == "thumbnail"
          return :stream if STREAM_OPS.match?(name) || THUMBNAIL_STREAM.include?(name)
          return :icc if ICC_OPS.include?(name)
          return :deny if DENY_OPS.include?(name) || name.match?(/load|save/)
          :memory
        end

        # [nickname, built] per Vips::Operation.call in progress.
        def permits
          Thread.current[PERMITS] ||= []
        end

        # An option given as a string ("x.jpg[shrink=2]", "[Q=90,strip]"):
        # nil, or why it is refused (a file name or an ICC profile file).
        def option_string_problem(str)
          s = str.to_s.strip
          return nil if s.empty?
          s = s[1...-1] if s.start_with?("[") && s.end_with?("]")
          s.split(",").each do |pair|
            k, v = pair.split("=", 2).map(&:strip)
            next unless k
            if PROFILE_OPTION.match?(k)
              next if v && BUILTIN_PROFILES.include?(v.downcase)
              return "native:vips:option string #{str.inspect} names an ICC profile file"
            end
            if FILE_OPTION.match?(k) || k.match?(/file|font/)
              return "native:vips:option string #{str.inspect} names a file"
            end
          end
          nil
        end

        # Options that are files: nil, or why the call is refused.
        def options_problem(name, opts)
          opts.each do |k, v|
            key = k.to_s
            return "native:vips:#{name} option #{key} names a file" if FILE_OPTION.match?(key)
            next unless PROFILE_OPTION.match?(key) && !v.nil?
            unless v.is_a?(String) && BUILTIN_PROFILES.include?(v.downcase)
              return "native:vips:#{name} with the ICC profile #{v.inspect} (a file lcms reads in C)"
            end
          end
          nil
        end

        # The nickname of the operation libvips builds for `name`, which is
        # what is classified. vips_operation_new finds it with
        # vips_type_find("VipsOperation", name), comparing every
        # operation's nickname and class name without regard to case:
        # "PNGLOAD", "PngLoad", "VipsForeignLoadPngFile" and
        # "VIPSFOREIGNLOADPNGFILE" all build pngload (vips_foreign_find_load
        # answers class names). The same lookup is made here. nil when
        # libvips has no such operation, or vci could not ask: refused.
        def nickname(name)
          n = name.to_s
          @nicks ||= {}
          return @nicks[n] if @nicks.key?(n)
          @nicks[n] = VciCollector.quiet do
            t = ::Vips.type_find("VipsOperation", n)
            nick = t.to_i.zero? ? nil : ::Vips.nickname_find(t)
            nick.is_a?(String) && !nick.empty? ? nick : nil
          end
        rescue StandardError
          nil
        end

        def unresolved(name)
          "native:vips:#{name.to_s.inspect} (not an operation name vci could resolve the way libvips does)"
        end

        def addr(x)
          p = x.respond_to?(:to_ptr) ? x.to_ptr : x
          p.respond_to?(:address) ? p.address : nil
        rescue StandardError
          nil
        end

        def strip_options(name)
          s = name.to_s
          i = s.rindex("[")
          s.end_with?("]") && i ? s[0...i] : s
        end

        # nil: allowed; a String: the taint; :refuse: the generic one.
        def check(cname, args)
          case cname
          when "vips_foreign_find_load", "vips_source_new_from_file"
            # The sniffer opens the file and reads its header; a file
            # source is read later, by the loader given it.
            path = VciCollector.pathify(args[0])
            return "native:vips:#{cname} without a file name" unless path
            # libvips strips "[options]" from a name here; a file whose
            # name ends in brackets is read as given: record both.
            VciCollector.rec(:read, path)
            VciCollector.rec(:read, strip_options(path)) if strip_options(path) != path
            nil
          when "vips_target_new_to_file"
            nil
          when "vips_source_new_from_descriptor", "vips_target_new_to_descriptor"
            "native:vips:#{cname} (a file descriptor libvips reads or writes in C)"
          when "vips_object_set_from_string"
            option_string_problem(args[1].to_s)
          when "vips_cache_operation_build"
            build(args[0])
          else
            SAFE.key?(cname) ? nil : :refuse
          end
        end

        def after(cname, args, result)
          case cname
          when "vips_operation_new"
            a = addr(result)
            @ops[a] = nickname(args[0]) || :unresolved if a && a != 0
          when "vips_target_new_to_file"
            wrote(args[0])
          end
        end

        def wrote(path)
          p = VciCollector.pathify(path)
          return unless p
          abs = VciCollector.expand(p)
          return unless abs
          existed = VciCollector.quiet { Real.exist?(abs) }
          VciCollector.opened(abs, "w", nil, existed, true)
        end

        # Building (running) an operation: a file operation only through
        # Operation.call, which recorded its file.
        def build(op)
          name = @ops[addr(op)]
          return "native:vips:build of an operation vci did not see created" unless name
          case classify(name)
          when :memory, :stream then nil
          when :deny then deny(name)
          else
            # Once per call: the operation Operation.call made for the
            # arguments it recorded.
            top = permits.last
            if top && top[0] == name && !top[1]
              top[1] = true
              nil
            else
              "native:vips:#{name} built outside Vips::Operation.call (vci did not see its file arguments)"
            end
          end
        end

        def deny(name)
          "native:vips:#{name} (libvips reads files, fonts or processes there that vci does not see)"
        end

        # Vips::Operation.call(name, supplied, optional, option_string):
        # nil when allowed (its file recorded), else the taint.
        def check_call(name, supplied, optional, option_string)
          kind = classify(name)
          return deny(name) if kind == :deny
          why = option_string_problem(option_string)
          return why if why
          opts = optional.is_a?(Hash) ? optional : {}
          why = options_problem(name, opts)
          return why if why
          case kind
          when :file
            path = VciCollector.pathify(name.include?("save") ? Array(supplied)[1] : Array(supplied)[0])
            return "native:vips:#{name} without a file name" unless path
            VciCollector.rec(:read, path) unless name.include?("save")
          when :icc
            # Profiles given as required arguments (icc_transform's output
            # profile, profile_load's name): a built-in name or a file.
            given = Array(supplied).select { |v| v.is_a?(String) || v.respond_to?(:to_path) }
            bad = given.reject { |v| v.is_a?(String) && BUILTIN_PROFILES.include?(v.downcase) }
            return "native:vips:#{name} with the ICC profile #{bad.first.inspect} (a file lcms reads in C)" unless bad.empty?
          end
          nil
        end

        def after_call(name, supplied)
          wrote(Array(supplied)[1]) if classify(name) == :file && name.include?("save")
        end
      end
    end

    module VipsOperationCall
      def call(name, supplied, optional = {}, option_string = "")
        return super if !VciCollector.collect? || VciCollector.busy?
        v = VciCollector::Native::Vips
        n = v.nickname(name)
        why = n ? v.check_call(n, supplied, optional, option_string) : v.unresolved(name)
        VciCollector.taint(why) if why
        v.permits.push(why ? nil : [n, false])
        begin
          super
        ensure
          v.permits.pop
          v.after_call(n, supplied) unless why
        end
      end
    end
  end

  # OpenSSL entry points that read files in C (see install_openssl).
  module OpenSSLHooks
    # Certificate stores whose contents OpenSSL reads where vci cannot see
    # it => why (weak keys: identity, and a frozen store can be marked).
    @unseen = ObjectSpace::WeakMap.new

    class << self
      # Marked whatever the caller (also inside the collector's own quiet
      # blocks): what the store holds is a fact about it, not a record.
      def mark(store, why)
        @unseen[store] = why
      rescue StandardError => e
        VciCollector.taint("vci:hook-failed:openssl-store:#{e.class}: #{e.message}")
      end

      # Verifying with a store reads what it holds.
      def check(store, where)
        return if VciCollector.busy? || store.nil?
        why = @unseen[store]
        VciCollector.taint("native:openssl:#{where} with a certificate store that #{why} (OpenSSL reads those certificates in C)") if why
      rescue StandardError => e
        VciCollector.taint("vci:hook-failed:openssl-check:#{e.class}: #{e.message}")
      end

      # A file OpenSSL reads whole, by name, now.
      def read_file(path, what)
        return if VciCollector.busy?
        p = VciCollector.pathify(path)
        return VciCollector.taint("native:openssl:#{what} of #{path.class} (not a file name vci can record)") unless p
        if VciCollector.exists_quietly?(p)
          VciCollector.read_path(p)
        else
          VciCollector.rec(:probe, p)
        end
        p
      end

      # SSLContext#setup (also run by SSLSocket.new in C): ca_file is read,
      # ca_path is a directory read by certificate hash on demand.
      def context(ctx, where)
        return if VciCollector.busy? || ctx.nil?
        f = VciCollector.quiet { ctx.ca_file }
        read_file(f, "#{where} ca_file") if f
        d = VciCollector.quiet { ctx.ca_path }
        VciCollector.taint("native:openssl:#{where} with ca_path #{d.to_s.inspect} (a certificate directory OpenSSL reads by hash in C)") if d
      rescue StandardError => e
        VciCollector.taint("vci:hook-failed:openssl-context:#{e.class}: #{e.message}")
      end

      def handshake(sock, where)
        return if VciCollector.busy?
        ctx = VciCollector.quiet { sock.context }
        return if ctx.nil? || VciCollector.quiet { ctx.verify_mode.to_i }.zero?
        check(VciCollector.quiet { ctx.cert_store }, where)
      rescue StandardError => e
        VciCollector.taint("vci:hook-failed:openssl-handshake:#{e.class}: #{e.message}")
      end
    end

    module Store
      def set_default_paths(*args, **kw, &blk)
        OpenSSLHooks.mark(self, "loaded OpenSSL's default paths (the system CA certificates, SSL_CERT_FILE, SSL_CERT_DIR)")
        super
      end

      def add_path(*args, **kw, &blk)
        OpenSSLHooks.mark(self, "has a certificate directory (add_path #{args[0].to_s.inspect}, read by hash on demand)")
        super
      end

      def add_file(path, *rest, **kw, &blk)
        OpenSSLHooks.read_file(path, "X509::Store#add_file")
        super
      end

      def verify(*args, **kw, &blk)
        OpenSSLHooks.check(self, "X509::Store#verify")
        super
      end
    end

    module StoreContext
      def initialize(*args, **kw, &blk)
        OpenSSLHooks.check(args[0], "X509::StoreContext.new")
        super
      end
    end

    module SSLContext
      def setup(*args, **kw, &blk)
        OpenSSLHooks.context(self, "SSLContext#setup")
        super
      end
    end

    module SSLSocket
      def initialize(*args, **kw, &blk)
        super
        OpenSSLHooks.context(VciCollector.quiet { context }, "SSLSocket.new")
      end

      %i[connect accept connect_nonblock accept_nonblock].each do |m|
        define_method(m) do |*args, **kw, &blk|
          OpenSSLHooks.handshake(self, "SSLSocket##{m}")
          super(*args, **kw, &blk)
        end
      end
    end

    module Config
      def initialize(*args, **kw, &blk)
        if args[0] && !VciCollector.busy?
          p = OpenSSLHooks.read_file(args[0], "Config.new")
          text = p && VciCollector.quiet { File.binread(p) rescue "" }
          if text&.match?(/^\s*\.include/)
            VciCollector.taint("native:openssl:Config.new(#{p.inspect}) with .include directives (files OpenSSL reads in C)")
          end
        end
        super
      end
    end

    module Random
      def load_random_file(path, *rest, **kw, &blk)
        OpenSSLHooks.read_file(path, "Random.load_random_file")
        super
      end

      def write_random_file(path, *rest, **kw, &blk)
        p = VciCollector.busy? ? nil : VciCollector.pathify(path)
        existed = p && VciCollector.exists_quietly?(p)
        r = super
        VciCollector.opened(p, "w", nil, existed, true) if p
        r
      end
    end
  end

  module SocketInit
    def initialize(*args, **kw, &blk)
      VciCollector.taint("network:#{self.class.name}.new") unless VciCollector.busy?
      super
    end
  end

  module SocketClassHooks
    # ip_address_list and getifaddrs: the machine's network interfaces.
    %i[tcp udp_server_sockets tcp_server_sockets unix unix_server_socket getaddrinfo gethostbyname
       gethostbyaddr getservbyname getnameinfo ip_address_list getifaddrs].each do |m|
      define_method(m) do |*args, **kw, &blk|
        VciCollector.taint("network:Socket.#{m}") unless VciCollector.busy?
        super(*args, **kw, &blk)
      end
    end
  end

  module AddrinfoHooks
    %i[getaddrinfo tcp udp foreach].each do |m|
      define_method(m) do |*args, **kw, &blk|
        VciCollector.taint("network:Addrinfo.#{m}") unless VciCollector.busy?
        super(*args, **kw, &blk)
      end
    end
  end

  # The development/test local secret is generated fresh in memory, as on a
  # fresh checkout, instead of being kept in tmp/local_secret.txt (whose
  # random content would otherwise be an input). The database configuration
  # Rails reads from config/database.yml is remembered, never changed (DB).
  module RailsConfigHooks
    def database_configuration
      VciCollector::DB.configured(super)
    end

    private

    def generate_local_secret
      VciCollector::DB.local_secret
    end
  end

  # The test database is the test engine's business. vci does not redirect,
  # prepare, purge or load it: Rails' maintain_test_schema! (which may shell
  # out to `bin/rails db:test:prepare`, VciCollector.engine_child?),
  # transactional tests and fixtures give each test its starting state, as
  # in a plain `bin/rails test` or `rspec`. Its contents are never an input:
  #
  # - the SQLite files config/database.yml configures for the test
  #   environment (every database of a multi-database app, Rails 8's
  #   storage/*.sqlite3 included) and their -wal, -shm and -journal siblings:
  #   opening them is accepted, and no read, stat, probe, listing entry or
  #   write of them is recorded (Output.write_records), as long as what is
  #   there is a SQLite database (DB.exempt): another file an entry names
  #   (one Rails never opens) is recorded like any file;
  # - a database server: Active Record's own connections to the test
  #   environment's databases are accepted (VciCollector.db_client_opened).
  #
  # What the test sees is recorded where Ruby reads it, and the schema files
  # every test database is loaded from (DB.schema_files) are inputs whether
  # or not this process reads them: db/schema.rb or structure.sql,
  # db/cache_schema.rb and the like, config/database.yml, the fixture files,
  # the code. Still refused: a SQLite file that is not one of those (SQLite
  # reads and writes it in C, where vci cannot see it), ATTACH, SQLite
  # extensions, a database client a test opens itself, and an Active Record
  # connection to any other server or database.
  module DB
    SQLITE_ATTACH = 24
    SIBLINGS = ["", "-wal", "-shm", "-journal"].freeze
    @yaml = nil
    @opened = [] # [as given, real path or nil]: SQLite files opened

    class << self
      def local_secret
        @local_secret ||= VciCollector.quiet { SecureRandom.hex(64) }
      end

      def env_name
        ENV["RAILS_ENV"] || ENV["RACK_ENV"] || "development"
      end

      # Rails' reading of config/database.yml (before DATABASE_URL is merged
      # in): kept as it is. The first reading (Rails' own, at boot) is the
      # one remembered, with the DATABASE_URL variables at that time.
      def configured(all)
        if all.is_a?(Hash) && @yaml.nil?
          @yaml = all
          @urls = VciCollector.quiet { url_env }
        end
        all
      end

      # DATABASE_URL and <NAME>_DATABASE_URL, which Active Record merges into
      # the configurations.
      def url_env
        ENV.keys.grep(/DATABASE_URL\z/).sort.to_h { |k| [k, ENV[k]] }
      end

      # The test environment's entries in config/database.yml.
      def yaml_configs
        cfg = @yaml && @yaml[env_name]
        return [] unless cfg.is_a?(Hash)
        return [cfg] if cfg.key?("adapter") || cfg.key?("database") || cfg.key?("url")
        cfg.values.select { |c| c.is_a?(Hash) }
      end

      # The test environment's database configurations as Active Record
      # resolves them (url, DATABASE_URL merged in; replicas and
      # database_tasks: false entries included), from the remembered
      # config/database.yml: what a test assigns to
      # ActiveRecord::Base.configurations later changes nothing.
      #
      # In a batch's slot, each also as Rails' parallel worker of that index
      # has it (database `<database>_<i>`: ActiveRecord::TestDatabases), the
      # slot's own database.
      def server_configs
        base = @server_configs ||= begin
          return [] unless @yaml && defined?(::ActiveRecord::DatabaseConfigurations)
          all = ::ActiveRecord::DatabaseConfigurations.new(@yaml)
          list = begin
            all.configs_for(env_name: env_name, include_hidden: true)
          rescue ArgumentError
            all.configs_for(env_name: env_name)
          end
          list.map { |c| c.configuration_hash.to_h.transform_keys(&:to_sym) }
        end
        i = Batch.slot
        return base unless i
        base + base.filter_map { |c| c.merge(database: "#{c[:database]}_#{i}") unless c[:database].to_s.empty? }
      end

      TARGET_KEYS = %i[host hostaddr port socket database service default_file default_group].freeze

      # What decides which server and database a client reaches.
      def target(h)
        h = h.to_h.transform_keys(&:to_sym)
        t = TARGET_KEYS.to_h { |k| [k, h[k].to_s] }
        t[:database] = (h[:database] || h[:dbname] || h[:db]).to_s
        t
      end

      # The target of a client's arguments (PG's in every form it accepts:
      # keywords, a hash, a connection string or URL, positional), or nil.
      def client_target(name, args, kw)
        if name == "postgresql"
          str = ::PG::Connection.parse_connect_args(*args, *(kw.empty? ? [] : [kw]))
          opts = ::PG::Connection.conninfo_parse(str).each_with_object({}) do |o, h|
            h[o[:keyword].to_sym] = o[:val] if o[:val]
          end
          return target(opts)
        end
        h = if args.empty?
              kw
            elsif args.size == 1 && args[0].is_a?(Hash) && kw.empty?
              args[0]
            end
        h && target(h)
      end

      # A configuration's target as its adapter passes it to the client
      # (TrilogyAdapter drops the host when a socket is given).
      def config_target(name, c)
        c = c.compact
        c = c.except(:host) if name == "trilogy" && !c[:socket].to_s.empty?
        target(c)
      end

      # true when a client opened with these arguments reaches one of the
      # test environment's databases; otherwise what it reaches.
      def configured_server?(name, args, kw)
        return "a server named by a DATABASE_URL the process changed" if @urls && url_env != @urls
        t = client_target(name, args, kw)
        return "a server vci cannot tell from the arguments" unless t
        return true if server_configs.any? { |c| config_target(name, c) == t }
        return true if Batch.slot_setup? && server_level?(name, t)
        where = [t[:socket], t[:host], t[:hostaddr]].reject(&:empty?).first || "localhost"
        where = "#{where}:#{t[:port]}" unless t[:port].empty?
        "#{where}/#{t[:database]}"
      end

      # A connection to a configured server without its database, as
      # Active Record's database tasks make one to create or purge a
      # database (MySQL: no database; PostgreSQL: "postgres"). Allowed only
      # while a batch's slot sets up its database (Batch.slot_setup?).
      def server_level?(name, t)
        return false unless ["", "postgres"].include?(t[:database])
        server_configs.any? { |c| config_target(name, c).merge(database: t[:database]) == t }
      end

      # A SQLite database name as SQLite opens it: [path, in_memory]. A
      # `file:` URI is parsed as SQLite parses it (an authority of "" or
      # "localhost", %HH escapes, the last `mode` parameter wins); only
      # ":memory:" (plain or as a URI's path) and mode=memory are in memory.
      # Anything else names a file ("file::memory:x" is a file named
      # ":memory:x"). The empty name is a private temporary database.
      def sqlite_name(f)
        f = f.to_s
        return [nil, true] if f.empty? || f == ":memory:"
        return [f, false] unless f.start_with?("file:")
        rest = f.delete_prefix("file:").split("#", 2).first.to_s
        path, query = rest.split("?", 2)
        path = path.to_s
        if path.start_with?("//")
          auth, slash, tail = path[2..].partition("/")
          path = auth.empty? || auth == "localhost" ? "#{slash}#{tail}" : path
        end
        path = uri_decode(path)
        mode = nil
        query.to_s.split("&").each do |kv|
          k, v = kv.split("=", 2)
          mode = uri_decode(v.to_s) if uri_decode(k.to_s) == "mode"
        end
        return [nil, true] if path == ":memory:" || mode == "memory"
        [path.empty? ? nil : path, path.empty?]
      end

      def uri_decode(s)
        s.b.gsub(/%([0-9A-Fa-f]{2})/) { Regexp.last_match(1).hex.chr }.force_encoding(Encoding::UTF_8)
      end

      # A SQLite database name as a file path, or nil (in memory, empty).
      def sqlite_path(f)
        sqlite_name(f).first
      end

      # Absolute paths of the SQLite files config/database.yml configures
      # for the test environment (relative to the application root, as
      # Active Record resolves them). An in-memory database has none.
      # In a batch's slot, each also with the slot's suffix (`<path>_<i>`,
      # the file Rails' parallel worker of that index uses).
      def sqlite_files
        root = VciCollector.root
        i = Batch.slot
        yaml_configs.flat_map do |c|
          url = c["url"].to_s
          db = if url.empty?
                 c["adapter"].to_s.start_with?("sqlite") ? c["database"] : nil
               elsif (m = url.match(/\Asqlite3?:(?:\/\/)?([^?]*)/))
                 m[1]
               end
          path = sqlite_path(db)
          next [] unless path
          abs = VciCollector.quiet { Real.expand_path(path, root) }
          i ? [abs, "#{abs}_#{i}"] : [abs]
        end.uniq
      end

      SQLITE_HEADER = "SQLite format 3\0".b.freeze

      # What about each configured file is not an input, by path (as given
      # and as real path): :all, or :meta (everything but a read of its
      # content). Only for what is a SQLite database at exit: a file that
      # starts with SQLite's header (:all), or one that is absent or empty
      # (:meta: SQLite has not written it yet). Anything else config/database.yml
      # names (a YAML file under an entry Rails never opens) is recorded like
      # any file. The -wal, -shm and -journal siblings of a database are
      # :meta, unless the sibling is a symlink (to another file).
      def exempt
        @exempt ||= VciCollector.quiet do
          out = {}
          sqlite_files.each do |f|
            real = VciCollector.real_of(f)
            state = db_state(real)
            next unless state
            out[f] = out[real] = state
            SIBLINGS.drop(1).each do |x|
              given = "#{f}#{x}"
              next if Real.symlink?(given)
              out[given] = :meta
              out[File.join(VciCollector.real_of(Real.dirname(given)), Real.basename(given))] = :meta
            end
          end
          out
        end
      end

      def db_state(real)
        return :meta unless Real.exist?(real)
        return nil unless Real.file?(real)
        return :meta if Real.stat(real).size.zero?
        Real.binread(real, SQLITE_HEADER.bytesize) == SQLITE_HEADER ? :all : nil
      rescue StandardError
        nil
      end

      # Whether a record of `kind` for `path` is exempt.
      def exempt?(kind, path)
        state = exempt[path]
        state == :all || (state == :meta && kind != :read)
      end

      # The schema files Active Record loads into the test environment's
      # databases (db/schema.rb or structure.sql, and db/cache_schema.rb and
      # the like of a multi-database app), absolute: inputs whether or not
      # this process read them. On a fresh database Rails reads none of them
      # in the process (`bin/rails db:test:prepare`, the engine's child,
      # loads them, and maintain_test_schema! only checks the first
      # database's file exists), yet a test sees the tables they define.
      def schema_files
        return [] unless defined?(::ActiveRecord::Base) && ::ActiveRecord.autoload?(:Base).nil? && @yaml
        require "active_record/tasks/database_tasks"
        tasks = ::ActiveRecord::Tasks::DatabaseTasks
        all = ::ActiveRecord::DatabaseConfigurations.new(@yaml)
        root = VciCollector.root
        all.configs_for(env_name: env_name).filter_map do |c|
          f = tasks.schema_dump_path(c)
          f && Real.expand_path(f.to_s, root)
        end.uniq
      rescue StandardError, LoadError => e
        VciCollector.taint("rails:schema-files:#{e.class}: #{e.message} (vci could not tell which schema files " \
                           "the test databases are loaded from)")
        []
      end

      def sqlite_opened(file, db)
        path = sqlite_path(file)
        if path
          abs = VciCollector.expand(path)
          @opened << [path, abs && VciCollector.real_of(abs)]
        end
        db.authorizer = proc do |action, *|
          VciCollector.taint("rails:sqlite-attach (ATTACH reads another database file in C)") if action == SQLITE_ATTACH
          0
        end
      rescue StandardError => e
        VciCollector.taint("rails:sqlite-hook:#{e.class}")
      end

      # At exit: SQLite files the process opened that are neither the test
      # environment's databases nor in vci's temp dir.
      def taints
        ok = sqlite_files.flat_map { |f| [f, VciCollector.real_of(f)] }
        tmp = TMP_ROOT && !TMP_ROOT.empty? ? Output.both(TMP_ROOT) : []
        @opened.filter_map do |given, real|
          next if real && (ok.include?(real) || tmp.any? { |d| VciCollector.inside?(real, d) })
          "rails:sqlite-file:#{real || given} (a SQLite database that is not one of the test environment's " \
            "databases in config/database.yml; SQLite reads and writes it in C, where vci cannot see it)"
        end.uniq
      end

      # The adapters of the test environment's databases (Active Record's
      # configurations: config/database.yml with DATABASE_URL merged in),
      # sorted and joined with ";": "sqlite3", "mysql2", "postgresql;sqlite3".
      # No server version: what a server holds or runs is not an input.
      # `load`: load Active Record for it (the probe, which boots the
      # application); otherwise only when the process loaded it.
      def adapters(load: false)
        return "" unless defined?(::ActiveRecord::Base)
        return "" unless load || ::ActiveRecord.autoload?(:Base).nil?
        configs = begin
          ::ActiveRecord::Base.configurations.configs_for(env_name: env_name, include_hidden: true)
        rescue ArgumentError
          ::ActiveRecord::Base.configurations.configs_for(env_name: env_name)
        end
        configs.map { |c| c.adapter.to_s }.reject(&:empty?).uniq.sort.join(";")
      rescue StandardError, LoadError
        ""
      end
    end
  end

  # Minitest: count every result.
  module MinitestPlugin
    def self.minitest_plugin_init(_options)
      ::Minitest.reporter << Reporter.new if ::Minitest.reporter
    end

    class Reporter
      attr_reader :count, :assertions, :failures, :errors, :skips, :no_assertions

      def initialize
        @count = 0
        @assertions = 0
        @failures = 0
        @errors = 0
        @skips = 0
        @no_assertions = 0
        @started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        VciCollector.instance_variable_set(:@minitest, self)
      end

      def duration_ms
        ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - @started) * 1000).round
      end

      def start; end
      def prerecord(_klass, _name); end

      def record(result)
        @count += 1
        @assertions += result.assertions.to_i
        if result.skipped?
          @skips += 1
        elsif result.error?
          @errors += 1
        elsif !result.passed?
          @failures += 1
        elsif result.assertions.to_i.zero?
          @no_assertions += 1
        end
      end

      def report; end

      def passed?
        true
      end
    end
  end

  # RSpec (VCI_RAILS_RUNNER=rspec). vci runs one spec file per process:
  #
  #   ruby -e 'require "bundler/setup"; require "rspec/core"; $0 = "rspec"; RSpec::Core::Runner.invoke' \
  #     -- --options .rspec <file>
  #
  # `--options .rspec` makes RSpec read the project's .rspec and nothing
  # else: not ~/.rspec, $XDG_CONFIG_HOME/rspec/options (outside the
  # repository) or .rspec-local (usually git-ignored). SPEC_OPTS is still
  # read (an environment variable, hashed whenever present).
  #
  # Installed in every mode (`vci ci` runs files the way they were attested):
  # - the example status file (`config.example_status_persistence_file_path`,
  #   which RSpec reads at start and rewrites at exit) is a fresh file in
  #   vci's temp dir: no earlier run's state is read, nothing is written in
  #   the repository;
  # - the default seed is 0 instead of a random one, so `config.order =
  #   :random` (and `Kernel.srand config.seed`) give the same order where the
  #   file was attested and in CI; defined order stays defined, and a seed
  #   given in .rspec, SPEC_OPTS or `config.seed =` is honoured;
  # - SimpleCov writes (and merges earlier results from) a directory in vci's
  #   temp dir instead of coverage/.
  # In collect mode the reporter is hooked to count examples, and what makes
  # a run unattestable is refused (see `taints`).
  module RSpecSupport
    STATUS_FILE = "vci-rspec-example-statuses.txt"
    COUNTS = %i[passed failed pending errors started finished].freeze
    @counts = COUNTS.to_h { |k| [k, 0] }
    # Examples that recorded a failure (Example#display_exception=), and
    # those of them later reported as passed: the failure was cleared before
    # the example finished (a retry in an around hook, rspec-retry, a
    # prepended Example#finish) or a reporter override turned it into a pass.
    @failed_examples = {}.compare_by_identity
    @cleared = []
    @errors = []
    @declared = 0
    @options = nil

    class << self
      attr_reader :counts, :errors, :options
      attr_accessor :declared

      def rspec?
        RUNNER == "rspec"
      end

      def tmpdir
        d = (Batch.slot_tmp || TMP).to_s
        d.empty? ? "/tmp" : d
      end

      # In a batch's slot (Batch.run_slot): the example status file the boot
      # configured moves to the slot's temp dir, as the boot's own would be
      # shared by the slots' processes.
      def slot_moved!
        return unless rspec? && defined?(::RSpec) && ::RSpec.respond_to?(:configuration)
        c = ::RSpec.configuration
        was = c.example_status_persistence_file_path
        c.example_status_persistence_file_path = was if was
      rescue StandardError
        nil
      end

      def status_file
        File.join(tmpdir, STATUS_FILE)
      end

      def coverage_dir
        VciCollector.quiet do
          d = File.join(tmpdir, "vci-coverage")
          Dir.mkdir(d) unless File.directory?(d)
          d
        end
      end

      def count(k)
        @counts[k] += 1
      end

      def example_failed!(example)
        @failed_examples[example] = true
      end

      def reported_passed(example)
        return unless @failed_examples.key?(example)
        @cleared << (example.respond_to?(:location) ? example.location.to_s : example.inspect)
      rescue StandardError => e
        @cleared << e.class.name
      end

      # What RSpec recorded per example (execution_result.status) against what
      # the reporter was told: a failed or pending status the reporter heard
      # about as something else (an overridden Reporter#example_failed).
      def status_mismatch
        statuses = ::RSpec.world.all_examples.map { |e| e.execution_result.status }
        failed = statuses.count(:failed)
        pending = statuses.count(:pending)
        return nil if failed <= @counts[:failed] && pending <= @counts[:pending]
        "rspec:status-mismatch (#{failed} examples failed and #{pending} are pending per RSpec, but the reporter " \
          "was told of #{@counts[:failed]} failures and #{@counts[:pending]} pending: a reporter override)"
      rescue StandardError => e
        "rspec:status-check-failed:#{e.class}: #{e.message}"
      end

      def install
        ::RSpec::Core::ConfigurationOptions.prepend(OptionsHook)
        ::RSpec::Core::Ordering::ConfigurationManager.prepend(SeedHook)
        ::RSpec::Core::Configuration.prepend(ConfigHook)
        ::RSpec::Core::Reporter.prepend(ReporterHook)
        ::RSpec::Core::World.prepend(WorldHook)
        ::RSpec::Core::Example.prepend(ExampleHook)
        # A configuration created before the hooks were installed gets the
        # same defaults.
        if ::RSpec.instance_variable_defined?(:@configuration) && (c = ::RSpec.instance_variable_get(:@configuration))
          SeedHook.default!(c.ordering_manager)
          path = c.instance_variable_get(:@example_status_persistence_file_path)
          c.example_status_persistence_file_path = path if path
        end
        true
      end

      # SimpleCov in an RSpec process: its results (and the earlier results
      # it merges, and .last_run.json) live in vci's temp dir. Minitest
      # processes are left as they were (coverage/ is a git-ignored scratch
      # directory there).
      def install_simplecov
        return true unless rspec?
        ::SimpleCov.singleton_class.prepend(Module.new do
          def coverage_path
            VciCollector::RSpecSupport.coverage_dir
          end
        end)
        true
      end

      # `vci plan`/`vci run` listing: the files `rspec` with no file
      # arguments would run, from RSpec's own configuration (default_path,
      # pattern, exclude_pattern, as .rspec and SPEC_OPTS set them; files
      # .rspec requires are loaded, as they would be).
      def list!(args)
        opts = ::RSpec::Core::ConfigurationOptions.new(args)
        config = ::RSpec.configuration
        opts.configure(config)
        world = ::RSpec.world
        if world.wants_to_quit || world.non_example_failure
          $stderr.puts "vci_collector: RSpec could not load its configuration (see above)"
          exit 1
        end
        files = config.files_to_run.map { |f| File.expand_path(f) }
        out = {
          files: files, defaultPath: config.default_path.to_s, pattern: config.pattern.to_s,
          excludePattern: config.exclude_pattern.to_s
        }
        $stdout.puts "VCI-RSPEC-LIST #{Json.dump(out)}"
      end

      def filters
        fm = ::RSpec.configuration.filter_manager
        parts = []
        parts << "inclusion filter #{fm.inclusions.description}" unless fm.inclusions.empty?
        parts << "exclusion filter #{fm.exclusions.description}" unless fm.exclusions.empty?
        parts << "only_failures" if ::RSpec.configuration.only_failures?
        parts << "fail_fast" if ::RSpec.configuration.fail_fast
        parts.empty? ? "" : " (#{parts.join("; ")})"
      rescue StandardError => e
        " (#{e.class})"
      end

      def declared_now
        [@declared.to_i, (::RSpec.world.all_examples.size rescue 0)].max
      end

      # Why this RSpec run cannot be attested (collect mode).
      def taints
        out = []
        o = @options
        if o.nil?
          out << "rspec:no-configuration (RSpec never read its options)" if @counts[:started].positive?
        else
          custom = (o.send(:custom_options_file) rescue nil)
          unless custom
            out << "rspec:option-files (RSpec was not given --options .rspec, so it read ~/.rspec, $XDG_CONFIG_HOME/rspec/options or .rspec-local)"
          end
          h = o.options
          out << "rspec:invocation:#{h[:runner].class.name} (--bisect, --drb, --init, --version or --help: no example of the file ran as such)" if h[:runner]
          out << "rspec:drb (examples run in another process)" if h[:drb]
        end
        if defined?(::RSpec) && ::RSpec.respond_to?(:configuration) && @counts[:started].positive?
          cfg = ::RSpec.configuration
          out << "rspec:dry-run (examples were reported without running)" if cfg.respond_to?(:dry_run?) && cfg.dry_run?
          run = @counts[:passed] + @counts[:failed] + @counts[:pending]
          declared = declared_now
          if @counts[:errors].positive?
            # A load error or a suite hook error stops RSpec early: that is
            # why examples did not run.
            out << "rspec:error-outside-examples:#{@errors.map { |e| e.lines.first.to_s.strip }.uniq.join("; ")}"
          elsif run < declared
            out << "rspec:filtered:#{declared - run} of #{declared} examples did not run#{filters} (a focused or filtered run vouches only for what ran)"
            out << "rspec:quit-early (RSpec stopped before running every example)" if ::RSpec.world.wants_to_quit
          end
        end
        unless @cleared.empty?
          out << "rspec:failure-cleared:#{@cleared.uniq.first(5).join(", ")} (an example failed and was then reported as passed: a retry, or code that clears or swallows the failure)"
        end
        if @counts[:started].positive? && (m = status_mismatch)
          out << m
        end
        if defined?(::RSpec::Retry) || defined?(::RSpec::Rebound)
          out << "rspec:retry (rspec-retry reports an example that failed and then passed as passed)"
        end
        if defined?(::ParallelTests) || defined?(::TurboTests)
          out << "rspec:parallel-tests (parallel_tests/turbo_tests split the suite across processes; vci runs one file per process itself)"
        end
        mt = VciCollector.instance_variable_get(:@minitest)
        out << "rspec:minitest-also-ran (#{mt.count} Minitest tests ran in the RSpec process)" if mt&.count.to_i.positive?
        out
      rescue StandardError => e
        ["rspec:check-failed:#{e.class}: #{e.message}"]
      end

      def result(status)
        c = @counts
        unless c[:started].positive?
          return { kind: "result", state: "failed", tests: 0, failed: 1, skipped: 0, durationMs: 0,
                   exitStatus: status, why: "no RSpec results (not a spec file, it failed to load, or RSpec never ran)" }
        end
        run = c[:passed] + c[:failed] + c[:pending]
        declared = declared_now
        failed = c[:failed] + c[:errors]
        state = if failed.positive? || status != 0 then "failed"
                elsif run.zero? then declared.positive? ? "filtered" : "no-tests"
                elsif run < declared then "filtered"
                elsif c[:pending].positive? then "passed"
                else "passed"
                end
        { kind: "result", state: state, tests: run, failed: failed.positive? || status.zero? ? failed : 1,
          skipped: c[:pending], declared: declared, errorsOutsideExamples: c[:errors],
          durationMs: ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - STARTED) * 1000).round,
          exitStatus: status }
      end
    end

    STARTED = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    # SimpleCov's configuration files outside the repository: ~/.simplecov
    # (simplecov/load_global_config.rb) and .simplecov in the directories
    # above the project that its upward search (simplecov/defaults.rb) tries
    # after the repository. Like ~/.rspec, never read in a vci RSpec process
    # (every mode): they look absent, on both sides.
    SIMPLECOV_CONFIG_FRAME = %r{/simplecov-[^/]+/lib/simplecov/(defaults|load_global_config)\.rb\z}

    module SimpleCovConfigGuard
      def exist?(path, *rest)
        return false if VciCollector::RSpecSupport.outside_simplecov_config?(path)
        super
      end
    end

    class << self
      def outside_simplecov_config?(path)
        return false if VciCollector.busy?
        p = VciCollector.pathify(path)
        return false unless p && Real.basename(p) == ".simplecov"
        abs = VciCollector.expand(p)
        return false if abs.nil? || VciCollector.inside?(VciCollector.resolve(abs), VciCollector.repo)
        SIMPLECOV_CONFIG_FRAME.match?(VciCollector.quiet { VciCollector.frame })
      rescue StandardError
        false
      end
    end

    module OptionsHook
      def initialize(*args, **kw, &blk)
        super
        VciCollector::RSpecSupport.instance_variable_set(:@options, self)
      end
    end

    module SeedHook
      def self.default!(manager)
        return unless manager
        manager.instance_variable_set(:@seed, 0) unless manager.instance_variable_get(:@seed_forced)
      end

      def initialize(*args, **kw, &blk)
        super
        SeedHook.default!(self)
      end
    end

    module ConfigHook
      def example_status_persistence_file_path=(value)
        super(value.nil? ? nil : VciCollector::RSpecSupport.status_file)
      end
    end

    module ReporterHook
      def start(*args, **kw, &blk)
        VciCollector::RSpecSupport.count(:started)
        super
      end

      def example_passed(example)
        VciCollector::RSpecSupport.count(:passed)
        VciCollector::RSpecSupport.reported_passed(example)
        super
      end

      def example_failed(example)
        VciCollector::RSpecSupport.count(:failed)
        super
      end

      def example_pending(example)
        VciCollector::RSpecSupport.count(:pending)
        super
      end

      def notify_non_example_exception(exception, context_description)
        VciCollector::RSpecSupport.count(:errors)
        VciCollector::RSpecSupport.errors << context_description.to_s
        super
      end

      def finish(*args, **kw, &blk)
        VciCollector::RSpecSupport.count(:finished)
        super
      end
    end

    # Example#set_exception and set_aggregate_failures_exception both store
    # the failure through display_exception=; for a pending example it goes
    # to execution_result.pending_exception instead (@exception stays nil).
    module ExampleHook
      def display_exception=(ex)
        super
        VciCollector::RSpecSupport.example_failed!(self) if ex && instance_variable_get(:@exception)
      end
    end

    # Every example the loaded files declare, before filtering (RSpec
    # clears its groups when every example was filtered out).
    module WorldHook
      def announce_filters(*args, **kw, &blk)
        begin
          n = all_examples.size
          VciCollector::RSpecSupport.declared = n if n > VciCollector::RSpecSupport.declared.to_i
        rescue StandardError
          nil
        end
        super
      end
    end
  end
end

# The first at_exit handler registered runs last: after Minitest's.
at_exit do
  status = VciCollector.exit_status($!)
  begin
    next unless Process.pid == VciCollector.pid
    case VciCollector::MODE
    when "collect"
      # A batch whose runner never asked for one of its files through the
      # runner's own loader (Batch.gate): nothing here is attributable.
      next VciCollector::Batch.undriven! if VciCollector::Batch.on? && !VciCollector::Batch.target
      VciCollector::Output.write!(status)
    when "probe" then VciCollector::Probe.print!
    end
  rescue Exception => e # rubocop:disable Lint/RescueException
    $stderr.puts "vci_collector: #{e.class}: #{e.message}"
    $stderr.puts e.backtrace.first(8)
  end
end

module VciCollector
  module Json
    module_function

    def str(s)
      s = s.to_s
      s = s.encode("UTF-8", invalid: :replace, undef: :replace) unless s.encoding == Encoding::UTF_8 && s.valid_encoding?
      out = +"\""
      s.each_char do |c|
        out << case c
               when "\"" then "\\\""
               when "\\" then "\\\\"
               when "\n" then "\\n"
               when "\r" then "\\r"
               when "\t" then "\\t"
               else c.ord < 0x20 ? format("\\u%04x", c.ord) : c
               end
      end
      out << "\""
    end

    def dump(v)
      case v
      when Hash then "{" + v.map { |k, x| "#{str(k)}:#{dump(x)}" }.join(",") + "}"
      when Array then "[" + v.map { |x| dump(x) }.join(",") + "]"
      when Integer then v.to_s
      when true then "true"
      when false then "false"
      when nil then "null"
      else str(v)
      end
    end
  end

  # The bundle: every spec Bundler activated.
  module Gems
    module_function

    def specs
      @specs ||= ::Gem.loaded_specs.values.uniq(&:full_name)
    end

    # The bundle Bundler resolved for this platform (the toolchain's gem set).
    def bundle
      if defined?(::Bundler) && ::Bundler.respond_to?(:load)
        ::Bundler.load.specs.to_a.uniq(&:full_name)
      else
        specs
      end
    rescue StandardError
      specs
    end

    # [[dir, spec]], longest first.
    def dirs
      @dirs ||= specs.flat_map do |s|
        d = []
        d << [File.expand_path(s.full_gem_path), s] if s.full_gem_path
        d << [File.expand_path(s.extension_dir), s] if s.respond_to?(:extension_dir) && s.extension_dir
        d
      end.sort_by { |p, _| -p.length }
    end

    # Directories RubyGems and Bundler install gems into (with the
    # directory of a bundle installed with a path, bundle_base), and their
    # caches. Inside the repository too: a bundle installed there
    # (vendor/bundle) is gems, identified by name and version, never
    # repository files.
    def roots
      @roots ||= begin
        r = ::Gem.path.dup
        r << ::Gem.default_dir
        r << ::Gem.user_dir if ::Gem.respond_to?(:user_dir)
        r << ::Gem.spec_cache_dir if ::Gem.respond_to?(:spec_cache_dir)
        r << ::Bundler.bundle_path.to_s if defined?(::Bundler) && ::Bundler.respond_to?(:bundle_path)
        r << bundle_base
        r << ::Bundler.user_cache.to_s if defined?(::Bundler) && ::Bundler.respond_to?(:user_cache)
        r.compact.map { |x| File.expand_path(x) }.uniq
      rescue StandardError
        ::Gem.path
      end
    end

    def spec_for(abs)
      dirs.each { |d, s| return s if VciCollector.inside?(abs, d) }
      nil
    end

    # The loaded gem of that full name, or nil.
    def named(full_name)
      (@named ||= specs.to_h { |s| [s.full_name, s] })[full_name]
    end

    def under_root?(abs)
      roots.any? { |r| VciCollector.inside?(abs, r) }
    end

    # Gem installation directories (GEM_HOME's layout: specifications/,
    # gems/, extensions/, ...): the bundle's, and every one RubyGems knows.
    def homes
      @homes ||= begin
        h = ::Gem.path.dup
        h << ::Gem.default_dir
        h << ::Gem.user_dir if ::Gem.respond_to?(:user_dir)
        h << ::Bundler.bundle_path.to_s if defined?(::Bundler) && ::Bundler.respond_to?(:bundle_path)
        h.compact.map { |x| File.expand_path(x) }.uniq
      rescue StandardError
        ::Gem.path
      end
    end

    GEMSPEC = %r{\Aspecifications/(default/)?[^/]+\.gemspec\z}
    BUILD_INFO = %r{\Abuild_info/[^/]+\.info\z}
    LISTED = %w[specifications specifications/default].freeze

    # What RubyGems and Bundler do under a gem root on their own account,
    # whatever is installed there: check whether and what each path is
    # (finding the gem that holds a required file, gem.build_complete
    # markers, the directories of every installation), list each
    # installation's specifications, and read every installed .gemspec
    # (RubyGems reads the stub line at the top of each one to know what is
    # installed) and build_info file. Not the content or the listing of
    # anything in a gem's directory: a file of a gem of the bundle is that
    # gem's (Output.classify), and one of any other gem is not RubyGems'
    # bookkeeping, whichever of their helpers reads it (Gem.read_binary,
    # Bundler.read_file, Gem::Util.glob_files_in_dir, Gem::Specification.load
    # of a file that is not an installed .gemspec).
    def bookkeeping?(kind, abs)
      return true if kind == :stat || kind == :probe
      vc = VciCollector
      homes.any? do |h|
        next false unless vc.inside?(abs, h) && abs != h
        rel = abs[(h.length + 1)..].to_s
        kind == :readdir ? LISTED.include?(rel) : GEMSPEC.match?(rel) || BUILD_INFO.match?(rel)
      end
    end

    # A .gemspec that code other than RubyGems' and Bundler's own may have
    # them evaluate (Gem::Specification.load runs its code): one of a gem of
    # the bundle (pinned by its version), of Ruby's own default gems, or of
    # Bundler itself (both part of the toolchain). Any other installed
    # gemspec holds whatever this machine has installed.
    def evaluated_gemspec?(abs)
      vc = VciCollector
      @gemspecs ||= specs.flat_map do |s|
        next [] unless s.loaded_from
        f = File.expand_path(s.loaded_from)
        [f, vc.real_of(f)]
      end
      return true if @gemspecs.include?(abs) || @gemspecs.include?(vc.real_of(abs))
      dd = ::Gem.respond_to?(:default_specifications_dir) ? File.expand_path(::Gem.default_specifications_dir) : nil
      return true if dd && vc.inside?(abs, dd)
      File.basename(abs).match?(/\Abundler-\d[^\/]*\.gemspec\z/)
    rescue StandardError
      false
    end

    # The directory Bundler installs a bundle with a path into
    # (BUNDLE_PATH=vendor/bundle, `bundle config set path vendor/bundle`):
    # it installs into <path>/ruby/<abi>, so everything there is installed
    # gems (another Ruby's, a stale install), never repository files. nil
    # for system gems, and for a path that holds the repository or the
    # project (every file would be under it).
    def bundle_base
      return nil unless defined?(::Bundler) && ::Bundler.respond_to?(:configured_bundle_path)
      cfg = ::Bundler.configured_bundle_path
      return nil if cfg.respond_to?(:use_system_gems?) && cfg.use_system_gems?
      base = File.expand_path(cfg.base_path.to_s, ::Bundler.root.to_s)
      vc = VciCollector
      return nil if vc.inside?(vc.repo, base) || vc.inside?(vc.root, base)
      base
    rescue StandardError
      nil
    end

    def source_of(s)
      src = s.respond_to?(:source) ? s.source : nil
      n = src.class.name.to_s
      if n.end_with?("::Git")
        "git #{src.revision}"
      elsif n.end_with?("::Path") || n.end_with?("::Gemspec")
        "path #{src.respond_to?(:expanded_original_path) ? src.expanded_original_path : src.path}"
      else
        ""
      end
    rescue StandardError => e
      "unknown #{e.class}"
    end

    # The version vci records: the gem's version, and for a git source its
    # locked revision. Not the platform: a native gem's builds for macOS
    # and Linux of one version are accepted as the same external (every
    # platform's build is pinned by Gemfile.lock, a global input).
    def version_of(s)
      src = source_of(s)
      src.start_with?("git ") ? "#{s.version} #{src}" : s.version.to_s
    end
  end

  # Time zone data: the system zoneinfo directory (or tzinfo-data).
  module Tz
    module_function

    SYSTEM_DIRS = %w[/usr/share/zoneinfo /usr/share/lib/zoneinfo /etc/zoneinfo /usr/share/misc/iso3166.tab
                     /usr/share/misc/iso3166].freeze

    def dirs
      d = SYSTEM_DIRS.dup
      if defined?(::TZInfo::DataSource) && (ds = (::TZInfo::DataSource.get rescue nil)) && ds.respond_to?(:zoneinfo_dir)
        d << ds.zoneinfo_dir.to_s
      end
      d.uniq
    end

    # "tzinfo-data" or "zoneinfo <version>" ("" when TZInfo is not loaded).
    def source
      @source ||= compute_source
    end

    def compute_source
      return "" unless defined?(::TZInfo::DataSource)
      ds = ::TZInfo::DataSource.get
      return "tzinfo-data" unless ds.respond_to?(:zoneinfo_dir)
      dir = ds.zoneinfo_dir.to_s
      v = (File.read(File.join(dir, "+VERSION")).strip rescue nil)
      v ||= (File.foreach(File.join(dir, "tzdata.zi")).first.to_s[/version\s+(\S+)/, 1] rescue nil)
      "zoneinfo #{v || "unknown"}"
    rescue StandardError => e
      "unknown #{e.class}"
    end
  end

  module Env
    # Read in C, before the collector loads or on every Time operation.
    ALWAYS_READ = %w[TZ RUBYLIB RUBY_YJIT_ENABLE RUBY_GC_HEAP_INIT_SLOTS RUBY_THREAD_VM_STACK_SIZE
                     RUBY_FREE_AT_EXIT RUBY_CRASH_REPORT RUBYGEMS_GEMDEPS RUBY_BOX RUBY_PAGER].freeze

    # Whole-environment reads by tooling whose result does not reach the
    # tests: Bundler keeps a copy of the environment to restore it for child
    # processes (environment_preserver.rb: to_hash, and replace to add its
    # BUNDLER_ORIG_* copies), and selects its BUNDLE_* settings from it
    # (settings.rb: to_h). BUNDLE_* variables are hashed whenever present.
    ALLOWED = [
      [%r{/bundler/environment_preserver\.rb\z}, %w[to_hash replace]],
      [%r{/bundler/settings\.rb\z}, %w[to_h]]
    ].freeze

    module_function

    def allowed_enumeration?(where, meth)
      return false if VciCollector.inside?(where, VciCollector.repo)
      ALLOWED.any? { |re, meths| re.match?(where) && meths.include?(meth) }
    end
  end

  module Output
    module_function

    # vci's temp dirs, as given and as real paths.
    def ignored_prefixes
      @ignored_prefixes ||= [TMP_ROOT, OUT].compact.reject(&:empty?).flat_map do |p|
        both(p)
      end.uniq
    end

    # A directory as given (expanded) and as its real path: a path the
    # process used may be spelt either way.
    def both(dir)
      d = File.expand_path(dir)
      [d, (File.realpath(d) rescue d)].uniq
    end

    # Ruby's own library directories, covered by the Ruby version. Not
    # site_ruby or vendor_ruby: anyone can add files there.
    def ruby_dirs
      @ruby_dirs ||= %w[rubylibdir rubyarchdir rubyhdrdir].map do |k|
        RbConfig::CONFIG[k]
      end.compact.reject(&:empty?).flat_map { |d| both(d) }.uniq
    end

    def tz_dirs
      @tz_dirs ||= Tz.dirs.flat_map { |d| both(d) }.uniq
    end

    # Standard $LOAD_PATH entries (site_ruby and vendor_ruby included: they
    # are on every Ruby's load path; a file loaded from them is a read
    # outside the repository).
    def ruby_load_dirs
      @ruby_load_dirs ||= (ruby_dirs + %w[sitedir sitelibdir sitearchdir vendordir vendorlibdir vendorarchdir].map do |k|
        RbConfig::CONFIG[k]
      end.compact.reject(&:empty?).map { |d| File.expand_path(d) }).uniq
    end

    DEVICES = %w[/dev/null /dev/urandom /dev/random /dev/zero /dev/tty /dev/stdin /dev/stdout /dev/stderr].freeze

    # A directory above one of vci's temp dirs, outside the repository
    # (`/`, `/private/var/...`): creating a path in the temp dir component
    # by component (rspec-support's DirectoryMaker.mkdir_p, used for the
    # example status file) checks that each one is a directory. That is
    # not an input (dropped in RSpec processes, which always create that
    # file; Minitest processes are unchanged).
    def temp_ancestor?(abs)
      return false if VciCollector.inside?(abs, VciCollector.repo)
      prefix = abs == "/" ? "/" : "#{abs}/"
      ignored_prefixes.any? { |p| p.start_with?(prefix) }
    end

    # Bundler's settings files (their effect, the resolved bundle, is
    # recorded instead).
    def bundler_config?(abs)
      abs.end_with?("/.bundle/config") || abs.include?("/.bundle/plugin/") ||
        (ENV["BUNDLE_APP_CONFIG"] && VciCollector.inside?(abs, File.expand_path(ENV["BUNDLE_APP_CONFIG"])))
    end

    def device?(abs)
      DEVICES.include?(abs) || abs.start_with?("/dev/fd/")
    end

    # nil (not an input), [:external, spec], [:outside_bundle, nil], [:path, abs]
    #
    # Every exemption (vci's temp dirs, the zone database, Ruby's own
    # directories) holds for where the path really leads, not for how it is
    # spelt: through a symlink there, a path naming a repository file is
    # that file (VciCollector.resolve recorded it so when it was used, as
    # the link may be gone now), and one leading anywhere else is classified
    # as what it leads to (a read outside the repository: refused).
    #
    # Each path is classified once per process (classified), and a batch's
    # file process starts with what its boot (or slot) had classified for
    # every path recorded before the file's process forked (Batch.share!).
    def classify(abs, depth = 0)
      return classify_now(abs, depth) unless depth.zero?
      known = classified[abs]
      if known
        c = unpack(known)
        return c unless c == :miss
      end
      c = classify_now(abs, 0)
      classified[abs] = pack(c)
      c
    end

    # abs => a classification as pack makes it (Marshal can carry it from a
    # batch's shared-output process back to its parent: a gem by its full
    # name, looked up again where it is used).
    def classified
      @classified ||= {}
    end

    def learn(classifications)
      classified.merge!(classifications) if classifications.is_a?(Hash)
    end

    def pack(c)
      return :none if c.nil?
      c[0] == :external ? [:external, c[1].full_name] : c
    end

    # A packed classification, or :miss (a gem this process does not have).
    def unpack(m)
      return nil if m == :none
      return m unless m[0] == :external
      s = Gems.named(m[1])
      s ? [:external, s] : :miss
    end

    def classify_now(abs, depth)
      return nil if device?(abs)
      vc = VciCollector
      inside = vc.inside?(abs, vc.repo)
      real = inside ? abs : (vc.reals[abs] || real_of(abs))
      return [:path, real] if !inside && real != abs && vc.inside?(real, vc.repo)
      leads = -> { real == abs || depth.positive? ? nil : classify(real, depth + 1) }
      if ignored_prefixes.any? { |p| vc.inside?(abs, p) }
        return inside ? [:path, abs] : leads.call
      end
      return nil if bundler_config?(abs)
      # RubyGems resolves symlinks in its directories (GEM_PATH through
      # /var -> /private/var): compare the real path too.
      s = Gems.spec_for(abs) || (real != abs && Gems.spec_for(real))
      if s
        # A path gem inside the repository is repository code: hash it.
        local = Gems.source_of(s).start_with?("path ") && inside
        return [:external, s] unless local
      end
      return [:outside_bundle, nil] if Gems.under_root?(abs) || (real != abs && Gems.under_root?(real))
      # The system zone database, when TZInfo uses it: its version is part of
      # the toolchain (Tz.source). With tzinfo-data it is not, so a read
      # there is an input outside the repository.
      return leads.call if Tz.source.start_with?("zoneinfo ") && tz_dirs.any? { |d| vc.inside?(abs, d) }
      return leads.call if !inside && ruby_dirs.any? { |d| vc.inside?(abs, d) }
      [:path, inside ? abs : real]
    end

    # The real path of `abs`, or of its nearest existing ancestor joined
    # with the rest (an absent path).
    def real_of(abs)
      VciCollector.real_of(abs)
    end

    def write!(status)
      unless OUT && VciCollector.test_id
        $stderr.puts "vci_collector: VCI_OUT or VCI_TEST_ID not set; nothing written"
        return
      end
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      # The schema files of the test databases (DB.schema_files).
      VciCollector.quiet { DB.schema_files }.each { |f| VciCollector.schema_input(f) }
      # First: what is written below requires libraries (and would hook them).
      unhooked = VciCollector.unhooked
      TP_COMPILED.disable
      TP_RAISE.disable
      VciCollector.quiet { write_records(status, unhooked, started) }
    end

    # A record under a gem root (classify: :outside_bundle) that is not an
    # input, wherever the bundle is installed (outside the repository, or in
    # it: BUNDLE_PATH=vendor/bundle, which ruby/setup-ruby's bundler-cache
    # sets). What is installed is recorded instead (the resolved bundle,
    # every loaded gem's version, which Gemfile.lock pins):
    # - RubyGems' and Bundler's own bookkeeping (VciCollector.add marked it
    #   :tooling or :gemspec_load), as Gems.bookkeeping? and
    #   Gems.evaluated_gemspec? narrow it. Not anything else they read, list
    #   or check for a caller: Gem.read_binary, Bundler.read_file,
    #   Gem::Util.glob_files_in_dir or Gem::Specification.load called by a
    #   test on a file of a gem that is not in the bundle (refused, as when
    #   the test reads it itself);
    # - the type checks realpath makes of each directory above a gem of the
    #   bundle (vendor/bundle, vendor/bundle/ruby/3.4.0, .../gems), when the
    #   code asking is not the repository's (Rails::Engine.find_root, in
    #   railties, does it for every engine). The same checks made by a test
    #   (File.directory?("vendor/bundle"), File.realpath of a gem's
    #   directory) are refused: where gems are installed differs between
    #   machines, and Bundler's settings that decide it are not inputs.
    def bundle_bookkeeping?(kind, by, abs)
      return Gems.bookkeeping?(kind, abs) if by == :tooling
      return Gems.bookkeeping?(kind, abs) && Gems.evaluated_gemspec?(abs) if by == :gemspec_load
      return false unless by.is_a?(Array) && by[0] == :realpath && kind == :stat
      vc = VciCollector
      by[1].all? do |target, where|
        next false unless Gems.spec_for(target) && vc.inside?(target, abs)
        next true unless vc.inside?(where, vc.repo)
        s = Gems.spec_for(where)
        !s.nil? && !Gems.source_of(s).start_with?("path ")
      end
    end

    # The output file: every line of `lines_of`, or, in a batch's file
    # process whose boot (or slot) wrote the lines its files share
    # (Batch.share!), the lines that are not among them, the shared part's
    # name and which of its lines are not this file's (Batch.split). vci
    # puts the two together again (rails.rs, read_batch).
    def write_records(status, unhooked = [], started = nil)
      lines = lines_of(status, unhooked)
      split = Batch.split(lines)
      require "digest/sha2"
      File.open(File.join(OUT, "#{Digest::SHA256.hexdigest(VciCollector.test_id)}.jsonl"), "w") do |f|
        (split || lines).each { |l| f.write(Json.dump(l), "\n") }
      end
      Batch.wrote_output(lines.size, split, started) if started
    end

    # Every line of the output of this process if it ended now (with exit
    # status `status`): meta, what it observed, its taints and its result.
    # `shared`: the lines a batch's files share (Batch.share!), as the
    # process their processes fork from has them: no meta, no taints (all
    # of a file's taints stay in its own output, in their order) and no
    # result, each line once; the gems' files are checked against their
    # archives (GemVerify.check remembers it for the files' processes).
    def lines_of(status, unhooked = [], shared: false)
      vc = VciCollector
      taints = vc.taints.dup + unhooked
      lines = shared ? [] : [meta]
      vc.enumerations.each do |where, meth|
        next if Env.allowed_enumeration?(where, meth)
        lines << { kind: "env", key: "*", where: "ENV.#{meth} at #{where}" }
      end
      written = vc.written
      externals = {}
      gem_files = {}
      seen = {}
      records = vc.records.to_a
      # Native extensions are loaded without a script_compiled event.
      $LOADED_FEATURES.each do |f|
        records << [[:module, f], true] if f.is_a?(String) && f.start_with?("/") && DLEXTS.any? { |x| f.end_with?(x) }
      end
      # The test environment's SQLite files (and their -wal, -shm and
      # -journal siblings) are the test engine's database: nothing about
      # them is an input (see DB.exempt).
      dbx = DB.exempt
      listed = {}
      records.each do |(kind, abs), by|
        next if kind == :write
        next if kind == :stat && RUNNER == "rspec" && temp_ancestor?(abs)
        # Not code: a Ruby file loaded from such a path is still an input.
        next if kind != :module && DB.exempt?(kind, abs)
        c = classify(abs)
        next unless c
        next if kind != :module && c[0] == :path && DB.exempt?(kind, c[1])
        # RubyGems' and Bundler's existence and type checks and listings
        # outside the repository (anywhere but under a gem root) are not
        # inputs (see TOOLING_FILES).
        next if by == :tooling && kind != :read && c[0] != :outside_bundle && !vc.inside?(abs, vc.repo)
        case c[0]
        when :external
          s = c[1]
          if %i[module read readdir].include?(kind)
            externals[[s.name, Gems.version_of(s)]] = s
            (gem_files[s.full_name] ||= []) << abs if kind != :readdir
          end
          next
        when :outside_bundle
          # Code loaded from an installed gem that is not in the bundle. Other
          # reads and checks there are RubyGems' and Bundler's bookkeeping
          # (specifications, caches) when they make them; anything else
          # depends on what happens to be installed on this machine.
          if kind == :module
            taints << "ruby:gem-outside-bundle:#{abs}"
          elsif !bundle_bookkeeping?(kind, by, abs)
            taints << "ruby:read-outside-bundle:#{kind} #{abs} (under a gem directory, not a gem of the bundle: what is installed there differs between machines)"
          end
          next
        end
        p = c[1]
        # Reads and checks of a file after this process created or replaced
        # it were never recorded (VciCollector.add); earlier ones are inputs.
        # The type or size of a log it appends to is not an input.
        next if kind == :stat && written[p] && vc.inside?(p, File.join(vc.root, "log"))
        next if kind == :probe && written.key?(p)
        if kind == :module && DLEXTS.any? { |x| p.end_with?(x) } && vc.inside?(p, vc.repo)
          taints << "native-extension-in-repository:#{p}"
        end
        next if seen[[kind, p]]
        seen[[kind, p]] = true
        listed[p] = true if kind == :readdir
        lines << { kind: kind.to_s, path: p }
      end
      # Many absent paths under one directory (load path probes): its
      # listing instead (fold_probes).
      lines = fold_probes(lines, seen, listed, written)
      # A listing of the directory holding one leaves it out (it is not in
      # a fresh checkout, and comes and goes with the database's journal).
      dbx.each_key do |x|
        next unless vc.inside?(x, vc.repo) && listed[File.dirname(x)] && !seen[[:exclude, x]]
        seen[[:exclude, x]] = true
        lines << { kind: "exclude", path: x }
      end
      written.each_key { |p| lines << { kind: "write", path: p } if vc.inside?(p, vc.repo) && !dbx.key?(p) }
      taints.concat(DB.taints) unless shared
      taints.concat(GemVerify.check(externals.values.uniq, gem_files))
      externals.each do |(name, version), s|
        rec = { kind: "external", name: name, version: version, platform: s.platform.to_s }
        src = Gems.source_of(s)
        rec[:source] = src unless src.empty?
        lines << rec
      end
      # Native libraries FFI opened (see install_ffi): compared with what the
      # probe's process opens where the attestation is checked.
      Native.versions.each { |name, version| lines << { kind: "external", name: name, version: version } }
      keys = vc.env_keys.dup
      Env::ALWAYS_READ.each { |k| keys[k] ||= { "ruby" => true } }
      keys.each { |k, w| lines << { kind: "env", key: k, where: w.keys.first(3).join(" | ") } }
      return lines.uniq if shared
      taints.concat(Checks.run)
      taints.concat(RSpecSupport.taints) if RUNNER == "rspec"
      res = result(status)
      if status != 0 && framework_clean?
        taints << "vci:process-exit:#{status} (the process exited #{status} after the test framework reported a pass: " \
                  "an at_exit handler such as SimpleCov's minimum_coverage failed the run)"
      end
      taints.uniq.each { |t| lines << { kind: "taint", reason: t } }
      lines << res
    end

    # --- absent paths folded into a listing ----------------------------------
    #
    # `require "x/y"` makes Ruby stat <entry>/x/y.rb, .so and .bundle in
    # every $LOAD_PATH entry ahead of the one that has it, and
    # VciCollector.lookup / missing_feature record each one inside the
    # repository as a probe (a file created there later would be loaded
    # instead). An application with lib/ and vendor/ on its load path gets
    # thousands: vex-api about 10,000 a file (5,000 under lib, 5,000 under
    # vendor), 70 % of its manifest's entries.
    #
    # Probes whose fold_target is the same directory D, FOLD_MIN or more of
    # them, are recorded as D's listing instead. D is the deepest real
    # directory above the probe, and the path's component just below D (its
    # `child`: the probe itself, or the first missing directory on the way
    # to it, lib/abstract_controller for lib/abstract_controller/
    # asset_paths.rb) is absent. Any change that makes such a path exist
    # creates that child, a new name in D's listing, so the listing changes
    # whenever one of the probes would: it can only re-run more (a file
    # added to D that no probe named), never less. It is listed at exit, as
    # every listing is (vci hashes what D holds when it builds the manifest).
    #
    # Every absent path in the repository counts, a test's own
    # File.exist?("lib/x") as much as a load path probe: the records do not
    # say who made them, and folding one into a listing D already gets is
    # as sound for one as for the other. Not folded (left as probes):
    # - fewer than FOLD_MIN under D (a few probes are cheaper, and re-run
    #   less, than a listing);
    # - a probe whose path exists now, or whose path below D runs through a
    #   file or a symlink (a symlink's target can change without D's listing
    #   changing), or any directory from the repository to D that is a
    #   symlink;
    # - D under vci's temp dirs, a directory this process wrote in (its
    #   listing changes during the run), or one whose listing is exempt
    #   (DB.exempt?);
    # - D holding a test file of this process (a batch's: any of its files),
    #   unless the process lists D anyway: RSpec puts spec/ first on the load
    #   path (thousands of probes there), and a listing of spec/ (or test/,
    #   or the repository's root) would run every test whenever a test file
    #   is added, the most common change there is. lib/ and vendor/ (Rails
    #   puts both on the load path) hold none; lib/ is usually listed
    #   already (Zeitwerk's autoload_lib), so folding there costs nothing;
    # - a probe whose child git ignores (as a file or as a directory): vci
    #   leaves git-ignored children out of a listing (2.0.3), so creating it
    #   would not change D's listing. One `git check-ignore` a process for
    #   the children it has not asked about; when git does not answer
    #   nothing is folded.
    FOLD_MIN = 50

    def fold_probes(lines, seen, listed, written)
      vc = VciCollector
      repo = vc.repo
      return lines unless repo && !repo.empty?
      lstats = {}
      groups = {}
      lines.each_with_index do |l, i|
        next unless l[:kind] == "probe"
        d, child = fold_target(l[:path], repo, lstats)
        (groups[d] ||= []) << [i, child] if d
      end
      groups.select! { |d, ps| ps.size >= FOLD_MIN && foldable_dir?(d, repo, written, lstats, seen) }
      return lines if groups.empty?
      ignored = ignored_children(groups.values.flat_map { |ps| ps.map(&:last) }.uniq, repo)
      return lines unless ignored
      drop = {}
      insert = {}
      groups.each do |d, ps|
        ps = ps.reject { |_, c| ignored[c] }
        next if ps.size < FOLD_MIN
        ps.each { |i, _| drop[i] = true }
        listed[d] = true
        next if seen[[:readdir, d]]
        seen[[:readdir, d]] = true
        insert[ps[0][0]] = { kind: "readdir", path: d }
      end
      return lines if drop.empty?
      out = []
      lines.each_with_index do |l, i|
        out << insert[i] if insert[i]
        out << l unless drop[i]
      end
      out
    end

    # [D, child] for an absent path `p` in the repository (see fold_probes),
    # or nil.
    def fold_target(p, repo, lstats)
      vc = VciCollector
      return nil unless p != repo && vc.inside?(p, repo)
      return nil if lstat_of(p, lstats)
      child = p
      loop do
        parent = Real.dirname(child)
        return nil if parent == child || !vc.inside?(parent, repo)
        st = lstat_of(parent, lstats)
        return st.directory? ? [parent, child] : nil if st
        child = parent
      end
    end

    def foldable_dir?(d, repo, written, lstats, seen)
      vc = VciCollector
      return false unless classify(d) == [:path, d]
      return false if !seen[[:readdir, d]] && test_files.any? { |t| vc.inside?(t, d) }
      return false if DB.exempt?(:readdir, d) || ignored_prefixes.any? { |x| vc.inside?(d, x) }
      return false if written.each_key.any? { |w| vc.inside?(w, d) }
      cur = d
      while vc.inside?(cur, repo)
        st = lstat_of(cur, lstats)
        return false unless st&.directory?
        break if cur == repo
        cur = Real.dirname(cur)
      end
      true
    end

    # The test files of this process (a batch's: all of them), absolute.
    def test_files
      @test_files ||= ((BATCH_IDS || []) + [VciCollector.test_id]).compact.uniq.map do |id|
        Real.expand_path(id, VciCollector.root)
      end
    end

    def lstat_of(p, lstats)
      lstats.fetch(p) do
        lstats[p] = begin
          Real.lstat(p)
        rescue SystemCallError
          nil
        end
      end
    end

    # child => whether git ignores it (as a file or as a directory), for
    # every child asked about so far in this process (and, in a batch's
    # file process, by the process it forked from: Batch.share!); nil when
    # git did not answer.
    def ignored_children(children, repo)
      ask = children.reject { |c| ignore_memo.key?(c) }
      unless ask.empty?
        got = git_check_ignore(repo, ask.flat_map { |c| [c, "#{c}/"] })
        return nil unless got
        ask.each { |c| ignore_memo[c] = got.key?(c) || got.key?("#{c}/") }
      end
      ignore_memo
    end

    def ignore_memo
      @ignore_memo ||= {}
    end

    def learn_ignored(memo)
      ignore_memo.merge!(memo) if memo.is_a?(Hash)
    end

    # The `paths` (absolute, in the repository) git ignores, as a Hash of
    # path => true; nil unless git answered (exit 0: some, 1: none).
    def git_check_ignore(repo, paths)
      out = nil
      Real.popen(["git", "-C", repo, "check-ignore", "--stdin", "-z"], "r+", err: File::NULL) do |io|
        writer = Thread.new do
          VciCollector.quiet do
            io.write(paths.map { |p| "#{p}\0" }.join)
            io.close_write
          end
        end
        out = io.read
        writer.join
      end
      return nil unless [0, 1].include?($?&.exitstatus)
      out.to_s.split("\0").to_h { |p| [p, true] }
    rescue StandardError, NotImplementedError
      nil
    end

    def meta
      {
        v: 1, kind: "meta", testId: VciCollector.test_id, adapter: "rails",
        ruby: Probe.ruby_version, engine: Probe.engine,
        rails: Probe.rails_version, bundler: Probe.bundler_version, runner: Probe.runner_version,
        root: VciCollector.root, platform: RUBY_PLATFORM, collector: "vci_collector@#{VERSION}",
        db: DB.adapters, tz: Tz.source
      }
    end

    # The test framework reported results and no failure or error among
    # them (what a non-zero exit then came from is something else).
    def framework_clean?
      if RUNNER == "rspec"
        c = RSpecSupport.counts
        c[:started].positive? && (c[:failed] + c[:errors]).zero?
      else
        mt = VciCollector.instance_variable_get(:@minitest)
        !mt.nil? && (mt.failures + mt.errors).zero?
      end
    end

    def result(status)
      return RSpecSupport.result(status) if RUNNER == "rspec"
      mt = VciCollector.instance_variable_get(:@minitest)
      unless mt
        return { kind: "result", state: "failed", tests: 0, failed: 1, skipped: 0, durationMs: 0,
                 exitStatus: status, why: "no Minitest results (not a Minitest file, or it never ran)" }
      end
      failed = mt.failures + mt.errors
      state = if failed.positive? || status != 0 then "failed"
              elsif mt.count.zero? then "no-tests"
              elsif mt.skips.positive? then "passed"
              elsif mt.no_assertions.positive? || mt.assertions.zero? then "no-assertions"
              else "passed"
              end
      { kind: "result", state: state, tests: mt.count, failed: failed.positive? || status.zero? ? failed : 1,
        skipped: mt.skips, assertions: mt.assertions, noAssertions: mt.no_assertions,
        durationMs: mt.duration_ms, exitStatus: status }
    end
  end

  # Gems are identified by name and version; this checks that what was
  # loaded is what that version is. For every gem a test used: the gem's
  # archive in the RubyGems cache must have the sha256 Gemfile.lock records
  # (CHECKSUMS), and every file of the gem the test loaded or read must be
  # the archive's copy (a hot-patched installed gem taints). Files a gem
  # compiles at install time (extensions built from source) are not in the
  # archive and are covered by the version only.
  module GemVerify
    module_function

    def lock_checksums
      @lock_checksums ||= begin
        lock = (::Bundler.default_lockfile.to_s rescue nil)
        out = {}
        if lock && File.file?(lock)
          in_section = false
          File.foreach(lock) do |line|
            if line.start_with?("CHECKSUMS")
              in_section = true
              next
            end
            in_section = false if in_section && !line.start_with?(" ")
            next unless in_section
            m = line.match(/\A\s+(\S+) \(([^)]+)\)(?: sha256=([0-9a-f]{64}))?/)
            out["#{m[1]}-#{m[2]}"] = m[3] if m && m[3]
          end
        end
        out
      end
    end

    # What earlier checks in this process found (a batch's file process
    # starts with its boot's or slot's, Batch.share!): a gem's own problems
    # (full name => taints: no archive, a checksum Gemfile.lock does not
    # have) and its files' ([full name, path] => [taint or nil, the file's
    # place in the archive or nil]). A file is compared once.
    def done
      @done ||= { gems: {}, files: {} }
    end

    def learn(found)
      return unless found.is_a?(Hash)
      done[:gems].merge!(found[:gems] || {})
      done[:files].merge!(found[:files] || {})
    end

    def check(specs, files_by_gem)
      return [] if specs.empty?
      require "rubygems/package"
      require "zlib"
      require "digest/sha2"
      out = []
      specs.each do |s|
        next if s.respond_to?(:default_gem?) && s.default_gem?
        src = Gems.source_of(s)
        next if src.start_with?("path ")
        if src.start_with?("git ")
          out << "ruby:git-gem-without-revision:#{s.name}" if src.strip == "git"
          next # a git checkout is compared to its locked revision by vci (see README)
        end
        files = (files_by_gem[s.full_name] || []).uniq
        next if files.empty?
        own = (done[:gems][s.full_name] ||= gem_problems(s))
        unless own.empty?
          out.concat(own)
          next
        end
        known = done[:files]
        todo = files.reject { |f| known.key?([s.full_name, f]) }
        compare(s, s.cache_file, todo).each { |f, r| known[[s.full_name, f]] = r } unless todo.empty?
        # In the order of a comparison of all of them at once: the files
        # that differ, in the archive's order, then those it lacks.
        found = files.filter_map { |f| known[[s.full_name, f]] }.select { |t, _| t }
        out.concat(found.select { |_, at| at }.sort_by { |_, at| at }.map(&:first))
        out.concat(found.reject { |_, at| at }.map(&:first))
      end
      out
    rescue StandardError, LoadError => e
      ["ruby:gem-verify:#{e.class}: #{e.message}"]
    end

    # What is wrong with a gem's archive itself, before any of its files is
    # compared with it: [] or [taint].
    def gem_problems(s)
      archive = s.respond_to?(:cache_file) ? s.cache_file : nil
      unless archive && File.file?(archive)
        return ["ruby:gem-unverifiable:#{s.full_name} (no #{s.full_name}.gem in the RubyGems cache to check its installed files against; reinstall it with `gem install --local` or `bundle install --redownload`)"]
      end
      want = lock_checksums[s.full_name]
      if want && Digest::SHA256.file(archive).hexdigest != want
        return ["ruby:gem-checksum:#{s.full_name} (#{archive} does not have the sha256 Gemfile.lock records)"]
      end
      []
    end

    # Each of `files` => [taint or nil, its place in the archive or nil].
    def compare(spec, archive, files)
      root = File.expand_path(spec.full_gem_path)
      res = files.to_h { |f| [f, [nil, nil]] }
      want = {}
      files.each do |f|
        next unless VciCollector.inside?(f, root) && File.file?(f)
        want[f.delete_prefix("#{root}/")] = f
      end
      return res if want.empty?
      found = {}
      at = 0
      File.open(archive, "rb") do |io|
        ::Gem::Package::TarReader.new(io) do |tar|
          tar.each do |entry|
            next unless entry.full_name == "data.tar.gz"
            ::Zlib::GzipReader.wrap(entry) do |gz|
              ::Gem::Package::TarReader.new(gz) do |data|
                data.each do |f|
                  at += 1
                  path = want[f.full_name]
                  next unless path && f.file?
                  found[f.full_name] = true
                  if f.read != File.binread(path)
                    res[path] = ["ruby:gem-modified:#{spec.full_name}:#{f.full_name} (differs from #{File.basename(archive)})", at]
                  end
                end
              end
            end
          end
        end
      end
      want.each do |rel, path|
        next if found[rel]
        # Built at install time (an extension compiled from source), or added.
        next if rel.end_with?(*DLEXTS) || rel.end_with?("gem.build_complete")
        res[path] = ["ruby:gem-modified:#{spec.full_name}:#{rel} (not in #{File.basename(archive)})", nil]
      end
      res
    end
  end

  module Checks
    module_function

    def run
      out = []
      if RubyVM::InstructionSequence.respond_to?(:load_iseq)
        out << "ruby:iseq-cache (RubyVM::InstructionSequence.load_iseq is defined, e.g. by Bootsnap's compile cache: code may not be compiled from the hashed source; set DISABLE_BOOTSNAP=1)"
      end
      if defined?(::Bootsnap::LoadPathCache) && ::Bootsnap::LoadPathCache.respond_to?(:enabled?) && ::Bootsnap::LoadPathCache.enabled?
        out << "ruby:bootsnap-load-path-cache (requires are answered from a cache; set DISABLE_BOOTSNAP=1)"
      end
      bs = bootsnap_patched
      unless bs.empty?
        out << "ruby:bootsnap-compile-cache (#{bs.join(", ")}: YAML, JSON or compiled code is served from Bootsnap's cache, read in C, not from the file vci hashes; do not call Bootsnap.setup with a compile cache in the test environment)"
      end
      out << "rails:spring (Spring preloads the application in another process)" if defined?(::Spring::Client) || defined?(::Spring::Application)
      VciCollector.expanded_load_path.each do |e|
        next if VciCollector.inside?(e, VciCollector.repo)
        next if Output.ruby_load_dirs.any? { |d| VciCollector.inside?(e, d) }
        next if Gems.spec_for(e) || Gems.under_root?(e)
        next if Output.ignored_prefixes.any? { |p| VciCollector.inside?(e, p) }
        out << "ruby:load-path-outside-repository:#{e}"
      end
      if defined?(::Bundler) && ::Bundler.respond_to?(:default_gemfile)
        gf = (::Bundler.default_gemfile.to_s rescue "")
        unless [File.join(VciCollector.root, "Gemfile"), File.join(VciCollector.root, "gems.rb")].include?(gf)
          out << "ruby:gemfile:#{gf} (the bundle must be the project's Gemfile)"
        end
      else
        out << "ruby:no-bundler (the test did not run under Bundler)"
      end
      Gems.specs.each do |s|
        src = Gems.source_of(s)
        next unless src.start_with?("path ")
        dir = File.expand_path(s.full_gem_path)
        out << "ruby:path-gem-outside-repository:#{s.name} (#{dir})" unless VciCollector.inside?(dir, VciCollector.repo)
      end
      out
    rescue StandardError => e
      ["vci:checks:#{e.class}: #{e.message}"]
    end

    # Bootsnap's compile caches prepend modules to YAML/Psych, JSON and
    # RubyVM::InstructionSequence (Bootsnap.setup installs them whatever
    # DISABLE_BOOTSNAP says).
    def bootsnap_patched
      targets = []
      targets << ["YAML", ::YAML] if defined?(::YAML)
      targets << ["Psych", ::Psych] if defined?(::Psych)
      targets << ["JSON", ::JSON] if defined?(::JSON)
      targets << ["RubyVM::InstructionSequence", ::RubyVM::InstructionSequence]
      out = targets.filter_map do |name, mod|
        name if mod.singleton_class.ancestors.any? { |a| a.name.to_s.start_with?("Bootsnap") }
      end
      if defined?(::Bootsnap::CompileCache)
        %i[ISeq YAML JSON].each do |k|
          next unless ::Bootsnap::CompileCache.const_defined?(k, false)
          c = ::Bootsnap::CompileCache.const_get(k, false)
          out << "Bootsnap::CompileCache::#{k}" if c.respond_to?(:cache_dir) && c.cache_dir
        end
      end
      out.uniq
    rescue StandardError => e
      ["bootsnap check failed: #{e.class}"]
    end
  end

  module Probe
    module_function

    def ruby_version
      "#{RUBY_VERSION}p#{RUBY_PATCHLEVEL}"
    end

    def engine
      "#{RUBY_ENGINE} #{RUBY_ENGINE_VERSION}"
    end

    # The Rails version: Rails::VERSION once Rails is loaded, else the
    # bundle's railties (whose version Rails::VERSION is). A file that never
    # loads Rails (a spec loading only spec_helper, a Minitest file under
    # test/lib requiring only minitest and plain Ruby) reports the same
    # version as the probe, which boots the application; with neither
    # (a project without Rails) it is "", on both sides.
    def rails_version
      return ::Rails::VERSION::STRING if defined?(::Rails::VERSION::STRING)
      spec_version("railties") || ""
    end

    def bundler_version
      defined?(::Bundler::VERSION) ? ::Bundler::VERSION : ""
    end

    RSPEC_GEMS = %w[rspec-core rspec-expectations rspec-mocks rspec-rails rspec-support].freeze

    def spec_version(name)
      s = ::Gem.loaded_specs[name]
      s&.version&.to_s
    rescue StandardError
      nil
    end

    # The test frameworks of the bundle: "minitest 6.0.6", and when the
    # bundle has RSpec, "; rspec-core 3.13.6, rspec-expectations ..., ...".
    # The same in every process of a project (probe, Minitest and RSpec
    # files): taken from the bundle's specs, not from what a file loaded.
    def runner_version
      parts = []
      mt = defined?(::Minitest::VERSION) ? ::Minitest::VERSION : spec_version("minitest")
      parts << "minitest #{mt}" if mt
      rs = RSPEC_GEMS.filter_map { |n| (v = spec_version(n)) && "#{n} #{v}" }
      rs << "rspec-core #{::RSpec::Core::Version::STRING}" if rs.empty? && defined?(::RSpec::Core::Version::STRING)
      parts << rs.join(", ") unless rs.empty?
      parts.join("; ")
    end

    # Libraries whose version the gem versions do not fix. Not OpenSSL: Ruby
    # links the platform's (Homebrew's 3.6 on a Mac, Ubuntu's 3.0 or a 3.5 on a
    # runner), so comparing it would rule out every cross-platform skip; its
    # algorithms compute the same results (see README, "Rails limitations").
    def libs
      l = []
      l << "sqlite=#{::SQLite3::SQLITE_LOADED_VERSION}" if defined?(::SQLite3::SQLITE_LOADED_VERSION)
      l << "yaml=#{::Psych::LIBYAML_VERSION}" if defined?(::Psych::LIBYAML_VERSION)
      l << "tz=#{Tz.source}"
      l << "encoding=#{Encoding.default_external}/#{Encoding.default_internal || "none"}"
      l << "collector=#{VERSION}"
      l.join(";")
    end

    # The probe without booting the application (`vci plan`, and the
    # toolchain `vci run` records): called after `require "bundler/setup"`,
    # which sets up the bundle as in every test process (and fails as they
    # would when it is not installed). For a Rails application (`rails_app`)
    # what booting it loads that the toolchain reports is loaded or read the
    # way booting does: YAML and TZInfo (every Rails application loads both),
    # SQLite3 when Bundler.require(*Rails.groups) requires it, both default
    # encodings set to UTF-8 (Rails' config.encoding), and the adapters of
    # the test environment's databases from config/database.yml as Rails
    # reads it (ERB, `shared`, DATABASE_URL), never the application's code.
    # When config/database.yml cannot be read that way (its ERB uses the
    # application), "db" is null and dbError says why (vci then boots the
    # application for it). `vci run` also boots the application and refuses
    # to attest when the booted application reports anything else.
    def light!(rails_app)
      return unless rails_app
      @light = true
      VciCollector.quiet do
        verbose = $VERBOSE
        $VERBOSE = nil
        Encoding.default_external = Encoding::UTF_8
        Encoding.default_internal = Encoding::UTF_8
        $VERBOSE = verbose
        require "psych"
        begin
          require "tzinfo"
        rescue LoadError
          nil
        end
        @light_db = light_db
        begin
          require "sqlite3" if autorequired?("sqlite3")
        rescue LoadError
          nil
        end
      end
    end

    # The groups Rails' generated config/application.rb requires
    # (Bundler.require(*Rails.groups)): default, the environment, and
    # RAILS_GROUPS.
    def rails_groups
      g = [:default, DB.env_name.to_sym]
      g.concat(ENV["RAILS_GROUPS"].to_s.split(",").map(&:to_sym))
      g.uniq
    end

    # Whether Bundler.require(*Rails.groups) requires `file`: a dependency of
    # those groups (on this platform) autorequires it, or is named so and
    # does not say what to require (Bundler::Runtime#require).
    def autorequired?(file)
      ::Bundler.definition.dependencies_for(rails_groups).any? do |d|
        Array(d.autorequire || d.name).map { |f| f == true ? d.name : f }.include?(file)
      end
    rescue StandardError
      false
    end

    # The test environment's database adapters as DB.adapters reports them
    # after booting: config/database.yml read as
    # Rails::Application::Configuration#database_configuration reads it, with
    # DATABASE_URL merged in by Active Record's DatabaseConfigurations. ""
    # without Active Record in the bundle, or without config/database.yml
    # and DATABASE_URL (an application that does not use Active Record).
    def light_db
      path = File.join(VciCollector.root, "config", "database.yml")
      return "" unless File.exist?(path) || ENV["DATABASE_URL"]
      begin
        require "active_record"
      rescue LoadError
        return ""
      end
      require "active_support/configuration_file"
      require "active_record/database_configurations"
      config = File.exist?(path) ? database_configuration(path) : {}
      configs = ::ActiveRecord::DatabaseConfigurations.new(config)
      list = begin
        configs.configs_for(env_name: DB.env_name, include_hidden: true)
      rescue ArgumentError
        configs.configs_for(env_name: DB.env_name)
      end
      list.map { |c| c.adapter.to_s }.reject(&:empty?).uniq.sort.join(";")
    rescue StandardError, LoadError, SyntaxError => e
      @light_db_error = "#{e.class}: #{e.message}"
      nil
    end

    # Rails::Application::Configuration#database_configuration (Rails 8.1).
    def database_configuration(path)
      loaded = ::ActiveSupport::ConfigurationFile.parse(path)
      if (shared = loaded.delete("shared"))
        loaded.each do |_env, config|
          if config.is_a?(Hash) && config.values.all?(Hash)
            if shared.is_a?(Hash) && shared.values.all?(Hash)
              config.map { |name, sub| sub.reverse_merge!(shared[name]) }
            else
              config.map { |_name, sub| sub.reverse_merge!(shared) }
            end
          else
            config.reverse_merge!(shared)
          end
        end
      end
      Hash.new(shared).merge(loaded)
    end

    def print!
      VciCollector.quiet do
        begin
          require "minitest"
        rescue LoadError
          nil
        end
        gems = Gems.bundle.map do |s|
          { name: s.name, version: Gems.version_of(s), platform: s.platform.to_s, source: Gems.source_of(s) }
        end
        out = {
          ruby: ruby_version, engine: engine, rails: rails_version, bundler: bundler_version,
          runner: runner_version, platform: RUBY_PLATFORM, libs: libs,
          db: @light ? @light_db : DB.adapters(load: true),
          gems: gems, gemfile: (::Bundler.default_gemfile.to_s rescue ""), taints: Checks.run,
          natives: Native.versions.map { |name, version| { name: name, version: version } }
        }
        out[:dbError] = @light_db_error if @light && @light_db.nil?
        $stdout.puts "VCI-PROBE #{Json.dump(out)}"
      end
    end
  end
end

# RSpec processes: SimpleCov's configuration files outside the repository
# look absent (every mode; prepended last, so in front of the collect-mode
# hooks, which therefore record nothing for them).
if VciCollector::RUNNER == "rspec"
  # Pathname#exist? asks FileTest, load_global_config.rb asks File.
  [File.singleton_class, FileTest.singleton_class].each do |t|
    VciCollector::Redefined.watch(t, VciCollector::RSpecSupport::SimpleCovConfigGuard)
    t.prepend(VciCollector::RSpecSupport::SimpleCovConfigGuard)
  end
end

# Whenever a constant one of the hooked libraries defines is set (from Ruby
# or from C, by a require vci saw or not), hook what has appeared.
module VciCollector
  module ConstAdded
    def const_added(name)
      super
      VciCollector.after_require if VciCollector::WATCHED_CONSTANTS[name]
    end
  end
end
Module.prepend(VciCollector::ConstAdded)

VciCollector.after_require
