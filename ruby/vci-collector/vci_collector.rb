# frozen_string_literal: true

# vci_collector: records what one Rails test file (one Ruby process) reads,
# for `vci run` (crates/vci-adapter/src/rails.rs). Findings behind it:
# docs/spike-rails.md.
#
# Loaded with RUBYOPT=-r<abs>/vci_collector.rb, so it runs before bin/rails,
# Bundler, Rails and the test file. Pure Ruby; it requires no gem while the
# tests run (a default gem required early could clash with the version the
# bundle activates later).
#
# Modes (VCI_RAILS_MODE):
#   collect  record everything, write $VCI_OUT/<sha256(VCI_TEST_ID)>.jsonl at exit
#   plain    no recording, only the run conditions `vci run` uses (fresh
#            SQLite databases loaded from the schema, a fresh local secret);
#            used by `vci ci` so CI runs each file the way it was attested
#   probe    print one "VCI-PROBE <json>" line with the toolchain at exit
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

module VciCollector
  # Part of the toolchain (Probe.libs): bumped whenever what the collector
  # records or refuses changes, so an attestation made by an older collector
  # (which may have missed an input) is not accepted where a newer one runs.
  VERSION = "0.3.1"
  MODE = ENV.fetch("VCI_RAILS_MODE", "collect")
  # The test framework vci started this process for: "minitest" (default,
  # `bin/rails test <file>`) or "rspec" (`rspec <file>`, see RSpecSupport).
  RUNNER = ENV["VCI_RAILS_RUNNER"] == "rspec" ? "rspec" : "minitest"
  OUT = ENV["VCI_OUT"]
  TEST_ID = ENV["VCI_TEST_ID"]
  # Fresh directory for this process's SQLite databases.
  DB_DIR = ENV["VCI_DB_DIR"]
  # The fresh temp dir vci gave this process (TMPDIR), read once here: a test
  # that later sets ENV["TMPDIR"] (to "/tmp", HOME, "/") changes where its
  # own temp files go, never which reads the collector treats as vci's
  # scratch space (it would otherwise hide every read under that directory).
  TMP = ENV["TMPDIR"]
  # policy.rails_allow_db: network databases are prepared fresh as well.
  ALLOW_DB = ENV["VCI_RAILS_ALLOW_DB"] == "1"
  DLEXTS = %w[.so .bundle].freeze
  RBEXTS = %w[.rb .so .bundle].freeze
  # Code of RubyGems and Bundler. What they look up decides which gems are
  # loaded and from where; that outcome is recorded (the resolved bundle,
  # every loaded gem's version), so their own bookkeeping is not an input:
  # their reads of TOOLING_ENV variables, and their existence and type checks
  # (never content reads) outside the repository (~/.gem, ~/.bundle, HOME).
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
              fnmatch].to_h { |m| [m, FS.instance_method(m)] }.freeze
    DIR = %i[children pwd].to_h { |m| [m, DS.instance_method(m)] }.freeze

    class << self
      FILE.each_key do |m|
        define_method(m) { |*args| FILE[m].bind_call(::File, *args) }
      end
      DIR.each_key do |m|
        define_method(:"dir_#{m}") { |*args| DIR[m].bind_call(::Dir, *args) }
      end
    end
  end

  # Only the process vci started writes output (a forked child inherits the
  # collector, and its "process:fork" taint).
  PID = Process.pid
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
  @enumerations = [] # [where, method]
  @lp_memo = {}
  @hooks_done = {}

  class << self
    attr_reader :records, :taints, :written, :produced, :env_keys, :enumerations

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

    def expand(p)
      return nil unless p.is_a?(String) && !p.empty? && !p.start_with?("|")
      quiet { Real.expand_path(p) }
    rescue StandardError
      nil
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

    # Record an observation. Outside the repository, RubyGems' and
    # Bundler's existence and type checks are dropped (see TOOLING_FILES),
    # and their content reads are marked as theirs (:tooling): under a gem
    # root outside the bundle only those are not inputs. A read or check of
    # a path whose content is this process's own output is not an input
    # (one made before the process replaced it is).
    def add(kind, abs)
      return unless abs
      return if %i[read stat readdir].include?(kind) && @produced[abs]
      unless inside?(abs, repo)
        return if RESOLV_CONF.include?(abs) && resolv_loading?
        if %i[stat probe readdir read].include?(kind) && quiet { tooling?(frame) }
          return unless kind == :read
          @records[[kind, abs]] ||= :tooling
          return
        end
      end
      @records[[kind, abs]] = true
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

    # Type (and, for a file, content) observed: absent -> probe, else stat.
    def observe_stat(path)
      return unless collect? && !busy?
      abs = expand(pathify(path))
      return unless abs
      exists = quiet { Real.exist?(abs) || Real.symlink?(abs) }
      add(exists ? :stat : :probe, abs)
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
    def wrote(path, produced: false, gone: false)
      return unless collect? && !busy?
      abs = expand(pathify(path))
      return unless abs
      @records[[:write, abs]] = true
      @written[abs] = true
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
      reads, writes, trunc, creat = mode_info(mode, flags)
      unless ok
        add(:probe, abs) if reads || !creat
        return
      end
      remember_inode(abs)
      if writes
        @records[[:write, abs]] = true
        @written[abs] = true
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
              @records[[:probe, c]] = true if inside?(e, repo)
            end
            return
          end
          next unless inside?(e, repo)
          cands.each { |c| @records[[exists_quietly?(c) ? :read : :probe, c]] = true }
        end
      end
    end

    # A failed require / require_relative / load / autoload.
    def missing_feature(path)
      return unless collect? && path.is_a?(String) && !path.empty?
      if relative_feature?(path)
        expanded_load_path.each do |e|
          next unless inside?(e, repo)
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
        start_base = base ? Real.expand_path(pathify(base) || base.to_s) : Real.dir_pwd
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
      abs = quiet { dir ? Real.expand_path(p, pathify(dir) || dir.to_s) : Real.expand_path(p) }
      cur = ""
      abs.split("/").reject(&:empty?).each do |c|
        cur = "#{cur}/#{c}"
        observe_stat(cur) if inside?(cur, repo)
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

module VciCollector
    # `require` of a feature: record the lookup (see VciCollector.lookup),
    # then hook libraries that appeared. The block does the require.
    def self.around_require(path)
      return yield if busy?
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
# File system, process and ENV hooks (collect mode only).
# ---------------------------------------------------------------------------
if VciCollector.collect?
  module VciCollector
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
          paths.each { |p| VciCollector.wrote(p, gone: true) }
          r
        end
      end

      %i[chmod lchmod].each do |m|
        define_method(m) do |mode, *paths|
          return super(mode, *paths) if VciCollector.busy?
          paths.each { |p| VciCollector.before_change(p) }
          r = super(mode, *paths)
          paths.each { |p| VciCollector.wrote(p) }
          r
        end
      end

      %i[chown lchown utime lutime].each do |m|
        define_method(m) do |a, b, *paths|
          return super(a, b, *paths) if VciCollector.busy?
          paths.each { |p| VciCollector.before_change(p) }
          r = super(a, b, *paths)
          paths.each { |p| VciCollector.wrote(p) }
          r
        end
      end

      %i[truncate mkfifo].each do |m|
        define_method(m) do |path, *rest|
          return super(path, *rest) if VciCollector.busy?
          VciCollector.before_change(path)
          r = super(path, *rest)
          VciCollector.wrote(path)
          r
        end
      end

      # The destination holds the source's content afterwards: the
      # process's own only if the source was (File.atomic_write).
      def rename(from, to)
        return super if VciCollector.busy?
        f = VciCollector.expand(VciCollector.pathify(from))
        produced = f && VciCollector.self_produced?(f)
        VciCollector.before_change(from)
        r = super
        VciCollector.wrote(from, gone: true)
        VciCollector.wrote(to, produced: produced, gone: !produced)
        t = VciCollector.expand(VciCollector.pathify(to))
        VciCollector.parent_observed(t) if t
        r
      end

      def symlink(target, link)
        unless VciCollector.busy?
          # Reading through the link reads the target.
          t = VciCollector.pathify(target)
          l = VciCollector.expand(VciCollector.pathify(link))
          VciCollector.rec(:read, VciCollector.quiet { Real.expand_path(t, Real.dirname(l)) }) if t && l
          VciCollector.wrote(link)
        end
        super
      end

      def link(src, dst)
        unless VciCollector.busy?
          VciCollector.rec(:read, src)
          VciCollector.wrote(dst)
        end
        super
      end
    end

    module IOHooks
      %i[read binread readlines].each do |m|
        define_method(m) do |*args, **kw, &blk|
          return super(*args, **kw, &blk) if VciCollector.busy?
          p = VciCollector.pathify(args[0])
          VciCollector.taint("process:IO.#{m}(|cmd)") if p&.start_with?("|")
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
          VciCollector.taint("process:IO.foreach(|cmd)") if p&.start_with?("|")
          if p
            VciCollector.exists_quietly?(p) ? VciCollector.read_path(p) : VciCollector.rec(:probe, p)
          end
        end
        super
      end

      %i[write binwrite].each do |m|
        define_method(m) do |*args, **kw, &blk|
          return super(*args, **kw, &blk) if VciCollector.busy?
          p = VciCollector.pathify(args[0])
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
        VciCollector.parent_observed(a) if a
        r
      end

      %i[rmdir delete unlink].each do |m|
        define_method(m) do |path|
          return super(path) if VciCollector.busy?
          VciCollector.before_change(path)
          r = super(path)
          VciCollector.wrote(path, gone: true)
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
        VciCollector.taint("process:fork")
        super
      end

      def daemon(*args)
        VciCollector.taint("process:daemon")
        super
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
        st.instance_variable_set(:@__vci_path, abs) if abs && !@produced[abs]
      rescue StandardError
        nil
      end

      def stat_metadata_read(st, what, kind)
        abs = st.instance_variable_get(:@__vci_path)
        metadata_read(abs, what, kind) if abs
      end

      def metadata_read(path, what, kind)
        return unless collect? && !busy?
        abs = expand(pathify(path))
        return unless abs && inside?(abs, repo) && !@produced[abs]
        where = quiet { frame }
        return if METADATA_ALLOWED.match?(where) || tooling?(where)
        return if kind == :perm && (where.start_with?("#{RUBYLIBDIR}/") || STDLIB_PERM.match?(where))
        rel = abs.delete_prefix("#{repo}/")
        taint("ruby:file-metadata:#{what} of #{rel} at #{where} (git does not keep file times, permission bits other than the executable bit, or owners: a checkout's differ)")
      end
    end
  end

  File.singleton_class.prepend(VciCollector::FileStatHooks)
  File.singleton_class.prepend(VciCollector::FileWriteHooks)
  FileTest.singleton_class.prepend(VciCollector::FileStatHooks)
  IO.singleton_class.prepend(VciCollector::IOHooks)
  File.prepend(VciCollector::FileInitHook)
  File.prepend(VciCollector::FileMetaHooks)
  IO.prepend(VciCollector::IOInitHook)
  IO.prepend(VciCollector::IOStatHook)
  File::Stat.prepend(VciCollector::FileStatInit)
  Dir.singleton_class.prepend(VciCollector::DirHooks)
  Dir.prepend(VciCollector::DirInitHook)
  Process.singleton_class.prepend(VciCollector::ProcessHooks)
  ENV.singleton_class.prepend(VciCollector::EnvHooks)
  RubyVM::InstructionSequence.singleton_class.prepend(VciCollector::ISeqHooks)
  ARGF.singleton_class.prepend(VciCollector::ArgfHooks)

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
    on_load: -> { defined?(::ActiveSupport) && ::ActiveSupport.respond_to?(:on_load) && install_on_load },
    socket: -> { defined?(::BasicSocket) && install_socket },
    pty: -> { defined?(::PTY) && install_pty },
    fiddle: -> { defined?(::Fiddle::Function) && defined?(::Fiddle::Handle) && install_fiddle },
    ffi: -> { defined?(::FFI::Library) && defined?(::FFI::DynamicLibrary) && install_ffi },
    zlib: -> { defined?(::Zlib::GzipReader) && install_zlib },
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
    zlib: -> { defined?(::Zlib::GzipReader) },
    prism: -> { defined?(::Prism) && ::Prism.respond_to?(:parse_file) },
    sqlite3: -> { defined?(::SQLite3::Database) },
    nokogiri: -> { defined?(::Nokogiri::XML::Document) }
  }.freeze

  # Database clients: [constant path, name]. Every way to open a
  # connection is wrapped as it appears (aliases may be defined later).
  DB_CLIENTS = [[%w[PG Connection], "postgresql"], [%w[Mysql2 Client], "mysql2"], [%w[Trilogy], "trilogy"]].freeze
  DB_OPENERS = %i[new connect open connect_start async_connect sync_connect setdb setdblogin].freeze

  # Constant names whose definition triggers after_require.
  WATCHED_CONSTANTS = %i[
    Minitest Configuration ActiveSupport BasicSocket Socket PTY Fiddle Function Handle FFI Library DynamicLibrary
    Zlib GzipReader SQLite3 Database PG Connection Mysql2 Client Trilogy Nokogiri XML Document Node Reader Schema
    RelaxNG SAX ParserContext XSLT Stylesheet ParseOptions
    RSpec Runner Reporter ConfigurationOptions ConfigurationManager World SimpleCov CodeStatistics Prism Example
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
              VciCollector.db_client_opened(name) unless VciCollector.busy?
              super(*args, **kw, &blk)
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

    def install_on_load
      ::ActiveSupport.on_load(:after_initialize) { VciCollector::DB.prepare! }
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

    # FFI: a library opened (ffi_lib, DynamicLibrary.open), a function or
    # variable attached (attach_function without ffi_lib uses the process's
    # own symbols), or a function pointer called.
    def install_ffi
      return true unless collect?
      ::FFI::Library.prepend(Module.new do
        %i[ffi_lib attach_function attach_variable].each do |m|
          define_method(m) do |*args, **kw, &blk|
            VciCollector.taint("native:FFI #{m}(#{args.first(2).inspect})")
            super(*args, **kw, &blk)
          end
        end
      end)
      ::FFI::DynamicLibrary.singleton_class.prepend(Module.new do
        def open(*args, **kw, &blk)
          VciCollector.taint("native:FFI::DynamicLibrary.open(#{args[0].inspect})")
          super
        end
      end)
      if defined?(::FFI::Function)
        ::FFI::Function.prepend(Module.new do
          def initialize(*args, **kw, &blk)
            VciCollector.taint("native:FFI::Function")
            super
          end
        end)
      end
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
    # other than the fresh ones vci prepared (in VCI_DB_DIR) or one in a
    # temp dir is not attestable, and so is ATTACH (an authorizer refuses it)
    # and loading an extension.
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

    # A database server connection. Active Record's adapters connecting to
    # a configured database are the test environment's database (refused
    # unless policy.rails_allow_db, which DB.prepare! handles); a client a
    # test opens itself is refused like any other socket.
    def db_client_opened(name)
      ar = quiet { caller_locations(2, 30).to_a }.any? do |l|
        (l.absolute_path || l.path).to_s.include?("/active_record/connection_adapters/")
      end
      if ar
        taint("#{DB::NETWORK_TAINT}#{name} (Active Record connection)")
      else
        taint("network:#{name} client (a database connection the test opened itself)")
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

  # SQLite databases of the test environment are redirected to fresh files
  # in VCI_DB_DIR; the development/test local secret is generated fresh in
  # memory, as on a fresh checkout, instead of being kept in
  # tmp/local_secret.txt (whose random content would otherwise be an input).
  module RailsConfigHooks
    def database_configuration
      VciCollector::DB.redirect(super)
    end

    private

    def generate_local_secret
      VciCollector::DB.local_secret
    end
  end

  module DB
    NETWORK_TAINT = "rails:network-db:"
    SQLITE_ATTACH = 24
    @adapters = []

    class << self
      attr_reader :adapters

      def sqlite_opened(file, db)
        f = file.to_s
        return if f.empty? || f == ":memory:" || f.start_with?("file::memory:")
        path = f.start_with?("file:") ? f.sub(/\Afile:/, "").split("?").first : f
        abs = VciCollector.expand(path)
        ok = abs && [DB_DIR, TMP].compact.reject(&:empty?).any? do |d|
          VciCollector.inside?(abs, (Real.realpath(d) rescue Real.expand_path(d)))
        end
        VciCollector.taint("rails:sqlite-file:#{abs || f} (a SQLite database vci did not prepare fresh; SQLite reads and writes it in C)") unless ok
        db.authorizer = proc do |action, *|
          VciCollector.taint("rails:sqlite-attach (ATTACH reads another database file in C)") if action == SQLITE_ATTACH
          0
        end
      rescue StandardError => e
        VciCollector.taint("rails:sqlite-hook:#{e.class}")
      end

      def local_secret
        @local_secret ||= VciCollector.quiet { SecureRandom.hex(64) }
      end

      def env_name
        ENV["RAILS_ENV"] || ENV["RACK_ENV"] || "development"
      end

      def redirect(all)
        return all unless DB_DIR && all.is_a?(Hash)
        env = env_name
        cfg = all[env]
        return all unless cfg.is_a?(Hash)
        out = all.dup
        out[env] = if cfg.key?("adapter") || cfg.key?("database") || cfg.key?("url")
                     redirect_one(cfg, "primary")
                   else
                     cfg.to_h { |name, c| [name, c.is_a?(Hash) ? redirect_one(c, name.to_s) : c] }
                   end
        out
      end

      def redirect_one(c, name)
        return c unless c["adapter"].to_s.start_with?("sqlite") && c["url"].nil?
        db = c["database"].to_s
        return c if db.empty? || db.include?(":memory:") || db.start_with?("file:")
        # One fresh file per configured file, so a replica of the primary
        # (another config naming the same file) stays the same database.
        @fresh ||= {}
        key = File.expand_path(db, VciCollector.root)
        @fresh[key] ||= File.join(DB_DIR, "#{@fresh.size}-#{File.basename(db).gsub(/[^A-Za-z0-9_.-]/, "_")}")
        c.merge("database" => @fresh[key])
      end

      # After Rails initialised (before rails/test_help's
      # maintain_test_schema!, which would shell out to `bin/rails
      # db:test:prepare`): load the schema into every database of the test
      # environment, fresh.
      def prepare!
        return unless env_name == "test" && defined?(::ActiveRecord::Base) && DB_DIR
        require "active_record/tasks/database_tasks"
        ::ActiveRecord::Base.configurations.configs_for(env_name: "test").each do |db_config|
          if MODE == "probe"
            probe(db_config)
          elsif db_config.adapter.to_s.start_with?("sqlite")
            prepare_sqlite(db_config)
          else
            prepare_network(db_config)
          end
        end
      rescue StandardError => e
        VciCollector.taint("rails:db-prepare:#{e.class}: #{e.message}")
        raise
      end

      def prepare_sqlite(db_config)
        db = db_config.database.to_s
        unless db.start_with?(File.join(DB_DIR, ""))
          VciCollector.taint("rails:db:sqlite database #{db.inspect} is not a file vci prepared fresh (in-memory, a url, or DATABASE_URL)")
          return
        end
        @adapters << "sqlite3"
        ::ActiveRecord::Tasks::DatabaseTasks.with_temporary_connection(db_config) { load_schema(db_config) }
      end

      # A database server: refused unless policy.rails_allow_db; then purged
      # and loaded from the schema like a SQLite file.
      def prepare_network(db_config)
        adapter = db_config.adapter.to_s
        VciCollector.taint("#{NETWORK_TAINT}#{adapter} (#{db_config.name})")
        return unless ALLOW_DB
        ::ActiveRecord::Tasks::DatabaseTasks.purge(db_config)
        ::ActiveRecord::Tasks::DatabaseTasks.with_temporary_connection(db_config) do |conn|
          @adapters << "#{adapter} #{server_version(conn)}"
          load_schema(db_config)
        end
      end

      # `vci plan`: the database software CI would use (a server's version
      # only when policy.rails_allow_db lets such files be attested).
      def probe(db_config)
        adapter = db_config.adapter.to_s
        if adapter.start_with?("sqlite") || !ALLOW_DB
          @adapters << adapter
        else
          ::ActiveRecord::Tasks::DatabaseTasks.with_temporary_connection(db_config) do |conn|
            @adapters << "#{adapter} #{server_version(conn)}"
          end
        end
      end

      def server_version(conn)
        conn.respond_to?(:database_version) ? conn.database_version.to_s : conn.select_value("select version()").to_s
      rescue StandardError
        "unknown"
      end

      def load_schema(db_config)
        tasks = ::ActiveRecord::Tasks::DatabaseTasks
        format = db_config.respond_to?(:schema_format) ? db_config.schema_format : ::ActiveRecord.schema_format
        file = tasks.schema_dump_path(db_config, format)
        return unless file
        if format.to_sym == :sql && db_config.adapter.to_s.start_with?("sqlite")
          # Rails would run the sqlite3 command line tool: load it in-process.
          tasks.migration_connection.raw_connection.execute_batch2(File.read(file))
          tasks.migration_connection_pool.internal_metadata.create_table_and_set_flags(
            db_config.env_name, tasks.send(:schema_sha1, file)
          )
        else
          tasks.load_schema(db_config, format, file)
        end
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
        d = TMP.to_s
        d.empty? ? "/tmp" : d
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
                elsif c[:pending].positive? then "failed"
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
        return false if abs.nil? || VciCollector.inside?(abs, VciCollector.repo)
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
    next unless Process.pid == VciCollector::PID
    case VciCollector::MODE
    when "collect" then VciCollector::Output.write!(status)
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

    # Directories RubyGems and Bundler install gems into, and their caches.
    def roots
      @roots ||= begin
        r = ::Gem.path.dup
        r << ::Gem.default_dir
        r << ::Gem.user_dir if ::Gem.respond_to?(:user_dir)
        r << ::Gem.spec_cache_dir if ::Gem.respond_to?(:spec_cache_dir)
        r << ::Bundler.bundle_path.to_s if defined?(::Bundler) && ::Bundler.respond_to?(:bundle_path)
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

    def under_root?(abs)
      roots.any? { |r| VciCollector.inside?(abs, r) }
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

    def ignored_prefixes
      @ignored_prefixes ||= [TMP, OUT, DB_DIR].compact.reject(&:empty?).map do |p|
        File.realpath(p)
      rescue StandardError
        File.expand_path(p)
      end.uniq
    end

    # Ruby's own library directories, covered by the Ruby version. Not
    # site_ruby or vendor_ruby: anyone can add files there.
    def ruby_dirs
      @ruby_dirs ||= %w[rubylibdir rubyarchdir rubyhdrdir].map do |k|
        RbConfig::CONFIG[k]
      end.compact.reject(&:empty?).map { |d| File.expand_path(d) }.uniq
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

    # nil (not an input), [:external, spec], [:outside_bundle, nil], [:path, abs]
    def classify(abs)
      return nil if DEVICES.include?(abs) || abs.start_with?("/dev/fd/")
      if ignored_prefixes.any? { |p| VciCollector.inside?(abs, p) }
        # vci's temp dirs; but a symlink there into the repository reads the
        # repository file.
        real = (File.realpath(abs) rescue nil)
        return real && VciCollector.inside?(real, VciCollector.repo) ? [:path, real] : nil
      end
      return nil if bundler_config?(abs)
      # RubyGems resolves symlinks in its directories (GEM_PATH through
      # /var -> /private/var): compare the real path too.
      real = real_of(abs)
      s = Gems.spec_for(abs) || (real != abs && Gems.spec_for(real))
      if s
        # A path gem inside the repository is repository code: hash it.
        local = Gems.source_of(s).start_with?("path ") && VciCollector.inside?(abs, VciCollector.repo)
        return [:external, s] unless local
      end
      return [:outside_bundle, nil] if Gems.under_root?(abs) || (real != abs && Gems.under_root?(real))
      # The system zone database, when TZInfo uses it: its version is part of
      # the toolchain (Tz.source). With tzinfo-data it is not, so a read
      # there is an input outside the repository.
      return nil if Tz.source.start_with?("zoneinfo ") && Tz.dirs.any? { |d| VciCollector.inside?(abs, d) }
      return nil if !VciCollector.inside?(abs, VciCollector.repo) && ruby_dirs.any? { |d| VciCollector.inside?(abs, d) }
      [:path, abs]
    end

    # The real path of `abs`, or of its nearest existing ancestor joined
    # with the rest (an absent path).
    def real_of(abs)
      rest = []
      cur = abs
      until cur == "/" || cur.empty?
        begin
          return File.join(File.realpath(cur), *rest.reverse)
        rescue SystemCallError
          rest << File.basename(cur)
          cur = File.dirname(cur)
        end
      end
      abs
    end

    def write!(status)
      unless OUT && TEST_ID
        $stderr.puts "vci_collector: VCI_OUT or VCI_TEST_ID not set; nothing written"
        return
      end
      # First: what is written below requires libraries (and would hook them).
      unhooked = VciCollector.unhooked
      TP_COMPILED.disable
      TP_RAISE.disable
      VciCollector.quiet { write_records(status, unhooked) }
    end

    def write_records(status, unhooked = [])
      vc = VciCollector
      taints = vc.taints.dup + unhooked
      lines = [meta]
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
      records.each do |(kind, abs), by|
        next if kind == :write
        next if kind == :stat && RUNNER == "rspec" && temp_ancestor?(abs)
        c = classify(abs)
        next unless c
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
          elsif by != :tooling
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
        lines << { kind: kind.to_s, path: p }
      end
      written.each_key { |p| lines << { kind: "write", path: p } if vc.inside?(p, vc.repo) }
      taints.concat(GemVerify.check(externals.values.uniq, gem_files))
      externals.each do |(name, version), s|
        rec = { kind: "external", name: name, version: version, platform: s.platform.to_s }
        src = Gems.source_of(s)
        rec[:source] = src unless src.empty?
        lines << rec
      end
      keys = vc.env_keys.dup
      Env::ALWAYS_READ.each { |k| keys[k] ||= { "ruby" => true } }
      keys.each { |k, w| lines << { kind: "env", key: k, where: w.keys.first(3).join(" | ") } }
      taints.concat(Checks.run)
      taints.concat(RSpecSupport.taints) if RUNNER == "rspec"
      res = result(status)
      if status != 0 && framework_clean?
        taints << "vci:process-exit:#{status} (the process exited #{status} after the test framework reported a pass: " \
                  "an at_exit handler such as SimpleCov's minimum_coverage failed the run)"
      end
      taints.uniq.each { |t| lines << { kind: "taint", reason: t } }
      lines << res
      require "digest/sha2"
      File.open(File.join(OUT, "#{Digest::SHA256.hexdigest(TEST_ID)}.jsonl"), "w") do |f|
        lines.each { |l| f.write(Json.dump(l), "\n") }
      end
    end

    def meta
      {
        v: 1, kind: "meta", testId: TEST_ID, adapter: "rails",
        ruby: Probe.ruby_version, engine: Probe.engine,
        rails: Probe.rails_version, bundler: Probe.bundler_version, runner: Probe.runner_version,
        root: VciCollector.root, platform: RUBY_PLATFORM, collector: "vci_collector@#{VERSION}",
        db: DB.adapters.uniq.join(";"), tz: Tz.source
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
              elsif mt.skips.positive? then "failed"
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
        archive = s.respond_to?(:cache_file) ? s.cache_file : nil
        unless archive && File.file?(archive)
          out << "ruby:gem-unverifiable:#{s.full_name} (no #{s.full_name}.gem in the RubyGems cache to check its installed files against; reinstall it with `gem install --local` or `bundle install --redownload`)"
          next
        end
        want = lock_checksums[s.full_name]
        if want && Digest::SHA256.file(archive).hexdigest != want
          out << "ruby:gem-checksum:#{s.full_name} (#{archive} does not have the sha256 Gemfile.lock records)"
          next
        end
        out.concat(compare(s, archive, files))
      end
      out
    rescue StandardError, LoadError => e
      ["ruby:gem-verify:#{e.class}: #{e.message}"]
    end

    def compare(spec, archive, files)
      root = File.expand_path(spec.full_gem_path)
      want = {}
      files.each do |f|
        next unless VciCollector.inside?(f, root) && File.file?(f)
        want[f.delete_prefix("#{root}/")] = f
      end
      return [] if want.empty?
      found = {}
      out = []
      File.open(archive, "rb") do |io|
        ::Gem::Package::TarReader.new(io) do |tar|
          tar.each do |entry|
            next unless entry.full_name == "data.tar.gz"
            ::Zlib::GzipReader.wrap(entry) do |gz|
              ::Gem::Package::TarReader.new(gz) do |data|
                data.each do |f|
                  path = want[f.full_name]
                  next unless path && f.file?
                  found[f.full_name] = true
                  out << "ruby:gem-modified:#{spec.full_name}:#{f.full_name} (differs from #{File.basename(archive)})" if f.read != File.binread(path)
                end
              end
            end
          end
        end
      end
      want.each_key do |rel|
        next if found[rel]
        # Built at install time (an extension compiled from source), or added.
        next if rel.end_with?(*DLEXTS) || rel.end_with?("gem.build_complete")
        out << "ruby:gem-modified:#{spec.full_name}:#{rel} (not in #{File.basename(archive)})"
      end
      out
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

    # A spec file that loads only spec_helper never loads Rails: its version
    # is then the bundle's railties (what the probe reports).
    def rails_version
      return ::Rails::VERSION::STRING if defined?(::Rails::VERSION::STRING)
      return "" unless RUNNER == "rspec"
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
          runner: runner_version, platform: RUBY_PLATFORM, libs: libs, db: DB.adapters.uniq.join(";"),
          gems: gems, gemfile: (::Bundler.default_gemfile.to_s rescue ""), taints: Checks.run
        }
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
  File.singleton_class.prepend(VciCollector::RSpecSupport::SimpleCovConfigGuard)
  FileTest.singleton_class.prepend(VciCollector::RSpecSupport::SimpleCovConfigGuard)
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
