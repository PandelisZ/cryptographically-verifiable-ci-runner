// vci: installed into the standard library's internal/testlog package with
// `go test -overlay` (only for the test binaries `vci run` builds; the file is
// never part of a normal build).
//
// Package os reports every file it opens or stats, every environment
// variable it looks up and every chdir to internal/testlog. `go test` itself
// only installs a logger when the test starts (testing.M.Run), so package
// initialisation (`var golden, _ = os.ReadFile("testdata/x")`) and TestMain
// before m.Run are not seen. This init runs when internal/testlog is
// initialised, which is before package os and therefore before any package
// that can reach the file system through os. It writes one line per event to
// $VCI_GO_TESTLOG, unbuffered, so nothing is lost when the process exits.
//
// The same overlay patches a few functions of packages os and time to call
// the VCI* functions below (see golang/hooks.rs): os.Readlink and
// Root.Readlink (a stat of the link, so its target is an input), os.Symlink,
// os.Link, Root.Symlink, Root.Link (the target of the new link), os.Environ
// (a taint), File.Chdir (the working directory changed) and time's
// initLocal (the local time zone is used).
//
// Line format: `<op> <Go-quoted string>`, op one of start, getenv, open,
// stat, chdir, exec, link, taint. Relative paths are made absolute with the
// working directory at the time of the call.

package testlog

import (
	"runtime"
	"strconv"
	"sync"
	"syscall"
)

type vciLogger struct {
	mu sync.Mutex
	fd int
	// wdChanged: the working directory changed since the process started.
	// A relative name that package os built from a File or Root opened
	// earlier (joinPath(f.Name(), entry)) was relative to the directory of
	// that open, not to the current one.
	wdChanged bool
}

// vci is the installed logger (nil when VCI_GO_TESTLOG is not set).
var vci *vciLogger

func (l *vciLogger) write(op, arg string) {
	b := []byte(op + " " + strconv.Quote(arg) + "\n")
	l.mu.Lock()
	defer l.mu.Unlock()
	for len(b) > 0 {
		n, err := syscall.Write(l.fd, b)
		if err == syscall.EINTR {
			continue
		}
		if err != nil || n <= 0 {
			// A lost record could hide an input: fail the test instead.
			panic("vci: writing VCI_GO_TESTLOG failed")
		}
		b = b[n:]
	}
}

func (l *vciLogger) changed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.wdChanged
}

// abs makes name absolute with the current working directory.
func (l *vciLogger) abs(op, name string) (string, bool) {
	if name == "" {
		l.write("taint", op+" of an empty path")
		return "", false
	}
	if name[0] == '/' {
		return name, true
	}
	wd, err := syscall.Getwd()
	if err != nil {
		l.write("taint", "getwd failed for "+op+" "+strconv.Quote(name))
		return "", false
	}
	return wd + "/" + name, true
}

// Functions of package os that log a name built from a File's or a Root's
// name (relative if that was opened with a relative path).
var handleDerived = [...]string{
	"os.(*File).lstatat",
	"os.(*unixDirent).Info",
	"os.(*Root).logOpen",
	"os.(*Root).logStat",
}

// fromHandle reports whether one of the innermost frames is a function
// that logs a handle-derived name (they call the logger directly or through
// testlog.Stat and os.Lstat).
func fromHandle() bool {
	var pcs [12]uintptr
	n := runtime.Callers(1, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()
		for _, h := range handleDerived {
			if f.Function == h {
				return true
			}
		}
		if !more {
			break
		}
	}
	return false
}

func (l *vciLogger) path(op, name string) {
	if name != "" && name[0] != '/' && l.changed() && fromHandle() {
		l.write("taint", op+" of "+strconv.Quote(name)+
			": a relative name derived from a file or os.Root opened before the working directory changed (resolved against the new directory it would name another file)")
		return
	}
	if p, ok := l.abs(op, name); ok {
		l.write(op, p)
	}
}

func (l *vciLogger) Getenv(key string) { l.write("getenv", key) }
func (l *vciLogger) Stat(file string)  { l.path("stat", file) }

func (l *vciLogger) Chdir(dir string) {
	l.mu.Lock()
	l.wdChanged = true
	l.mu.Unlock()
	l.path("chdir", dir)
}

// Open is also how os.StartProcess reports the program it starts: a child
// process is invisible to this log, so it is recorded as "exec".
func (l *vciLogger) Open(file string) {
	var pcs [8]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	for i := 0; i < 4; i++ {
		f, more := frames.Next()
		if f.Function == "os.StartProcess" {
			l.path("exec", file)
			return
		}
		if !more {
			break
		}
	}
	l.path("open", file)
}

// VCIEvent records an event from a patched standard library function:
// "taint" (the argument says why) or "wdchanged" (File.Chdir, which package
// os does not log).
func VCIEvent(op, arg string) {
	l := vci
	if l == nil {
		return
	}
	switch op {
	case "wdchanged":
		l.mu.Lock()
		l.wdChanged = true
		l.mu.Unlock()
	case "taint":
		l.write("taint", arg)
	default:
		l.write("taint", "unknown vci event "+strconv.Quote(op))
	}
}

// VCILink records the target of a new hard link ("link": oldname, relative
// to the working directory) or symbolic link ("symlink": oldname, relative
// to the directory of newname) as an absolute path. A read through the new
// link is logged under the link's name, not the target's. inRoot: the names
// were built from an os.Root's name.
func VCILink(kind, oldname, newname string, inRoot bool) {
	l := vci
	if l == nil {
		return
	}
	if inRoot && l.changed() && (oldname == "" || oldname[0] != '/' || newname == "" || newname[0] != '/') {
		l.write("taint", kind+" in an os.Root with a relative name after the working directory changed")
		return
	}
	target := oldname
	if kind == "symlink" && (target == "" || target[0] != '/') {
		n, ok := l.abs(kind, newname)
		if !ok {
			return
		}
		dir := n
		for len(dir) > 0 && dir[len(dir)-1] != '/' {
			dir = dir[:len(dir)-1]
		}
		target = dir + target
	}
	if t, ok := l.abs(kind, target); ok {
		l.write("link", t)
	}
}

// VCILocalZone is called when package time first needs the local time zone.
// Without TZ it comes from /etc/localtime, which is not an input (it
// differs between the attesting machine and CI); TZ="" and TZ=UTC mean
// UTC, and any other TZ value is hashed. A TZ naming a file is not an
// input either.
func VCILocalZone() {
	l := vci
	if l == nil {
		return
	}
	tz, ok := syscall.Getenv("TZ")
	switch {
	case !ok:
		l.write("taint", "the test uses the local time zone (time.Local) and TZ is unset, so it comes from /etc/localtime, which is not an input (set TZ, for example TZ=UTC, and declare it in vci.toml [env] global)")
	case len(tz) > 0 && (tz[0] == '/' || (tz[0] == ':' && len(tz) > 1 && tz[1] == '/')):
		l.write("taint", "TZ names a zoneinfo file ("+strconv.Quote(tz)+"), which is not an input")
	}
}

func init() {
	path, ok := syscall.Getenv("VCI_GO_TESTLOG")
	if !ok || path == "" {
		return
	}
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_APPEND|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		panic("vci: cannot open VCI_GO_TESTLOG: " + err.Error())
	}
	l := &vciLogger{fd: fd}
	var impl Interface = l
	if !logger.CompareAndSwap(nil, &impl) {
		panic("vci: a test logger is already installed")
	}
	vci = l
	l.write("start", runtime.Version()+" "+runtime.GOOS+"/"+runtime.GOARCH)
}
