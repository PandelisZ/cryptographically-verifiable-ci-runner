#!/usr/bin/env bash
# units-for-change.sh: suggest the vci test units that cover a change.
#
# Usage (from anywhere inside the repository):
#   units-for-change.sh [--base REF] [-q] [PATH...]
#
#   --base REF  compare against the merge base of HEAD and REF
#               (default: $VCI_BASE_REF, else origin/HEAD, origin/main,
#               origin/master, main, master)
#   -q          no explanations on stderr
#   PATH...     treat these repo-relative paths as the change instead of
#               asking git
#
# Prints one unit id per line on stdout, repo-relative, ready for
#   cd "$(git rev-parse --show-toplevel)" && vci run $(units-for-change.sh) --key ...
# Explanations go to stderr. A line "ALL <project>" on stderr means a global
# input changed (lockfile, runner config, vci.toml, ...): every unit of that
# project depends on it, so run `vci run` with no arguments (or every unit of
# that project).
#
# This is a heuristic (file names, imports, package graphs). vci records what
# each unit really read, so suggesting too much only costs local run time, and
# missing a unit only means CI runs it. Needs git and POSIX tools; uses `go`
# and `cargo` + `python3` when present for package graphs. Works with bash 3.2.

set -u
LC_ALL=C
export LC_ALL

QUIET=0
BASE="${VCI_BASE_REF:-}"
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --base) BASE="${2:-}"; shift 2 ;;
    --base=*) BASE="${1#--base=}"; shift ;;
    -q) QUIET=1; shift ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    --) shift; while [ $# -gt 0 ]; do ARGS+=("$1"); shift; done ;;
    -*) echo "units-for-change: unknown option $1" >&2; exit 2 ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "units-for-change: not inside a git repository" >&2; exit 2; }
cd "$ROOT" || exit 2

T=$(mktemp -d "${TMPDIR:-/tmp}/vci-units.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT
: >"$T/units"; : >"$T/all"

note() { [ "$QUIET" = 1 ] || echo "units-for-change: $*" >&2; }
unit() { # unit <id> <reason>
  printf '%s\n' "$1" >>"$T/units"
  note "$1  <- $2"
}
all_of() { # all_of <project> <reason>
  printf '%s\t%s\n' "$1" "$2" >>"$T/all"
}
# Escape a string for use inside an ERE.
re_escape() { printf '%s' "$1" | sed 's/[][\.*^$+?(){}|/]/\\&/g'; }

# ---------------------------------------------------------------- projects
# vci.toml: single form (project/adapter) or [[projects]] (path/adapter).
if [ ! -f vci.toml ]; then
  echo "units-for-change: no vci.toml at $ROOT (run \`vci init\` first)" >&2
  exit 2
fi
awk '
  function val(s) { sub(/^[^=]*=[[:space:]]*/, "", s); sub(/[[:space:]]*#.*$/, "", s);
                    gsub(/^["'\'']|["'\'']$/, "", s); return s }
  /^[[:space:]]*\[\[projects\]\]/ { if (multi) print p "\t" a; multi=1; sect="p"; p="."; a="vitest"; next }
  /^[[:space:]]*\[/ { sect = "x"; next }
  sect == "" && /^[[:space:]]*project[[:space:]]*=/ { tp = val($0) }
  sect == "" && /^[[:space:]]*adapter[[:space:]]*=/ { ta = val($0) }
  sect == "p" && /^[[:space:]]*path[[:space:]]*=/ { p = val($0) }
  sect == "p" && /^[[:space:]]*adapter[[:space:]]*=/ { a = val($0) }
  END {
    if (multi) print p "\t" a
    else print (tp == "" ? "." : tp) "\t" (ta == "" ? "vitest" : ta)
  }' vci.toml | sed -e 's#\t\./#\t#' -e 's#^\./##' -e 's#/\t#\t#' -e 's#^\t#.\t#' >"$T/projects"

# ---------------------------------------------------------------- changes
# Lines "<status>\t<path>", status A (added), M (modified) or D (deleted).
if [ ${#ARGS[@]} -gt 0 ]; then
  for a in "${ARGS[@]}"; do
    a=${a#./}
    if [ -e "$a" ]; then printf 'M\t%s\n' "$a"; else printf 'D\t%s\n' "$a"; fi
  done >"$T/changes"
else
  if [ -z "$BASE" ]; then
    for r in origin/HEAD origin/main origin/master main master; do
      if git rev-parse -q --verify "$r^{commit}" >/dev/null 2>&1; then BASE=$r; break; fi
    done
  fi
  MB=""
  [ -n "$BASE" ] && MB=$(git merge-base HEAD "$BASE" 2>/dev/null)
  if [ -z "$MB" ]; then
    note "no base ref found (pass --base); using uncommitted changes only"
    MB=HEAD
  fi
  note "changes since $(git rev-parse --short "$MB") (merge base with ${BASE:-HEAD}), working tree included"
  { git diff --no-renames --name-status "$MB" -- . 2>/dev/null \
      | awk -F'\t' '{ s = substr($1, 1, 1); if (s != "A" && s != "D") s = "M"; print s "\t" $2 }'
    git ls-files --others --exclude-standard | awk '{ print "A\t" $0 }'
  } | sort -u >"$T/changes"
fi
if [ ! -s "$T/changes" ]; then note "no changed files"; exit 0; fi

# Longest project path containing a file ("" when none).
project_of() {
  local f=$1 best="" p
  while IFS='	' read -r p _; do
    if [ "$p" = "." ] || [ "${f#"$p"/}" != "$f" ]; then
      if [ -z "$best" ] || [ ${#p} -gt ${#best} ] || [ "$best" = "." ]; then
        [ "$p" = "." ] && [ -n "$best" ] && continue
        best=$p
      fi
    fi
  done <"$T/projects"
  printf '%s' "$best"
}
adapter_of() { awk -F'\t' -v p="$1" '$1 == p { print $2; exit }' "$T/projects"; }
# Repo-relative path of a project-relative one, and back.
in_proj() { if [ "$1" = "." ]; then printf '%s' "$2"; else printf '%s/%s' "$1" "$2"; fi; }
rel_to() { if [ "$1" = "." ]; then printf '%s' "$2"; else printf '%s' "${2#"$1"/}"; fi; }

# Tracked and untracked (not ignored) files of a project, cached.
files_of() {
  local key; key=$(printf '%s' "$1" | tr '/.' '__')
  if [ ! -f "$T/files.$key" ]; then
    if [ "$1" = "." ]; then git ls-files -co --exclude-standard
    else git ls-files -co --exclude-standard -- "$1"; fi | sort -u >"$T/files.$key"
  fi
  cat "$T/files.$key"
}

# Import-closure over stems: source files (matching $2) that mention a stem
# on an import-like line add their own stem; then every test file (matching
# $3) mentioning any collected stem is a candidate. $4: file with stems.
import_closure() {
  local proj=$1 srcre=$2 testre=$3 stems=$4 pat
  files_of "$proj" | grep -E "$srcre" | grep -vE "$testre" >"$T/src" || true
  files_of "$proj" | grep -E "$testre" >"$T/tests" || true
  sort -u "$stems" | grep . >"$T/seen"; cp "$T/seen" "$T/frontier"
  for _ in 1 2 3 4; do  # four rounds of imports
    [ -s "$T/frontier" ] || break
    pat=$(sed 's/[][\.*^$+?(){}|/]/\\&/g' "$T/frontier" | paste -sd'|' -)
    pat="(import|from|require|export|load|include).*(^|[^A-Za-z0-9_])($pat)([^A-Za-z0-9_]|\$)"
    tr '\n' '\0' <"$T/src" | xargs -0 grep -lE "$pat" -- 2>/dev/null \
      | sed -e 's#.*/##' -e 's#\.[^.]*$##' | sort -u >"$T/found"
    comm -13 "$T/seen" "$T/found" >"$T/frontier"
    sort -u "$T/seen" "$T/frontier" -o "$T/seen"
  done
  pat=$(sed 's/[][\.*^$+?(){}|/]/\\&/g' "$T/seen" | paste -sd'|' -)
  pat="(import|from|require|export|load|include).*(^|[^A-Za-z0-9_])($pat)([^A-Za-z0-9_]|\$)"
  tr '\n' '\0' <"$T/tests" | xargs -0 grep -lE "$pat" -- 2>/dev/null || true
}

# Test files (matching $2) and source files (matching $3) that name a data
# file by its base name; source hits are followed through import_closure.
data_users() {
  local proj=$1 testre=$2 srcre=$3 base=$4
  files_of "$proj" | grep -E "$testre" | tr '\n' '\0' \
    | xargs -0 grep -lF -- "$base" 2>/dev/null || true
  files_of "$proj" | grep -E "$srcre" | grep -vE "$testre" | tr '\n' '\0' \
    | xargs -0 grep -lF -- "$base" 2>/dev/null \
    | sed -e 's#.*/##' -e 's#\.[^.]*$##' | sort -u >"$T/dstems"
  [ -s "$T/dstems" ] && import_closure "$proj" "$srcre" "$testre" "$T/dstems"
  return 0
}

stem_of() { # module-ish name of a path: index/__init__ -> parent directory
  local b=${1##*/}; b=${b%.*}
  case "$b" in index|__init__|mod|main) b=${1%/*}; b=${b##*/} ;; esac
  printf '%s' "$b"
}

# ---------------------------------------------------------------- adapters
JS_TEST='\.(test|spec)\.[cm]?[jt]sx?$'
JS_SRC='\.([cm]?[jt]sx?|vue|svelte|astro)$'
PY_TEST='(^|/)(test_[^/]*|[^/]*_test)\.py$'
PY_SRC='\.py$'
RB_TEST='(^|/)test/.*_test\.rb$|(^|/)spec/.*_spec\.rb$'
RB_SRC='\.(rb|rake|erb|haml|slim|builder|jbuilder)$'

do_vitest() { # proj status relpath file
  local proj=$1 st=$2 rel=$3 f=$4 b=${3##*/}
  case "$b" in
    package.json|package-lock.json|npm-shrinkwrap.json|pnpm-lock.yaml|yarn.lock|.npmrc|tsconfig*.json|vitest.config.*|vite.config.*|vitest.workspace.*)
      all_of "$proj" "$f (global input of every test file)"; return ;;
  esac
  if printf '%s' "$rel" | grep -qE "$JS_TEST"; then
    [ "$st" != D ] && unit "$f" "test file changed"; return
  fi
  case "$rel" in
    */__snapshots__/*.snap|__snapshots__/*.snap)
      local t; t="${f%/__snapshots__/*}/${b%.snap}"
      [ -f "$t" ] && unit "$t" "its snapshot $f changed"; return ;;
  esac
  if printf '%s' "$rel" | grep -qE "$JS_SRC"; then
    stem_of "$rel" >"$T/stems"; echo >>"$T/stems"
    import_closure "$proj" "$JS_SRC" "$JS_TEST" "$T/stems" | while read -r t; do
      unit "$t" "imports (perhaps indirectly) $f"; done
  else
    data_users "$proj" "$JS_TEST" "$JS_SRC" "$b" | while read -r t; do
      unit "$t" "names $b (directly or through a module)"; done
  fi
}

do_pytest() {
  local proj=$1 st=$2 rel=$3 f=$4 b=${3##*/}
  case "$rel" in
    pyproject.toml|uv.lock|.python-version|pytest.ini|setup.cfg|tox.ini|conftest.py)
      all_of "$proj" "$f (global input or root conftest)"; return ;;
  esac
  if [ "$b" = conftest.py ]; then
    local d=${f%/*}
    files_of "$proj" | grep -E "$PY_TEST" | while read -r t; do
      case "$t" in "$d"/*) unit "$t" "under $f" ;; esac; done
    return
  fi
  if printf '%s' "$rel" | grep -qE "$PY_TEST"; then
    [ "$st" != D ] && unit "$f" "test file changed"; return
  fi
  if printf '%s' "$rel" | grep -qE "$PY_SRC"; then
    stem_of "$rel" >"$T/stems"; echo >>"$T/stems"
    import_closure "$proj" "$PY_SRC" "$PY_TEST" "$T/stems" | while read -r t; do
      unit "$t" "imports (perhaps indirectly) $f"; done
  else
    data_users "$proj" "$PY_TEST" "$PY_SRC" "$b" | while read -r t; do
      unit "$t" "names $b (directly or through a module)"; done
  fi
}

go_units_done=""
do_go() {
  local proj=$1 st=$2 rel=$3 f=$4
  case "$rel" in
    go.mod|go.sum|go.work|go.work.sum)
      all_of "$proj" "$f (module graph)"; return ;;
  esac
  # The package directory: nearest directory (within the module) with .go files.
  local d=${f%/*}; [ "$d" = "$f" ] && d=.
  while :; do
    if ls "$d"/*.go >/dev/null 2>&1; then break; fi
    if [ "$d" = "$proj" ] || [ "$d" = . ]; then d=""; break; fi
    case "$d" in */*) d=${d%/*} ;; *) d=. ;; esac
  done
  if [ -z "$d" ]; then note "$f: no Go package around it (unmapped)"; return; fi
  printf '%s\n' "$d" >>"$T/go.changed.$(printf '%s' "$proj" | tr '/.' '__')"
  case " $go_units_done " in *" $proj "*) ;; *) go_units_done="$go_units_done $proj" ;; esac
}
go_finish() { # reverse dependencies of changed packages, per module
  local proj key dir
  for proj in $go_units_done; do
    key=$(printf '%s' "$proj" | tr '/.' '__')
    sort -u "$T/go.changed.$key" -o "$T/go.changed.$key"
    if command -v go >/dev/null 2>&1 && (cd "$proj" && go list -e -test \
        -f '{{.ImportPath}}	{{.Dir}}	{{join .Deps " "}}' ./... >"$T/go.list" 2>/dev/null); then
      # import paths of the changed package directories
      : >"$T/go.cip"
      while read -r dir; do
        local adir; adir=$(cd "$dir" 2>/dev/null && pwd -P) || continue
        awk -F'\t' -v d="$adir" '$2 == d && $1 !~ / / && $1 !~ /\.test$/ { print $1 }' "$T/go.list" >>"$T/go.cip"
      done <"$T/go.changed.$key"
      sort -u "$T/go.cip" -o "$T/go.cip"
      # every package (or its test variant) that is or depends on one of them
      awk -F'\t' 'NR == FNR { c[$1] = 1; next }
        { n = split($3, deps, " "); hit = ($1 in c); base = $1; sub(/ .*/, "", base)
          if (base in c) hit = 1
          for (i = 1; i <= n && !hit; i++) if (deps[i] in c) hit = 1
          if (hit) print $2 }' "$T/go.cip" "$T/go.list" | sort -u >"$T/go.dirs"
    else
      note "go not available: suggesting only the changed packages, not their dependents"
      while read -r dir; do (cd "$dir" && pwd -P); done <"$T/go.changed.$key" | sort -u >"$T/go.dirs"
    fi
    while read -r dir; do
      ls "$dir"/*_test.go >/dev/null 2>&1 || continue
      local r=${dir#"$ROOT"/}; [ "$dir" = "$ROOT" ] && r=.
      unit "$r" "Go package changed or depends on a changed package"
    done <"$T/go.dirs"
  done
}

cargo_done=""
do_cargo() {
  local proj=$1 st=$2 rel=$3 f=$4 b=${3##*/}
  case "$rel" in
    Cargo.lock|rust-toolchain|rust-toolchain.toml|.cargo/config|.cargo/config.toml)
      all_of "$proj" "$f (workspace-wide)"; return ;;
  esac
  local d=${f%/*}; [ "$d" = "$f" ] && d=.
  while [ ! -f "$d/Cargo.toml" ]; do
    if [ "$d" = "$proj" ] || [ "$d" = . ]; then d=""; break; fi
    case "$d" in */*) d=${d%/*} ;; *) d=. ;; esac
  done
  if [ "$d" = "$proj" ] && [ "$b" = Cargo.toml ] && grep -q '^\[workspace\]' "$f" 2>/dev/null; then
    all_of "$proj" "$f (workspace manifest)"; return
  fi
  local key; key=$(printf '%s' "$proj" | tr '/.' '__')
  if [ -z "$d" ] || ! grep -q '^\[package\]' "$d/Cargo.toml" 2>/dev/null; then
    # Not inside a package: packages whose sources name it (include_str!,
    # build scripts, paths), and units that declare it under [[inputs]].
    note "$f: outside every package directory; units that declare it under [[inputs]] in vci.toml need it too"
    files_of "$proj" | grep -E '\.(rs|toml)$' | tr '\n' '\0' | xargs -0 grep -lF -- "$b" 2>/dev/null \
      | while read -r s; do
          s=${s%/*}
          while [ -n "$s" ] && [ ! -f "$s/Cargo.toml" ]; do case "$s" in */*) s=${s%/*} ;; *) s="" ;; esac; done
          [ -n "$s" ] && grep -q '^\[package\]' "$s/Cargo.toml" 2>/dev/null && printf '%s\n' "$s"
        done >>"$T/cargo.changed.$key"
  else
    printf '%s\n' "$d" >>"$T/cargo.changed.$key"
  fi
  case " $cargo_done " in *" $proj "*) ;; *) cargo_done="$cargo_done $proj" ;; esac
}
cargo_finish() { # changed packages plus workspace members depending on them
  local proj key
  for proj in $cargo_done; do
    key=$(printf '%s' "$proj" | tr '/.' '__')
    sort -u "$T/cargo.changed.$key" -o "$T/cargo.changed.$key"
    if command -v cargo >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 \
       && (cd "$proj" && cargo metadata --format-version 1 --no-deps --offline >"$T/cargo.json" 2>/dev/null); then
      python3 -I - "$ROOT" "$T/cargo.json" "$T/cargo.changed.$key" <<'PY' >"$T/cargo.dirs"
import json, os, sys
root, meta, changed = sys.argv[1], sys.argv[2], sys.argv[3]
pkgs = json.load(open(meta))["packages"]
rel = lambda p: os.path.relpath(os.path.dirname(p), root)
dirs = {p["name"]: rel(p["manifest_path"]) for p in pkgs}
want = {l.strip() for l in open(changed) if l.strip()}
rdeps = {}
for p in pkgs:
    for d in p.get("dependencies", []):
        if d.get("path"):
            rdeps.setdefault(os.path.relpath(d["path"], root), set()).add(rel(p["manifest_path"]))
todo, seen = list(want), set(want)
while todo:
    for r in rdeps.get(todo.pop(), ()):
        if r not in seen:
            seen.add(r); todo.append(r)
print("\n".join(sorted(d for d in seen if d in dirs.values())))
PY
    else
      note "cargo or python3 not available: suggesting only the changed packages, not their dependents"
      cp "$T/cargo.changed.$key" "$T/cargo.dirs"
    fi
    while read -r d; do
      [ -n "$d" ] && unit "$d" "cargo package changed or depends on one (vci runs every unit of it)"
    done <"$T/cargo.dirs"
  done
}

camel() { # widget_thing -> WidgetThing
  printf '%s' "$1" | awk -F_ '{ for (i = 1; i <= NF; i++) printf "%s%s", toupper(substr($i,1,1)), substr($i,2) }'
}
do_rails() {
  local proj=$1 st=$2 rel=$3 f=$4 b=${3##*/}
  case "$rel" in
    Gemfile|Gemfile.lock|gems.rb|gems.locked|.ruby-version|.tool-versions|mise.toml|.mise.toml|.rspec|Rakefile|config.ru|bin/rails|config/*|db/schema.rb|db/structure.sql|test/test_helper.rb|spec/spec_helper.rb|spec/rails_helper.rb|spec/support/*|spec/factories/*|test/factories/*|factories/*)
      all_of "$proj" "$f (loaded by every test that boots the app)"; return ;;
    test/fixtures/*.yml|spec/fixtures/*.yml)
      all_of "$proj" "$f (fixtures :all loads every fixture)"; return ;;
  esac
  if printf '%s' "$rel" | grep -qE "$RB_TEST"; then
    [ "$st" != D ] && unit "$f" "test file changed"; return
  fi
  case "$rel" in
    app/*|lib/*)
      if [ "$st" = A ] || [ "$st" = D ]; then
        case "$rel" in app/views/*|app/assets/*|app/javascript/*) ;; *)
          all_of "$proj" "$f was added or removed (autoload directory listings are inputs)"; return ;;
        esac
      fi ;;
  esac
  local stem=${b%%.*} cands="" sub t
  case "$rel" in
    app/views/*)
      sub=${rel#app/views/}; sub=${sub%/*}; stem=${sub##*/}
      printf '%s\n%s\n' "$(camel "$stem")Controller" "$stem" >"$T/stems" ;;
    *.rb)
      printf '%s\n' "$(camel "$stem")" >"$T/stems"
      case "$rel" in
        app/*/*) sub=${rel#app/*/}; sub=${sub%.rb}; local kind=${rel#app/}; kind=${kind%%/*}
                 cands="test/$kind/${sub}_test.rb spec/$kind/${sub}_spec.rb"
                 [ "$kind" = controllers ] && cands="$cands spec/requests/${sub%_controller}_spec.rb test/integration/${sub%_controller}_test.rb" ;;
        lib/*)   sub=${rel#lib/}; sub=${sub%.rb}; cands="test/lib/${sub}_test.rb spec/lib/${sub}_spec.rb" ;;
      esac ;;
    *) printf '%s\n' "$b" >"$T/stems" ;;
  esac
  for t in $cands; do
    t=$(in_proj "$proj" "$t"); [ -f "$t" ] && unit "$t" "conventional test of $f"
  done
  # Ruby code refers to constants, not files: follow constant names.
  local pat
  files_of "$proj" | grep -E "$RB_SRC" | grep -vE "$RB_TEST" >"$T/src" || true
  files_of "$proj" | grep -E "$RB_TEST" >"$T/tests" || true
  sort -u "$T/stems" | grep . >"$T/seen"; cp "$T/seen" "$T/frontier"
  for _ in 1 2 3; do  # three rounds of constant references
    [ -s "$T/frontier" ] || break
    pat=$(sed 's/[][\.*^$+?(){}|/]/\\&/g' "$T/frontier" | paste -sd'|' -)
    tr '\n' '\0' <"$T/src" | xargs -0 grep -lE "(^|[^A-Za-z0-9_])($pat)([^A-Za-z0-9_]|\$)" -- 2>/dev/null \
      | while read -r s; do s=${s##*/}; s=${s%%.*}; camel "$s"; echo; done | sort -u >"$T/found"
    comm -13 "$T/seen" "$T/found" >"$T/frontier"
    sort -u "$T/seen" "$T/frontier" -o "$T/seen"
  done
  pat=$(sed 's/[][\.*^$+?(){}|/]/\\&/g' "$T/seen" | paste -sd'|' -)
  tr '\n' '\0' <"$T/tests" | xargs -0 grep -lE "(^|[^A-Za-z0-9_])($pat)([^A-Za-z0-9_]|\$)" -- 2>/dev/null \
    | while read -r t; do unit "$t" "mentions a constant or name reached from $f"; done
}

# ---------------------------------------------------------------- main
outside=0
while IFS='	' read -r st f <&3; do
  [ -n "$f" ] || continue
  if [ "$f" = vci.toml ]; then
    while IFS='	' read -r p _; do all_of "$p" "vci.toml (global input of every unit)"; done <"$T/projects"
    continue
  fi
  case "$f" in .vci/*|.git-meta|.github/*) continue ;; esac
  proj=$(project_of "$f")
  if [ -z "$proj" ]; then outside=$((outside + 1)); continue; fi
  rel=$(rel_to "$proj" "$f")
  before=$(cat "$T/units" "$T/all" | wc -l)
  ad=$(adapter_of "$proj")
  case "$ad" in
    vitest) do_vitest "$proj" "$st" "$rel" "$f" ;;
    pytest) do_pytest "$proj" "$st" "$rel" "$f" ;;
    go)     do_go "$proj" "$st" "$rel" "$f" ;;
    cargo)  do_cargo "$proj" "$st" "$rel" "$f" ;;
    rails)  do_rails "$proj" "$st" "$rel" "$f" ;;
    *)      note "$f: unknown adapter $ad" ;;
  esac
  case "$ad" in vitest|pytest|rails)
    case "${f##*/}" in .keep|.gitkeep|.gitignore|.gitattributes) continue ;; esac
    if [ "$(cat "$T/units" "$T/all" | wc -l)" = "$before" ] && [ "$st" != D ]; then
      note "$f: no unit found by name or import (it may be reached through a computed path); if it matters, attest every unit of $proj"
    fi ;;
  esac
done 3<"$T/changes"
[ "$outside" -gt 0 ] && note "$outside changed file(s) outside every vci project (ignored)"
go_finish
cargo_finish

if [ -s "$T/all" ]; then
  sort -u "$T/all" | while IFS='	' read -r p why; do
    echo "units-for-change: ALL $p: $why" >&2
  done
fi
sort -u "$T/units"
