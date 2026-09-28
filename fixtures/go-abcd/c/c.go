// Package c serves embedded data files.
package c

import (
	"embed"
	"sort"
)

//go:embed data/*.txt
var data embed.FS

// Names lists the embedded data files.
func Names() []string {
	entries, _ := data.ReadDir("data")
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

// Impl names the implementation file the test loads at run time.
func Impl() string { return "impl-" + "x" + ".txt" }
