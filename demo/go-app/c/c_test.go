package c

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNames(t *testing.T) {
	if got := strings.Join(Names(), ","); got != "x.txt" {
		t.Fatalf("Names() = %q", got)
	}
}

// The file is chosen at run time by name: no static analysis can see it.
func TestImpl(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", Impl()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), "implementation") {
		t.Fatalf("unexpected %q", b)
	}
}
