package b

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Read while the package is initialised, before the test starts: go test's
// own test log does not see this, vci's does.
var golden = func() string {
	b, err := os.ReadFile("testdata/golden.txt")
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(b))
}()

func TestGreet(t *testing.T) {
	raw, err := os.ReadFile("testdata/b.json")
	if err != nil {
		t.Fatal(err)
	}
	var in struct{ Greeting string }
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	if got := Greet(in.Greeting); got != golden {
		t.Fatalf("Greet(%q) = %q, want %q", in.Greeting, got, golden)
	}
}
